"""TLS admission webhook for adapting OCE gateway-state mounts to Nitro."""

from __future__ import annotations

import base64
import json
import logging
import os
import signal
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from adapter import AdmissionError, build_patch

MAX_BODY_BYTES = 1_048_576
MAX_CONCURRENT_REQUESTS = 32
SOCKET_TIMEOUT_SECONDS = 5.0
LOG = logging.getLogger("oce-nitro-adapter")


def admit(review: Any) -> dict[str, Any]:
    """Build an AdmissionReview response without any HTTP dependencies."""
    uid = ""
    try:
        if not isinstance(review, dict):
            raise AdmissionError("AdmissionReview must be an object")
        if review.get("apiVersion") != "admission.k8s.io/v1":
            raise AdmissionError("only admission.k8s.io/v1 is supported")
        request = review.get("request")
        if not isinstance(request, dict):
            raise AdmissionError("AdmissionReview.request must be an object")
        uid = request.get("uid", "")
        if not isinstance(uid, str) or not uid:
            raise AdmissionError("AdmissionRequest.uid must be a non-empty string")
        if request.get("operation") != "CREATE":
            raise AdmissionError("only Pod CREATE admission is supported")
        resource = request.get("resource")
        if resource != {"group": "", "version": "v1", "resource": "pods"}:
            raise AdmissionError("only core/v1 Pods are supported")
        if not isinstance(request.get("namespace"), str) or not request["namespace"]:
            raise AdmissionError("Pod admission request must name a namespace")
        pod = request.get("object")
        patch = build_patch(pod)
        response: dict[str, Any] = {"uid": uid, "allowed": True}
        if patch:
            encoded = json.dumps(
                patch, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            response.update(
                {
                    "patchType": "JSONPatch",
                    "patch": base64.b64encode(encoded).decode("ascii"),
                }
            )
    except AdmissionError as error:
        response = {
            "uid": uid,
            "allowed": False,
            "status": {"code": 400, "message": str(error)},
        }
    except Exception:
        LOG.exception("unexpected admission failure")
        response = {
            "uid": uid,
            "allowed": False,
            "status": {"code": 500, "message": "internal admission error"},
        }
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": response,
    }


class AdmissionHandler(BaseHTTPRequestHandler):
    server_version = "oce-nitro-adapter"
    sys_version = ""

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path not in {"/healthz", "/readyz"}:
            self.send_error(404)
            return
        self._write_json(200, {"status": "ok"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if urlsplit(self.path).path != "/mutate":
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if length <= 0 or length > MAX_BODY_BYTES:
                raise ValueError
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError
            review = json.loads(body)
        except (ValueError, json.JSONDecodeError):
            self._write_json(
                400,
                {
                    "apiVersion": "admission.k8s.io/v1",
                    "kind": "AdmissionReview",
                    "response": {
                        "uid": "",
                        "allowed": False,
                        "status": {
                            "code": 400,
                            "message": "invalid AdmissionReview request body",
                        },
                    },
                },
            )
            return
        self._write_json(200, admit(review))

    def log_message(self, format: str, *args: Any) -> None:
        LOG.info("%s - %s", self.client_address[0], format % args)

    def _write_json(self, status: int, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded server with bounded admission concurrency and read timeouts."""

    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._request_slots = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    def get_request(self) -> tuple[Any, Any]:
        request, client_address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT_SECONDS)
        return request, client_address

    def process_request(self, request: Any, client_address: Any) -> None:
        self._request_slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    address = os.environ.get("LISTEN_ADDRESS", "0.0.0.0")
    port = int(os.environ.get("PORT", "8443"))
    cert_file = os.environ.get("TLS_CERT_FILE", "/tls/tls.crt")
    key_file = os.environ.get("TLS_KEY_FILE", "/tls/tls.key")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)

    server = BoundedThreadingHTTPServer((address, port), AdmissionHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    def stop_server(*_: Any) -> None:
        # BaseServer.shutdown must run outside the serve_forever thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop_server)
    signal.signal(signal.SIGINT, stop_server)
    LOG.info("listening on %s:%d", address, port)
    server.serve_forever()


if __name__ == "__main__":
    main()

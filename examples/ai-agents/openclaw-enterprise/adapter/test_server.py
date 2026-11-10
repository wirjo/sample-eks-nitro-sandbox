from __future__ import annotations

import base64
import json
import unittest

from server import admit
from test_adapter import target_pod


def review(pod: dict) -> dict:
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "test-uid",
            "operation": "CREATE",
            "namespace": "oce-tenant-test",
            "resource": {"group": "", "version": "v1", "resource": "pods"},
            "object": pod,
        },
    }


class AdmitTests(unittest.TestCase):
    def test_returns_an_encoded_json_patch(self) -> None:
        response = admit(review(target_pod()))["response"]
        self.assertTrue(response["allowed"])
        self.assertEqual(response["uid"], "test-uid")
        self.assertEqual(response["patchType"], "JSONPatch")
        patch = json.loads(base64.b64decode(response["patch"]))
        self.assertTrue(
            any(
                operation["path"] == "/spec/runtimeClassName"
                for operation in patch
            )
        )

    def test_denies_an_unmatched_workload(self) -> None:
        pod = target_pod()
        pod["metadata"]["labels"]["openclaw.dev/workload-role"] = "controller"
        response = admit(review(pod))["response"]
        self.assertFalse(response["allowed"])
        self.assertEqual(response["status"]["code"], 400)
        self.assertIn("workload role", response["status"]["message"])

    def test_denies_an_unsafe_target_pod(self) -> None:
        pod = target_pod()
        pod["spec"]["containers"][-1]["volumeMounts"][-1]["subPathExpr"] = "$x"
        response = admit(review(pod))["response"]
        self.assertFalse(response["allowed"])
        self.assertEqual(response["status"]["code"], 400)
        self.assertIn("subPathExpr", response["status"]["message"])


if __name__ == "__main__":
    unittest.main()

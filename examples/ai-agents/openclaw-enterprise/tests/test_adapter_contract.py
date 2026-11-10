"""Static deployment contracts for the OCE Nitro admission adapter."""

from __future__ import annotations

import pathlib
from typing import Any

import yaml

SAMPLE = pathlib.Path(__file__).resolve().parent.parent
DEPLOY = SAMPLE / "deploy"


def _yaml_documents(path: pathlib.Path) -> list[dict[str, Any]]:
    documents = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    return [document for document in documents if document]


def _one(
    documents: list[dict[str, Any]], kind: str, name: str
) -> dict[str, Any]:
    matches = [
        document
        for document in documents
        if document.get("kind") == kind
        and document.get("metadata", {}).get("name") == name
    ]
    assert len(matches) == 1, f"expected one {kind}/{name}, found {len(matches)}"
    return matches[0]


def test_webhook_matches_all_pods_in_oce_namespaces_and_fails_closed() -> None:
    documents = _yaml_documents(DEPLOY / "adapter-webhook.yaml")
    webhook_configuration = _one(
        documents,
        "MutatingWebhookConfiguration",
        "openclaw-enterprise-nitro-adapter",
    )
    webhook = webhook_configuration["webhooks"][0]

    assert webhook["failurePolicy"] == "Fail"
    assert webhook["sideEffects"] == "None"
    assert webhook["namespaceSelector"] == {
        "matchLabels": {
            "app.kubernetes.io/managed-by": "openclaw-enterprise"
        }
    }
    assert "objectSelector" not in webhook
    assert webhook["rules"] == [
        {
            "apiGroups": [""],
            "apiVersions": ["v1"],
            "operations": ["CREATE"],
            "resources": ["pods"],
            "scope": "Namespaced",
        }
    ]


def test_webhook_pod_has_restricted_security_and_no_service_account_token() -> None:
    documents = _yaml_documents(DEPLOY / "adapter-webhook.yaml")
    deployment = _one(
        documents,
        "Deployment",
        "openclaw-enterprise-nitro-adapter",
    )
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]

    assert pod["automountServiceAccountToken"] is False
    assert pod["enableServiceLinks"] is False
    assert pod["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    assert container["securityContext"] == {
        "allowPrivilegeEscalation": False,
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "runAsUser": 65532,
        "runAsGroup": 65532,
        "capabilities": {"drop": ["ALL"]},
    }
    assert container["resources"]["requests"]
    assert container["resources"]["limits"]
    assert container["livenessProbe"]["httpGet"]["scheme"] == "HTTPS"
    assert container["readinessProbe"]["httpGet"]["scheme"] == "HTTPS"


def test_webhook_certificate_and_service_names_match() -> None:
    documents = _yaml_documents(DEPLOY / "adapter-webhook.yaml")
    certificate = _one(
        documents,
        "Certificate",
        "openclaw-enterprise-nitro-adapter-serving",
    )
    service = _one(
        documents,
        "Service",
        "openclaw-enterprise-nitro-adapter",
    )
    namespace = service["metadata"]["namespace"]
    service_name = service["metadata"]["name"]
    expected_names = {
        f"{service_name}.{namespace}.svc",
        f"{service_name}.{namespace}.svc.cluster.local",
    }

    assert set(certificate["spec"]["dnsNames"]) == expected_names
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["ports"] == [
        {
            "name": "https",
            "port": 443,
            "targetPort": "https",
            "protocol": "TCP",
        }
    ]

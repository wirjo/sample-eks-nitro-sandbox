"""Static security contracts for the AgentGateway EKS deployment."""

from __future__ import annotations

import json
import pathlib
import re
from typing import Any

import yaml

SAMPLE = pathlib.Path(__file__).resolve().parent.parent
MANIFEST = SAMPLE / "deploy" / "agentgateway.yaml"
IAM = SAMPLE / "iam"
NAMESPACE = "openclaw-enterprise-agw"
PROFILE = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
MODEL = "anthropic.claude-haiku-4-5-20251001-v1:0"


def _documents() -> list[dict[str, Any]]:
    return [
        document
        for document in yaml.safe_load_all(MANIFEST.read_text(encoding="utf-8"))
        if document
    ]


def _one(kind: str) -> dict[str, Any]:
    matches = [document for document in _documents() if document["kind"] == kind]
    assert len(matches) == 1, f"expected one {kind}, found {len(matches)}"
    return matches[0]


def _named(kind: str, name: str) -> dict[str, Any]:
    matches = [
        document
        for document in _documents()
        if document["kind"] == kind and document["metadata"]["name"] == name
    ]
    assert len(matches) == 1, f"expected one {kind}/{name}, found {len(matches)}"
    return matches[0]


def _container() -> tuple[dict[str, Any], dict[str, Any]]:
    pod_spec = _one("Deployment")["spec"]["template"]["spec"]
    assert len(pod_spec["containers"]) == 1
    return pod_spec, pod_spec["containers"][0]


def test_namespace_and_service_account_enforce_restricted_identity():
    namespace = _one("Namespace")
    account = _one("ServiceAccount")
    pod_spec, _ = _container()

    assert namespace["metadata"]["name"] == NAMESPACE
    labels = namespace["metadata"]["labels"]
    for mode in ("enforce", "audit", "warn"):
        assert labels[f"pod-security.kubernetes.io/{mode}"] == "restricted"

    assert account["metadata"]["namespace"] == NAMESPACE
    assert account["metadata"]["name"] == "agentgateway"
    assert account["automountServiceAccountToken"] is False
    assert pod_spec["serviceAccountName"] == account["metadata"]["name"]
    assert pod_spec["automountServiceAccountToken"] is False


def test_cert_manager_certificate_matches_service_dns_and_gateway_tls():
    root = _named("Certificate", "agentgateway-root")
    ca_issuer = _named("Issuer", "agentgateway-ca")
    certificate = _named("Certificate", "agentgateway-serving")
    config_map = _one("ConfigMap")
    pod_spec, container = _container()
    config = yaml.safe_load(config_map["data"]["config.yaml"])

    assert root["spec"]["isCA"] is True
    assert root["spec"]["secretName"] == "agentgateway-ca"
    assert ca_issuer["spec"]["ca"]["secretName"] == root["spec"]["secretName"]
    assert certificate["spec"]["issuerRef"]["name"] == ca_issuer["metadata"]["name"]
    assert certificate["spec"]["dnsNames"] == [
        f"agentgateway.{NAMESPACE}.svc",
        f"agentgateway.{NAMESPACE}.svc.cluster.local",
    ]
    assert certificate["spec"]["secretName"] == "agentgateway-tls"

    gateway = config["gateways"]["llm"]
    assert gateway["port"] == 4000
    assert gateway["protocol"] == "HTTPS"
    assert gateway["tls"] == {
        "cert": "/tls/tls.crt",
        "key": "/tls/tls.key",
        "minTLSVersion": "TLS_V1_2",
    }
    assert config["llm"]["gateways"] == ["llm"]

    tls_volume = next(volume for volume in pod_spec["volumes"] if volume["name"] == "tls")
    assert tls_volume["secret"]["secretName"] == certificate["spec"]["secretName"]
    assert tls_volume["secret"]["defaultMode"] == 0o440
    tls_mount = next(
        mount for mount in container["volumeMounts"] if mount["name"] == "tls"
    )
    assert tls_mount == {"name": "tls", "mountPath": "/tls", "readOnly": True}


def test_client_key_comes_only_from_a_kubernetes_secret():
    config = yaml.safe_load(_one("ConfigMap")["data"]["config.yaml"])
    _, container = _container()

    api_key = config["llm"]["policies"]["apiKey"]
    assert api_key["mode"] == "strict"
    assert api_key["location"] == {
        "header": {"name": "authorization", "prefix": "Bearer "}
    }
    assert api_key["keys"] == [
        {
            "keyHash": "${AGW_TENANT_A_KEY_SHA256}",
            "allowedModels": ["claude-haiku"],
        },
        {
            "keyHash": "${AGW_TENANT_B_KEY_SHA256}",
            "allowedModels": ["claude-haiku"],
        },
    ]

    for tenant in ("A", "B"):
        client_key = next(
            item
            for item in container["env"]
            if item["name"] == f"AGW_TENANT_{tenant}_KEY_SHA256"
        )
        assert "value" not in client_key
        assert client_key["valueFrom"]["secretKeyRef"] == {
            "name": "agw-client-key",
            "key": f"tenant-{tenant.lower()}-sha256",
            "optional": False,
        }
    session_key = next(
        item for item in container["env"] if item["name"] == "SESSION_KEY"
    )
    assert session_key["valueFrom"]["secretKeyRef"] == {
        "name": "agw-session-key",
        "key": "key",
        "optional": False,
    }
    assert not any(document["kind"] == "Secret" for document in _documents())


def test_bedrock_model_uses_implicit_aws_authentication():
    config = yaml.safe_load(_one("ConfigMap")["data"]["config.yaml"])
    model = config["llm"]["models"][0]

    assert model["provider"] == "bedrock"
    assert model["auth"] == {"aws": {}}


def test_deployment_uses_an_immutable_image_and_restricted_container():
    pod_spec, container = _container()

    assert re.fullmatch(
        r"cr\.agentgateway\.dev/agentgateway@sha256:[0-9a-f]{64}",
        container["image"],
    )
    assert pod_spec["enableServiceLinks"] is False
    assert pod_spec["securityContext"]["seccompProfile"] == {"type": "RuntimeDefault"}
    assert pod_spec["securityContext"]["runAsNonRoot"] is True

    security = container["securityContext"]
    assert security["allowPrivilegeEscalation"] is False
    assert security["readOnlyRootFilesystem"] is True
    assert security["runAsNonRoot"] is True
    assert security["capabilities"] == {"drop": ["ALL"]}


def test_deployment_has_resources_health_checks_and_disruption_budget():
    deployment = _one("Deployment")
    budget = _one("PodDisruptionBudget")
    _, container = _container()

    assert deployment["spec"]["replicas"] >= 2
    assert container["resources"]["requests"] == {"cpu": "100m", "memory": "128Mi"}
    assert container["resources"]["limits"] == {"cpu": "1", "memory": "512Mi"}

    assert container["startupProbe"]["httpGet"] == {
        "path": "/healthz/ready",
        "port": "health",
        "scheme": "HTTP",
    }
    assert container["readinessProbe"]["httpGet"] == {
        "path": "/healthz/ready",
        "port": "health",
        "scheme": "HTTP",
    }
    assert container["livenessProbe"]["tcpSocket"] == {"port": "https"}
    assert budget["spec"]["minAvailable"] == 1
    assert budget["spec"]["selector"] == deployment["spec"]["selector"]


def test_service_is_cluster_internal_and_forwards_only_to_https_listener():
    deployment = _one("Deployment")
    service = _one("Service")
    _, container = _container()

    assert service["metadata"]["namespace"] == NAMESPACE
    assert service["spec"]["type"] == "ClusterIP"
    assert service["spec"]["selector"] == deployment["spec"]["selector"]["matchLabels"]
    assert service["spec"]["ports"] == [
        {"name": "https", "port": 443, "targetPort": "https", "protocol": "TCP"}
    ]
    assert {"name": "https", "containerPort": 4000, "protocol": "TCP"} in container[
        "ports"
    ]


def test_agentgateway_ingress_is_limited_to_managed_oce_workloads():
    policy = _one("NetworkPolicy")

    assert policy["metadata"]["namespace"] == NAMESPACE
    assert policy["spec"]["podSelector"] == {
        "matchLabels": {"app.kubernetes.io/name": "agentgateway"}
    }
    assert policy["spec"]["policyTypes"] == ["Ingress"]
    assert policy["spec"]["ingress"] == [
        {
            "from": [
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/managed-by": "openclaw-enterprise"
                        }
                    },
                    "podSelector": {
                        "matchExpressions": [
                            {
                                "key": "openclaw.dev/workload-role",
                                "operator": "In",
                                "values": ["agent", "gateway"],
                            }
                        ]
                    },
                }
            ],
            "ports": [{"protocol": "TCP", "port": 4000}],
        }
    ]


def test_bedrock_policy_covers_only_the_profile_and_its_destination_models():
    account_id = "111122223333"
    profile_arn = (
        f"arn:aws:bedrock:us-west-2:{account_id}:inference-profile/{PROFILE}"
    )
    policy = json.loads(
        (IAM / "bedrock-invoke.json")
        .read_text(encoding="utf-8")
        .replace("<ACCOUNT_ID>", account_id)
    )
    assert len(policy["Statement"]) == 2

    profile, models = policy["Statement"]
    expected_actions = {
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
    }
    assert set(profile["Action"]) == expected_actions
    assert profile["Resource"] == profile_arn
    assert profile["Condition"]["StringEquals"] == {
        "aws:RequestedRegion": "us-west-2"
    }

    assert set(models["Action"]) == expected_actions
    assert set(models["Resource"]) == {
        f"arn:aws:bedrock:{region}::foundation-model/{MODEL}"
        for region in ("us-east-1", "us-east-2", "us-west-2")
    }
    assert models["Condition"]["StringEquals"] == {
        "bedrock:InferenceProfileArn": profile_arn
    }
    assert "*" not in json.dumps(policy)


def test_pod_identity_trust_is_bound_to_agentgateway_service_account():
    policy = json.loads((IAM / "pod-identity-trust.json").read_text(encoding="utf-8"))
    assert len(policy["Statement"]) == 1
    statement = policy["Statement"][0]

    assert statement["Principal"] == {"Service": "pods.eks.amazonaws.com"}
    assert set(statement["Action"]) == {"sts:AssumeRole", "sts:TagSession"}
    assert statement["Condition"]["StringEquals"] == {
        "aws:SourceAccount": "<ACCOUNT_ID>",
        "aws:RequestTag/kubernetes-namespace": NAMESPACE,
        "aws:RequestTag/kubernetes-service-account": "agentgateway",
    }
    assert statement["Condition"]["ArnEquals"] == {
        "aws:SourceArn": (
            "arn:aws:eks:<REGION>:<ACCOUNT_ID>:cluster/<CLUSTER_NAME>"
        )
    }

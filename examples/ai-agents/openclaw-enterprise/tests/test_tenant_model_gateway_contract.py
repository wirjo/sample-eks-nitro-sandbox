"""Contracts for the per-tenant private model-gateway path."""

from __future__ import annotations

import pathlib

import yaml

SAMPLE = pathlib.Path(__file__).resolve().parent.parent
TEMPLATE = SAMPLE / "deploy" / "tenant-model-gateway.yaml.tpl"
SCRIPT = SAMPLE / "scripts" / "configure-tenant-model-gateway.sh"


def _network_policies() -> list[dict]:
    rendered = (
        TEMPLATE.read_text(encoding="utf-8")
        .replace("OCE_TENANT_NAMESPACE", "tenant-a")
        .replace("OCE_AGENTGATEWAY_SERVICE_CIDR", "10.100.0.42/32")
    )
    return [
        document
        for document in yaml.safe_load_all(rendered)
        if document is not None
    ]


def _named(name: str) -> dict:
    matches = [
        policy
        for policy in _network_policies()
        if policy["metadata"]["name"] == name
    ]
    assert len(matches) == 1
    return matches[0]


def test_default_deny_applies_to_every_tenant_pod() -> None:
    policy = _named("default-deny-egress")

    assert policy["spec"] == {
        "podSelector": {},
        "policyTypes": ["Egress"],
    }


def test_dns_egress_is_explicitly_allowed() -> None:
    policy = _named("allow-dns")

    assert policy["spec"]["podSelector"] == {}
    assert policy["spec"]["egress"] == [
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": "kube-system"
                        }
                    },
                    "podSelector": {
                        "matchLabels": {"k8s-app": "kube-dns"}
                    },
                }
            ],
            "ports": [
                {"protocol": "UDP", "port": 53},
                {"protocol": "TCP", "port": 53},
            ],
        }
    ]


def test_network_policy_limits_egress_to_private_agentgateway() -> None:
    policy = _named("allow-agentgateway")

    assert policy["kind"] == "NetworkPolicy"
    assert policy["metadata"] == {
        "name": "allow-agentgateway",
        "namespace": "tenant-a",
    }
    assert policy["spec"]["podSelector"]["matchExpressions"] == [
        {
            "key": "openclaw.dev/workload-role",
            "operator": "In",
            "values": ["agent", "gateway"],
        }
    ]
    assert policy["spec"]["policyTypes"] == ["Egress"]
    assert policy["spec"]["egress"] == [
        {
            "to": [
                {"ipBlock": {"cidr": "10.100.0.42/32"}},
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": "openclaw-enterprise-agw"
                        }
                    },
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": "agentgateway"
                        }
                    },
                }
            ],
            "ports": [
                {"protocol": "TCP", "port": 443},
                {"protocol": "TCP", "port": 4000},
            ],
        }
    ]


def test_configure_script_copies_only_public_ca_and_applies_policy() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "app\\.kubernetes\\.io/managed-by" in script
    assert "tls\\.crt" in script
    assert "tls\\.key" not in script
    assert "--dry-run=client" in script
    assert "jq '.immutable = true'" in script
    assert "agentgateway_cidr" in script
    assert "OCE_AGENTGATEWAY_SERVICE_CIDR" in script

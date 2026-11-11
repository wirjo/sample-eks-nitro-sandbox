from __future__ import annotations

import copy
import json
import unittest

from adapter import (
    AGW_CA_PATH,
    AGW_CA_MOUNT_PATH,
    AGW_CA_VOLUME,
    AdmissionError,
    LINK_INIT_NAME,
    NODE_CA_ENV,
    build_patch,
)


def target_pod() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "namespace": "oce-tenant-test",
            "labels": {"openclaw.dev/workload-role": "gateway"},
        },
        "spec": {
            "initContainers": [
                *[
                    {"name": f"setup-{index}", "image": "example.invalid/oce:test"}
                    for index in range(9)
                ],
                {
                    "name": "prepare-private-state",
                    "image": "example.invalid/oce@sha256:abc",
                    "imagePullPolicy": "IfNotPresent",
                    "volumeMounts": [
                        {
                            "name": "runtime-state",
                            "mountPath": "/runtime-state",
                            "mountPropagation": "HostToContainer",
                        },
                        {
                            "name": "openclaw-gateway-state",
                            "mountPath": "/gateway-state",
                        },
                    ],
                },
            ],
            "containers": [
                *[
                    {"name": f"helper-{index}", "image": "example.invalid/oce:test"}
                    for index in range(5)
                ],
                {
                    "name": "gateway",
                    "image": "example.invalid/oce@sha256:abc",
                    "volumeMounts": [
                        {
                            "name": "runtime-state",
                            "mountPath": "/home/node",
                            "subPath": "home",
                            "mountPropagation": "HostToContainer",
                        },
                        {
                            "name": "workspace",
                            "mountPath": "/workspace",
                            "subPathExpr": "$(TENANT)/workspace",
                            "readOnly": True,
                            "recursiveReadOnly": "Enabled",
                        },
                        {
                            "name": "openclaw-gateway-state",
                            "mountPath": "/home/node/.openclaw/sessions",
                            "subPath": "sessions",
                        },
                        {
                            "name": "openclaw-gateway-state",
                            "mountPath": "/home/node/.openclaw/agents",
                            "subPath": "agents",
                            "readOnly": True,
                        },
                    ],
                },
            ],
            "volumes": [
                {"name": "runtime-state", "emptyDir": {}},
                {"name": "workspace", "emptyDir": {}},
                {
                    "name": "openclaw-gateway-state",
                    "persistentVolumeClaim": {"claimName": "gateway-state"},
                },
            ],
        },
    }


def admitted_target_pod() -> dict:
    pod = target_pod()
    pod["spec"]["volumes"].extend(
        [
            {
                "name": "kube-api-access-k82tq",
                "projected": {
                    "defaultMode": 420,
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "expirationSeconds": 3607,
                                "path": "token",
                            }
                        },
                        {
                            "configMap": {
                                "name": "kube-root-ca.crt",
                                "items": [{"key": "ca.crt", "path": "ca.crt"}],
                            }
                        },
                        {
                            "downwardAPI": {
                                "items": [
                                    {
                                        "path": "namespace",
                                        "fieldRef": {
                                            "apiVersion": "v1",
                                            "fieldPath": "metadata.namespace",
                                        },
                                    }
                                ]
                            }
                        },
                    ],
                },
            },
            {
                "name": "projected-settings",
                "projected": {
                    "sources": [{"configMap": {"name": "runtime-settings"}}]
                },
            },
            {
                "name": "custom-api-token",
                "projected": {
                    "sources": [
                        {
                            "serviceAccountToken": {
                                "audience": "agentgateway",
                                "expirationSeconds": 600,
                                "path": "credentials/token",
                            }
                        }
                    ]
                },
            },
        ]
    )

    for container in [
        *pod["spec"]["initContainers"],
        *pod["spec"]["containers"],
    ]:
        container.setdefault("volumeMounts", []).append(
            {
                "name": "kube-api-access-k82tq",
                "readOnly": True,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
            }
        )

    pod["spec"]["initContainers"][-1]["volumeMounts"].append(
        {
            "name": "projected-settings",
            "mountPath": "/etc/runtime-settings",
            "readOnly": True,
        }
    )
    pod["spec"]["containers"][-1]["volumeMounts"].extend(
        [
            {
                "name": "projected-settings",
                "mountPath": "/etc/runtime-settings",
                "readOnly": True,
            },
            {
                "name": "custom-api-token",
                "mountPath": "/var/run/openclaw/tokens",
                "readOnly": True,
            },
        ]
    )
    return pod


def apply_patch(document: dict, patch: list[dict]) -> dict:
    result = copy.deepcopy(document)
    for operation in patch:
        parts = operation["path"].strip("/").split("/")
        parent = result
        for part in parts[:-1]:
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
        key = parts[-1]
        if isinstance(parent, list):
            index = len(parent) if key == "-" else int(key)
            if operation["op"] == "add":
                parent.insert(index, operation["value"])
            elif operation["op"] == "remove":
                parent.pop(index)
            else:
                parent[index] = operation["value"]
        else:
            if operation["op"] == "remove":
                del parent[key]
            else:
                parent[key] = operation["value"]
    return result


class BuildPatchTests(unittest.TestCase):
    def test_removes_preinjected_service_account_volume_only(self) -> None:
        pod = admitted_target_pod()
        preserved = copy.deepcopy(pod["spec"]["volumes"][-2:])

        volumes = apply_patch(pod, build_patch(pod))["spec"]["volumes"]

        self.assertNotIn(
            "kube-api-access-k82tq",
            [volume["name"] for volume in volumes],
        )
        for volume in preserved:
            self.assertIn(volume, volumes)

    def test_removes_preinjected_service_account_mounts_only(self) -> None:
        pod = admitted_target_pod()
        service_account_mount = {
            "name": "kube-api-access-k82tq",
            "readOnly": True,
            "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount",
        }
        unrelated_mount = {
            "name": "projected-settings",
            "mountPath": "/etc/runtime-settings",
            "readOnly": True,
        }
        custom_token_mount = {
            "name": "custom-api-token",
            "mountPath": "/var/run/openclaw/tokens",
            "readOnly": True,
        }

        rendered = apply_patch(pod, build_patch(pod))
        spec = rendered["spec"]

        for container in [
            *spec["initContainers"],
            *spec["containers"],
        ]:
            self.assertNotIn(
                service_account_mount,
                container.get("volumeMounts", []),
                container["name"],
            )
        rendered_prep = next(
            container
            for container in spec["initContainers"]
            if container["name"] == "prepare-private-state"
        )
        rendered_gateway = next(
            container
            for container in spec["containers"]
            if container["name"] == "gateway"
        )
        self.assertIn(unrelated_mount, rendered_prep["volumeMounts"])
        self.assertIn(unrelated_mount, rendered_gateway["volumeMounts"])
        self.assertIn(custom_token_mount, rendered_gateway["volumeMounts"])

    def test_rewrites_structurally_and_preserves_unrelated_mounts(self) -> None:
        pod = target_pod()
        workspace = copy.deepcopy(
            pod["spec"]["containers"][-1]["volumeMounts"][1]
        )

        rendered = apply_patch(pod, build_patch(pod))
        spec = rendered["spec"]

        self.assertEqual(spec["runtimeClassName"], "isolated-sandbox")
        self.assertIs(spec["automountServiceAccountToken"], False)
        gateway_mounts = spec["containers"][-1]["volumeMounts"]
        self.assertEqual(gateway_mounts[1], workspace)
        self.assertEqual(
            [
                mount
                for mount in gateway_mounts
                if mount["name"] == "openclaw-gateway-state"
            ],
            [
                {
                    "name": "openclaw-gateway-state",
                    "mountPath": "/gateway-state",
                }
            ],
        )
        self.assertIn(
            {
                "name": AGW_CA_VOLUME,
                "mountPath": AGW_CA_MOUNT_PATH,
                "readOnly": True,
            },
            gateway_mounts,
        )
        self.assertIn(
            {"name": NODE_CA_ENV, "value": AGW_CA_PATH},
            spec["containers"][-1]["env"],
        )
        self.assertEqual(
            spec["volumes"][-1],
            {
                "name": AGW_CA_VOLUME,
                "configMap": {
                    "name": AGW_CA_VOLUME,
                    "items": [{"key": "ca.crt", "path": "ca.crt"}],
                },
            },
        )

        prep_index = next(
            index
            for index, container in enumerate(spec["initContainers"])
            if container["name"] == "prepare-private-state"
        )
        link_init = spec["initContainers"][prep_index + 1]
        self.assertEqual(link_init["name"], LINK_INIT_NAME)
        self.assertEqual(
            [mount["name"] for mount in link_init["volumeMounts"]],
            ["runtime-state", "openclaw-gateway-state"],
        )
        self.assertEqual(
            json.loads(link_init["env"][0]["value"]),
            [
                {"link": ".openclaw/agents", "target": "agents"},
                {"link": ".openclaw/sessions", "target": "sessions"},
            ],
        )

    def test_rejects_missing_or_unknown_oce_workload_role(self) -> None:
        pod = target_pod()
        pod["metadata"]["labels"] = {"app": "unrelated"}
        with self.assertRaisesRegex(AdmissionError, "workload role"):
            build_patch(pod)

        pod = target_pod()
        pod["metadata"]["labels"]["openclaw.dev/workload-role"] = "controller"
        with self.assertRaisesRegex(AdmissionError, "workload role"):
            build_patch(pod)

    def test_rejects_state_free_oce_pods(self) -> None:
        pod = target_pod()
        pod["spec"]["volumes"] = [{"name": "runtime-state", "emptyDir": {}}]
        pod["spec"]["containers"][-1]["volumeMounts"] = []
        pod["spec"]["initContainers"][-1]["volumeMounts"] = [
            {"name": "runtime-state", "mountPath": "/runtime-state"}
        ]
        with self.assertRaisesRegex(AdmissionError, "requires openclaw-gateway-state"):
            build_patch(pod)

    def test_deduplicates_link_input_deterministically(self) -> None:
        pod = target_pod()
        duplicate = copy.deepcopy(pod["spec"]["containers"][-1])
        duplicate["name"] = "duplicate-consumer"
        pod["spec"]["containers"].insert(0, duplicate)

        rendered = apply_patch(pod, build_patch(pod))
        link_init = next(
            container
            for container in rendered["spec"]["initContainers"]
            if container["name"] == LINK_INIT_NAME
        )
        self.assertEqual(len(json.loads(link_init["env"][0]["value"])), 2)

    def test_rejects_target_sub_path_expr(self) -> None:
        pod = target_pod()
        mount = pod["spec"]["containers"][-1]["volumeMounts"][-1]
        mount.pop("subPath")
        mount["subPathExpr"] = "$(TENANT)/sessions"
        with self.assertRaisesRegex(AdmissionError, "subPathExpr"):
            build_patch(pod)

    def test_rejects_unsafe_or_conflicting_target_shapes(self) -> None:
        cases = []

        unsafe = target_pod()
        unsafe["spec"]["containers"][-1]["volumeMounts"][-1]["subPath"] = "../sessions"
        cases.append(unsafe)

        collision = target_pod()
        collision["spec"]["containers"][-1]["volumeMounts"].append(
            {"name": "other", "mountPath": "/gateway-state"}
        )
        cases.append(collision)

        missing_prep = target_pod()
        missing_prep["spec"]["initContainers"][-1]["name"] = "not-prepare"
        cases.append(missing_prep)

        wrong_runtime = target_pod()
        wrong_runtime["spec"]["runtimeClassName"] = "runc"
        cases.append(wrong_runtime)

        for pod in cases:
            with self.subTest(pod=pod):
                with self.assertRaises(AdmissionError):
                    build_patch(pod)

    def test_refuses_dedicated_workspace(self) -> None:
        pod = target_pod()
        pod["spec"]["volumes"].append(
            {
                "name": "openclaw-workspace",
                "persistentVolumeClaim": {"claimName": "dedicated-workspace"},
            }
        )
        with self.assertRaisesRegex(AdmissionError, "dedicated"):
            build_patch(pod)

    def test_refuses_conflicting_ca_configuration(self) -> None:
        pod = target_pod()
        pod["spec"]["containers"][-1]["env"] = [
            {"name": NODE_CA_ENV, "value": "/different/ca.crt"}
        ]
        with self.assertRaisesRegex(AdmissionError, NODE_CA_ENV):
            build_patch(pod)


if __name__ == "__main__":
    unittest.main()

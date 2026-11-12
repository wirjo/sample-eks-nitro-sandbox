"""Pure OCE Pod mutation logic for the Nitro admission webhook."""

from __future__ import annotations

import copy
import json
from pathlib import PurePosixPath
from typing import Any

OCE_ROLES = frozenset({"agent", "gateway"})
STATE_VOLUME = "openclaw-gateway-state"
RUNTIME_VOLUME = "runtime-state"
DEDICATED_WORKSPACE_VOLUME = "openclaw-workspace"
STATE_ROOT = "/gateway-state"
RUNTIME_ROOT = "/runtime-state"
HOME_ROOT = "/home/node/"
LINK_INIT_NAME = "nitro-link-gateway-state"
AGW_CA_VOLUME = "agentgateway-ca"
AGW_CA_CONFIG_MAP = "agentgateway-ca"
AGW_CA_MOUNT_PATH = "/etc/agentgateway-ca"
AGW_CA_PATH = f"{AGW_CA_MOUNT_PATH}/ca.crt"
NODE_CA_ENV = "NODE_EXTRA_CA_CERTS"
TMPDIR_ENV = "TMPDIR"
TMPDIR_PATH = "/home/node/.openclaw/tmp"
SERVICE_ACCOUNT_MOUNT_PATH = "/var/run/secrets/kubernetes.io/serviceaccount"

LINK_SCRIPT = r"""
const fs = require("node:fs");
const path = require("node:path");
const links = JSON.parse(process.env.OCE_STATE_LINKS || "[]");
const temporary = "/runtime-state/home/.openclaw/tmp";
fs.mkdirSync(temporary, {recursive: true, mode: 0o700});
fs.chmodSync(temporary, 0o700);
for (const item of links) {
  const link = path.posix.join("/runtime-state/home", item.link);
  const target = path.posix.join("/gateway-state", item.target);
  fs.mkdirSync(path.posix.dirname(link), {recursive: true});
  let current;
  try {
    current = fs.lstatSync(link);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (current === undefined) {
    fs.symlinkSync(target, link);
  } else if (!current.isSymbolicLink() || fs.readlinkSync(link) !== target) {
    throw new Error(`refusing to replace ${link}`);
  }
}
""".strip()


class AdmissionError(ValueError):
    """A target OCE Pod has a shape the adapter cannot safely mutate."""


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _safe_relative_path(value: Any, field: str) -> str:
    if not _is_nonempty_string(value):
        raise AdmissionError(f"{field} must be a non-empty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise AdmissionError(f"{field} must not be absolute or contain dot segments")
    if str(path) != value or "//" in value:
        raise AdmissionError(f"{field} must be a normalized relative path")
    return value


def _container_groups(spec: dict[str, Any]) -> tuple[list[Any], list[Any]]:
    init_containers = spec.get("initContainers", [])
    containers = spec.get("containers")
    if not isinstance(init_containers, list):
        raise AdmissionError("spec.initContainers must be a list")
    if not isinstance(containers, list) or not containers:
        raise AdmissionError("spec.containers must be a non-empty list")
    return init_containers, containers


def _mounts(container: Any, location: str) -> list[Any]:
    if not isinstance(container, dict):
        raise AdmissionError(f"{location} must be an object")
    mounts = container.get("volumeMounts", [])
    if not isinstance(mounts, list):
        raise AdmissionError(f"{location}.volumeMounts must be a list")
    return mounts


def _validate_link_paths(links: dict[str, str]) -> None:
    paths = sorted(PurePosixPath(link).parts for link in links)
    for index, path in enumerate(paths):
        for other in paths[index + 1 :]:
            if len(path) < len(other) and other[: len(path)] == path:
                raise AdmissionError(
                    "gateway-state mount paths must not contain one another"
                )


def _runtime_environment(container: dict[str, Any], location: str) -> list[Any]:
    environment = container.get("env", [])
    if not isinstance(environment, list):
        raise AdmissionError(f"{location}.env must be a list")
    required = {
        NODE_CA_ENV: AGW_CA_PATH,
        TMPDIR_ENV: TMPDIR_PATH,
    }
    for name, value in required.items():
        matches = [
            entry
            for entry in environment
            if isinstance(entry, dict) and entry.get("name") == name
        ]
        if len(matches) > 1:
            raise AdmissionError(f"{location} has duplicate {name} entries")
        if matches and matches[0] != {"name": name, "value": value}:
            raise AdmissionError(f"{location} already configures {name}")
    return environment


def _default_service_account_volumes(
    volumes: list[Any], mounts: list[Any]
) -> set[str]:
    """Find only Kubernetes' standard auto-injected service-account projections."""
    removable: set[str] = set()
    for volume in volumes:
        if not isinstance(volume, dict):
            continue
        name = volume.get("name")
        projected = volume.get("projected")
        if not (
            _is_nonempty_string(name)
            and name.startswith("kube-api-access-")
            and isinstance(projected, dict)
            and isinstance(projected.get("sources"), list)
        ):
            continue

        sources = projected["sources"]
        has_default_token = any(
            isinstance(source, dict)
            and isinstance(source.get("serviceAccountToken"), dict)
            and source["serviceAccountToken"].get("path") == "token"
            for source in sources
        )
        has_root_ca = any(
            isinstance(source, dict)
            and isinstance(source.get("configMap"), dict)
            and source["configMap"].get("name") == "kube-root-ca.crt"
            for source in sources
        )
        has_namespace = any(
            isinstance(source, dict)
            and isinstance(source.get("downwardAPI"), dict)
            and any(
                isinstance(item, dict)
                and item.get("path") == "namespace"
                and isinstance(item.get("fieldRef"), dict)
                and item["fieldRef"].get("fieldPath") == "metadata.namespace"
                for item in source["downwardAPI"].get("items", [])
            )
            for source in sources
        )
        references = [
            mount
            for mount in mounts
            if isinstance(mount, dict) and mount.get("name") == name
        ]
        if (
            has_default_token
            and has_root_ca
            and has_namespace
            and references
            and all(
                mount.get("mountPath") == SERVICE_ACCOUNT_MOUNT_PATH
                for mount in references
            )
        ):
            removable.add(name)
    return removable


def build_patch(pod: dict[str, Any]) -> list[dict[str, Any]]:
    """Return an RFC 6902 patch, or raise AdmissionError for unsafe target Pods."""
    if not isinstance(pod, dict):
        raise AdmissionError("Pod must be an object")

    metadata = pod.get("metadata")
    labels = metadata.get("labels", {}) if isinstance(metadata, dict) else {}
    role = labels.get("openclaw.dev/workload-role") if isinstance(labels, dict) else None
    if role not in OCE_ROLES:
        raise AdmissionError("OCE workload role must be agent or gateway")

    spec = pod.get("spec")
    if not isinstance(spec, dict):
        raise AdmissionError("target OCE Pod must have a spec")
    volumes = spec.get("volumes", [])
    if not isinstance(volumes, list):
        raise AdmissionError("spec.volumes must be a list")
    init_containers, containers = _container_groups(spec)

    reserved_ca_volumes = [
        volume
        for volume in volumes
        if isinstance(volume, dict) and volume.get("name") == AGW_CA_VOLUME
    ]
    if reserved_ca_volumes:
        raise AdmissionError(f"volume name {AGW_CA_VOLUME} is reserved")

    all_mounts = [
        mount
        for group_name, group in (
            ("spec.initContainers", init_containers),
            ("spec.containers", containers),
        )
        for index, container in enumerate(group)
        for mount in _mounts(container, f"{group_name}[{index}]")
    ]
    default_service_account_volumes = _default_service_account_volumes(
        volumes, all_mounts
    )
    if any(
        isinstance(volume, dict)
        and volume.get("name") == DEDICATED_WORKSPACE_VOLUME
        for volume in volumes
    ) or any(
        isinstance(mount, dict)
        and mount.get("name") == DEDICATED_WORKSPACE_VOLUME
        for mount in all_mounts
    ):
        raise AdmissionError(
            "dedicated openclaw-workspace Pods are not supported by this adapter"
        )

    state_volumes = [
        volume
        for volume in volumes
        if isinstance(volume, dict) and volume.get("name") == STATE_VOLUME
    ]
    if not state_volumes:
        raise AdmissionError(f"target OCE Pod requires {STATE_VOLUME}")
    if len(state_volumes) != 1:
        raise AdmissionError(f"expected exactly one {STATE_VOLUME} volume")
    claim = state_volumes[0].get("persistentVolumeClaim")
    if not isinstance(claim, dict) or not _is_nonempty_string(claim.get("claimName")):
        raise AdmissionError(f"{STATE_VOLUME} must be a PersistentVolumeClaim")

    runtime_volumes = [
        volume
        for volume in volumes
        if isinstance(volume, dict) and volume.get("name") == RUNTIME_VOLUME
    ]
    if len(runtime_volumes) != 1 or "emptyDir" not in runtime_volumes[0]:
        raise AdmissionError(f"{RUNTIME_VOLUME} must be exactly one emptyDir volume")

    prep_indexes = [
        index
        for index, container in enumerate(init_containers)
        if isinstance(container, dict)
        and container.get("name") == "prepare-private-state"
    ]
    if len(prep_indexes) != 1:
        raise AdmissionError("expected exactly one prepare-private-state init container")
    prep_index = prep_indexes[0]
    prep = init_containers[prep_index]
    if not _is_nonempty_string(prep.get("image")):
        raise AdmissionError("prepare-private-state must declare an image")
    if any(
        isinstance(container, dict) and container.get("name") == LINK_INIT_NAME
        for container in [*init_containers, *containers]
    ):
        raise AdmissionError(f"container name {LINK_INIT_NAME} is reserved")

    prep_mounts = _mounts(prep, f"spec.initContainers[{prep_index}]")
    prep_runtime = [
        mount
        for mount in prep_mounts
        if isinstance(mount, dict)
        and mount.get("name") == RUNTIME_VOLUME
        and mount.get("mountPath") == RUNTIME_ROOT
        and "subPath" not in mount
        and "subPathExpr" not in mount
    ]
    prep_state = [
        mount
        for mount in prep_mounts
        if isinstance(mount, dict)
        and mount.get("name") == STATE_VOLUME
        and mount.get("mountPath") == STATE_ROOT
        and "subPath" not in mount
        and "subPathExpr" not in mount
    ]
    if len(prep_runtime) != 1 or len(prep_state) != 1:
        raise AdmissionError(
            "prepare-private-state must mount runtime-state and gateway state at their roots"
        )

    links: dict[str, str] = {}
    mount_patches: list[dict[str, Any]] = []
    environment_patches: list[dict[str, Any]] = []
    groups = (
        ("initContainers", init_containers),
        ("containers", containers),
    )
    for group_name, group in groups:
        for index, container in enumerate(group):
            mounts = _mounts(container, f"spec.{group_name}[{index}]")
            rewritten: list[dict[str, Any]] = []
            state_root_count = 0
            state_affected = False
            mounts_changed = False

            for mount in mounts:
                if not isinstance(mount, dict):
                    raise AdmissionError(
                        f"spec.{group_name}[{index}].volumeMounts entries must be objects"
                    )
                if (
                    mount.get("name") in default_service_account_volumes
                    and mount.get("mountPath") == SERVICE_ACCOUNT_MOUNT_PATH
                ):
                    mounts_changed = True
                    continue
                if mount.get("name") != STATE_VOLUME:
                    if mount.get("mountPath") == STATE_ROOT:
                        raise AdmissionError(
                            f"{STATE_ROOT} is already used by another volume"
                        )
                    rewritten.append(copy.deepcopy(mount))
                    continue

                if "subPathExpr" in mount:
                    raise AdmissionError(
                        f"{STATE_VOLUME} subPathExpr mounts are not supported"
                    )
                if "subPath" not in mount:
                    if mount.get("mountPath") != STATE_ROOT:
                        raise AdmissionError(
                            f"{STATE_VOLUME} root mounts must use {STATE_ROOT}"
                        )
                    state_root_count += 1
                    rewritten.append(copy.deepcopy(mount))
                    continue

                if group_name == "initContainers" and index <= prep_index:
                    raise AdmissionError(
                        f"{STATE_VOLUME} subPath init mounts must run after prepare-private-state"
                    )
                mount_path = mount.get("mountPath")
                if not _is_nonempty_string(mount_path) or not mount_path.startswith(
                    HOME_ROOT
                ):
                    raise AdmissionError(
                        f"{STATE_VOLUME} subPath mounts must be below {HOME_ROOT}"
                    )
                link = _safe_relative_path(
                    mount_path.removeprefix(HOME_ROOT), "gateway-state mountPath"
                )
                target = _safe_relative_path(
                    mount.get("subPath"), "gateway-state subPath"
                )
                previous = links.setdefault(link, target)
                if previous != target:
                    raise AdmissionError(
                        f"conflicting gateway-state targets for {mount_path}"
                    )
                state_affected = True

            if state_root_count > 1:
                raise AdmissionError(
                    f"spec.{group_name}[{index}] has duplicate {STATE_ROOT} mounts"
                )
            if state_affected:
                if state_root_count == 0:
                    rewritten.append(
                        {"name": STATE_VOLUME, "mountPath": STATE_ROOT}
                    )
                if group_name == "containers":
                    if any(
                        mount.get("name") == AGW_CA_VOLUME
                        or mount.get("mountPath") == AGW_CA_MOUNT_PATH
                        for mount in rewritten
                    ):
                        raise AdmissionError(
                            f"spec.{group_name}[{index}] already uses the AgentGateway CA mount"
                        )
                    rewritten.append(
                        {
                            "name": AGW_CA_VOLUME,
                            "mountPath": AGW_CA_MOUNT_PATH,
                            "readOnly": True,
                        }
                    )
                    environment = _runtime_environment(
                        container, f"spec.{group_name}[{index}]"
                    )
                    required_environment = [
                        {"name": NODE_CA_ENV, "value": AGW_CA_PATH},
                        {"name": TMPDIR_ENV, "value": TMPDIR_PATH},
                    ]
                    missing_environment = [
                        entry
                        for entry in required_environment
                        if not any(
                            isinstance(current, dict)
                            and current.get("name") == entry["name"]
                            for current in environment
                        )
                    ]
                    if missing_environment:
                        environment_patches.append(
                            {
                                "op": "add"
                                if "env" not in container
                                else "replace",
                                "path": f"/spec/{group_name}/{index}/env",
                                "value": [
                                    *copy.deepcopy(environment),
                                    *missing_environment,
                                ],
                            }
                        )
            if state_affected or mounts_changed:
                mount_patches.append(
                    {
                        "op": "replace",
                        "path": f"/spec/{group_name}/{index}/volumeMounts",
                        "value": rewritten,
                    }
                )

    if not links:
        raise AdmissionError(
            f"{STATE_VOLUME} has no supported subPath mounts to adapt"
        )
    _validate_link_paths(links)

    link_data = [
        {"link": link, "target": target}
        for link, target in sorted(links.items())
    ]
    link_init: dict[str, Any] = {
        "name": LINK_INIT_NAME,
        "image": prep["image"],
        "command": ["node", "-e"],
        "args": [LINK_SCRIPT],
        "env": [
            {
                "name": "OCE_STATE_LINKS",
                "value": json.dumps(link_data, separators=(",", ":"), sort_keys=True),
            }
        ],
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "volumeMounts": [
            {"name": RUNTIME_VOLUME, "mountPath": RUNTIME_ROOT},
            {"name": STATE_VOLUME, "mountPath": STATE_ROOT},
        ],
    }
    if "imagePullPolicy" in prep:
        link_init["imagePullPolicy"] = prep["imagePullPolicy"]

    patch: list[dict[str, Any]] = []
    runtime_class = spec.get("runtimeClassName")
    if runtime_class is None:
        patch.append(
            {
                "op": "add",
                "path": "/spec/runtimeClassName",
                "value": "isolated-sandbox",
            }
        )
    elif runtime_class != "isolated-sandbox":
        raise AdmissionError(
            f"refusing to replace runtimeClassName {runtime_class!r}"
        )

    if "automountServiceAccountToken" not in spec:
        patch.append(
            {
                "op": "add",
                "path": "/spec/automountServiceAccountToken",
                "value": False,
            }
        )
    elif spec["automountServiceAccountToken"] is not False:
        patch.append(
            {
                "op": "replace",
                "path": "/spec/automountServiceAccountToken",
                "value": False,
            }
        )

    patch.extend(mount_patches)
    patch.extend(environment_patches)
    patch.append(
        {
            "op": "replace",
            "path": "/spec/volumes",
            "value": [
                *[
                    copy.deepcopy(volume)
                    for volume in volumes
                    if not (
                        isinstance(volume, dict)
                        and volume.get("name") in default_service_account_volumes
                    )
                ],
                {
                    "name": AGW_CA_VOLUME,
                    "configMap": {
                        "name": AGW_CA_CONFIG_MAP,
                        "items": [{"key": "ca.crt", "path": "ca.crt"}],
                    },
                },
            ],
        }
    )
    patch.append(
        {
            "op": "add",
            "path": f"/spec/initContainers/{prep_index + 1}",
            "value": link_init,
        }
    )
    return patch

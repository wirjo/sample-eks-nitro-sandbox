#!/usr/bin/env bash
# Build all sample images inside AWS CodeBuild and export digest-qualified ECR refs.
set -euo pipefail

die() {
  printf 'image build: %s\n' "$*" >&2
  exit 1
}

require_value() {
  local name="$1"
  [[ -n "${!name:-}" ]] || die "$name is required"
}

require_sha() {
  local name="$1"
  local value="${!name:-}"
  [[ "$value" =~ ^[0-9a-f]{40}$ ]] ||
    die "$name must be a full 40-character lowercase Git commit SHA"
}

require_value CODEBUILD_BUILD_ARN
require_value CODEBUILD_SRC_DIR
require_value AWS_ACCOUNT_ID
require_value AWS_DEFAULT_REGION
require_value SAMPLE_SOURCE_DIR
require_value OCE_REPOSITORY_URL
require_value ADAPTER_REPOSITORY
require_value CONTROLLER_REPOSITORY
require_value RUNTIME_REPOSITORY
require_value BUILD_OUTPUT_ENV
require_sha SAMPLE_GIT_REVISION
require_sha OCE_GIT_REVISION

[[ "$AWS_ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || die "AWS_ACCOUNT_ID must be 12 digits"
[[ "${TARGET_PLATFORM:-linux/amd64}" =~ ^linux/(amd64|arm64)$ ]] ||
  die "TARGET_PLATFORM must be linux/amd64 or linux/arm64"
[[ -d "$SAMPLE_SOURCE_DIR/.git" ]] || die "SAMPLE_SOURCE_DIR is not a Git checkout"

for command in aws docker git node python3 sha256sum; do
  command -v "$command" >/dev/null || die "$command is required"
done
docker buildx version >/dev/null || die "Docker Buildx is required"

SAMPLE_SOURCE_REVISION="$(git -C "$SAMPLE_SOURCE_DIR" rev-parse HEAD)"
[[ "$SAMPLE_SOURCE_REVISION" == "$SAMPLE_GIT_REVISION" ]] ||
  die "sample checkout resolved to $SAMPLE_SOURCE_REVISION, expected $SAMPLE_GIT_REVISION"

OCE_SOURCE_DIR="$CODEBUILD_SRC_DIR/oce-source"
git init "$OCE_SOURCE_DIR"
git -C "$OCE_SOURCE_DIR" remote add origin "$OCE_REPOSITORY_URL"
git -C "$OCE_SOURCE_DIR" fetch --depth 1 origin "$OCE_GIT_REVISION"
OCE_SOURCE_REVISION="$(git -C "$OCE_SOURCE_DIR" rev-parse FETCH_HEAD)"
[[ "$OCE_SOURCE_REVISION" == "$OCE_GIT_REVISION" ]] ||
  die "OCE checkout resolved to $OCE_SOURCE_REVISION, expected $OCE_GIT_REVISION"
git -C "$OCE_SOURCE_DIR" checkout --detach "$OCE_GIT_REVISION"

REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_DEFAULT_REGION}.amazonaws.com"
aws ecr get-login-password --region "$AWS_DEFAULT_REGION" |
  docker login --username AWS --password-stdin "$REGISTRY"
trap 'docker logout "$REGISTRY" >/dev/null 2>&1 || true' EXIT

build_identity="$(printf '%s' "$CODEBUILD_BUILD_ARN" | sha256sum | cut -c1-16)"
sample_tag="${SAMPLE_SOURCE_REVISION}-${build_identity}"
oce_tag="${OCE_SOURCE_REVISION}-${build_identity}"
metadata_dir="$CODEBUILD_SRC_DIR/image-metadata"
mkdir -p "$metadata_dir"

adapter_tagged="${REGISTRY}/${ADAPTER_REPOSITORY}:${sample_tag}"
controller_tagged="${REGISTRY}/${CONTROLLER_REPOSITORY}:${oce_tag}"
runtime_tagged="${REGISTRY}/${RUNTIME_REPOSITORY}:${oce_tag}"

docker buildx build \
  --pull \
  --push \
  --platform "${TARGET_PLATFORM:-linux/amd64}" \
  --metadata-file "$metadata_dir/adapter.json" \
  --label "org.opencontainers.image.revision=$SAMPLE_SOURCE_REVISION" \
  --tag "$adapter_tagged" \
  "$SAMPLE_SOURCE_DIR/examples/ai-agents/openclaw-enterprise/adapter"

node_base_image="$(
  node -e '
    const fs = require("node:fs");
    const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const value = data?.prepare?.defaultEnv?.NODE_BASE_IMAGE;
    if (typeof value !== "string" || !/@sha256:[0-9a-f]{64}$/.test(value)) {
      process.exit(1);
    }
    process.stdout.write(value);
  ' "$OCE_SOURCE_DIR/scripts/ci/test-suites/images-packaging.json"
)" || die "could not resolve OCE's pinned NODE_BASE_IMAGE"

docker buildx build \
  --pull \
  --push \
  --platform "${TARGET_PLATFORM:-linux/amd64}" \
  --target runtime \
  --metadata-file "$metadata_dir/controller.json" \
  --build-arg "NODE_BASE_IMAGE=$node_base_image" \
  --build-arg "OCC_BUILD_REVISION=$OCE_SOURCE_REVISION" \
  --label "org.opencontainers.image.revision=$OCE_SOURCE_REVISION" \
  --tag "$controller_tagged" \
  "$OCE_SOURCE_DIR"

mapfile -t openclaw_source_args < <(
  cd "$OCE_SOURCE_DIR"
  node scripts/lib/openclaw-source.mjs build-args
)
[[ "${#openclaw_source_args[@]}" -gt 0 ]] ||
  die "OCE returned no pinned OpenClaw source arguments"

runtime_build_args=()
for argument in "${openclaw_source_args[@]}"; do
  [[ "$argument" == *=* ]] || die "invalid OCE runtime build argument"
  runtime_build_args+=(--build-arg "$argument")
done

docker buildx build \
  --pull \
  --push \
  --platform "${TARGET_PLATFORM:-linux/amd64}" \
  --metadata-file "$metadata_dir/runtime.json" \
  "${runtime_build_args[@]}" \
  --build-arg "NODE_BASE_IMAGE=$node_base_image" \
  --build-arg "OCC_BUILD_REVISION=$OCE_SOURCE_REVISION" \
  --label "org.opencontainers.image.revision=$OCE_SOURCE_REVISION" \
  --file "$OCE_SOURCE_DIR/deploy/runtime/Dockerfile" \
  --tag "$runtime_tagged" \
  "$OCE_SOURCE_DIR"

read_digest() {
  python3 - "$1" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    digest = json.load(handle).get("containerimage.digest", "")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
    raise SystemExit(f"invalid image digest in {sys.argv[1]}: {digest!r}")
print(digest)
PY
}

adapter_digest="$(read_digest "$metadata_dir/adapter.json")"
controller_digest="$(read_digest "$metadata_dir/controller.json")"
runtime_digest="$(read_digest "$metadata_dir/runtime.json")"

verify_digest() {
  local repository="$1"
  local digest="$2"
  local _
  for _ in {1..10}; do
    if aws ecr describe-images \
      --region "$AWS_DEFAULT_REGION" \
      --repository-name "$repository" \
      --image-ids "imageDigest=$digest" \
      --query 'imageDetails[0].imageDigest' \
      --output text 2>/dev/null | grep -Fxq "$digest"; then
      return 0
    fi
    sleep 2
  done
  die "ECR did not return $repository@$digest after push"
}

verify_digest "$ADAPTER_REPOSITORY" "$adapter_digest"
verify_digest "$CONTROLLER_REPOSITORY" "$controller_digest"
verify_digest "$RUNTIME_REPOSITORY" "$runtime_digest"

ADAPTER_IMAGE="${REGISTRY}/${ADAPTER_REPOSITORY}@${adapter_digest}"
CONTROLLER_IMAGE="${REGISTRY}/${CONTROLLER_REPOSITORY}@${controller_digest}"
RUNTIME_IMAGE="${REGISTRY}/${RUNTIME_REPOSITORY}@${runtime_digest}"
export ADAPTER_IMAGE CONTROLLER_IMAGE RUNTIME_IMAGE
export SAMPLE_SOURCE_REVISION OCE_SOURCE_REVISION

{
  printf 'export ADAPTER_IMAGE=%q\n' "$ADAPTER_IMAGE"
  printf 'export CONTROLLER_IMAGE=%q\n' "$CONTROLLER_IMAGE"
  printf 'export RUNTIME_IMAGE=%q\n' "$RUNTIME_IMAGE"
  printf 'export SAMPLE_SOURCE_REVISION=%q\n' "$SAMPLE_SOURCE_REVISION"
  printf 'export OCE_SOURCE_REVISION=%q\n' "$OCE_SOURCE_REVISION"
} >"$BUILD_OUTPUT_ENV"

python3 - "$CODEBUILD_SRC_DIR/image-digests.json" <<'PY'
import json
import os
import sys

result = {
    "adapter": {
        "image": os.environ["ADAPTER_IMAGE"],
        "sourceRevision": os.environ["SAMPLE_SOURCE_REVISION"],
    },
    "controller": {
        "image": os.environ["CONTROLLER_IMAGE"],
        "sourceRevision": os.environ["OCE_SOURCE_REVISION"],
    },
    "runtime": {
        "image": os.environ["RUNTIME_IMAGE"],
        "sourceRevision": os.environ["OCE_SOURCE_REVISION"],
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(result, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

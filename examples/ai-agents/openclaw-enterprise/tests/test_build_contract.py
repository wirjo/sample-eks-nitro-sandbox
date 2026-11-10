"""Static contracts for the CodeBuild and ECR source-build path."""

from __future__ import annotations

import pathlib
import re
import subprocess
from typing import Any

import yaml

SAMPLE = pathlib.Path(__file__).resolve().parent.parent
BUILD = SAMPLE / "build"
TEMPLATE = BUILD / "template.yaml"
SCRIPT = BUILD / "build-images.sh"


class _CloudFormationLoader(yaml.SafeLoader):
    pass


def _construct_tagged(
    loader: _CloudFormationLoader, tag_suffix: str, node: yaml.Node
) -> Any:
    del tag_suffix
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    return loader.construct_mapping(node)


_CloudFormationLoader.add_multi_constructor("!", _construct_tagged)


def _template() -> dict[str, Any]:
    return yaml.load(
        TEMPLATE.read_text(encoding="utf-8"), Loader=_CloudFormationLoader
    )


def _resources(resource_type: str) -> list[dict[str, Any]]:
    return [
        resource
        for resource in _template()["Resources"].values()
        if resource["Type"] == resource_type
    ]


def _buildspec() -> str:
    project = _resources("AWS::CodeBuild::Project")
    assert len(project) == 1
    return project[0]["Properties"]["Source"]["BuildSpec"]


def test_template_creates_three_immutable_scan_on_push_repositories() -> None:
    repositories = _resources("AWS::ECR::Repository")

    assert len(repositories) == 3
    assert {
        repository["Properties"]["RepositoryName"] for repository in repositories
    } == {
        "${RepositoryPrefix}/adapter",
        "${RepositoryPrefix}/controller",
        "${RepositoryPrefix}/runtime",
    }
    for repository in repositories:
        properties = repository["Properties"]
        assert properties["ImageTagMutability"] == "IMMUTABLE"
        assert properties["ImageScanningConfiguration"] == {"ScanOnPush": True}
        assert properties["EncryptionConfiguration"] == {
            "EncryptionType": "KMS",
            "KmsKey": "ImageEncryptionKey.Arn",
        }


def test_codebuild_has_no_local_source_and_exports_digest_outputs() -> None:
    project = _resources("AWS::CodeBuild::Project")[0]["Properties"]
    buildspec = project["Source"]["BuildSpec"]

    assert project["Source"]["Type"] == "NO_SOURCE"
    assert project["Artifacts"]["Type"] == "NO_ARTIFACTS"
    assert project["Environment"]["PrivilegedMode"] is True
    assert project["Environment"]["ImagePullCredentialsType"] == "CODEBUILD"
    assert set(
        yaml.safe_load(buildspec)["env"]["exported-variables"]
    ) == {
        "ADAPTER_IMAGE",
        "CONTROLLER_IMAGE",
        "RUNTIME_IMAGE",
        "SAMPLE_SOURCE_REVISION",
        "OCE_SOURCE_REVISION",
    }
    assert "git -C \"$SAMPLE_SOURCE_DIR\" fetch --depth 1 origin" in buildspec
    assert (
        'test "$(git -C "$SAMPLE_SOURCE_DIR" rev-parse FETCH_HEAD)" '
        '= "$SAMPLE_GIT_REVISION"' in buildspec
    )
    assert "build/build-images.sh" in buildspec


def test_source_revisions_are_full_commit_shas() -> None:
    parameters = _template()["Parameters"]

    for name in ("SampleGitRevision", "OceGitRevision"):
        assert parameters[name]["AllowedPattern"] == "^[0-9a-f]{40}$"
    assert parameters["OceGitRevision"]["Default"] == (
        "c6541831756ae40d0485d16d8f0ffeab9851372d"
    )


def test_repository_encryption_key_rotates() -> None:
    keys = _resources("AWS::KMS::Key")

    assert len(keys) == 1
    assert keys[0]["Properties"]["EnableKeyRotation"] is True


def test_codebuild_role_is_scoped_to_logs_and_the_three_repositories() -> None:
    role = _resources("AWS::IAM::Role")[0]
    statements = role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    actions = {
        action
        for statement in statements
        for action in (
            statement["Action"]
            if isinstance(statement["Action"], list)
            else [statement["Action"]]
        )
    }

    assert actions == {
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
    }
    logs_statement = next(
        statement for statement in statements if statement["Sid"] == "WriteBuildLogs"
    )
    assert set(logs_statement["Resource"]) == {
        (
            "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:"
            "log-group:/aws/codebuild/openclaw-enterprise-images"
        ),
        (
            "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:"
            "log-group:/aws/codebuild/openclaw-enterprise-images:*"
        ),
    }
    push_statement = next(
        statement for statement in statements if statement["Sid"] == "PushAndVerifyImages"
    )
    assert set(push_statement["Resource"]) == {
        "AdapterRepository.Arn",
        "ControllerRepository.Arn",
        "RuntimeRepository.Arn",
    }
    token_statement = next(
        statement
        for statement in statements
        if statement["Sid"] == "GetEcrAuthorizationToken"
    )
    assert token_statement["Resource"] == "*"


def test_build_script_builds_each_image_from_the_expected_source() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    assert "require_value CODEBUILD_BUILD_ARN" in script
    assert "require_sha SAMPLE_GIT_REVISION" in script
    assert "require_sha OCE_GIT_REVISION" in script
    assert 'git -C "$OCE_SOURCE_DIR" fetch --depth 1 origin "$OCE_GIT_REVISION"' in script
    assert (
        '[[ "$OCE_SOURCE_REVISION" == "$OCE_GIT_REVISION" ]]'
        in script
    )
    assert (
        '"$SAMPLE_SOURCE_DIR/examples/ai-agents/openclaw-enterprise/adapter"'
        in script
    )
    assert "--target runtime" in script
    assert '--file "$OCE_SOURCE_DIR/deploy/runtime/Dockerfile"' in script
    assert "node scripts/lib/openclaw-source.mjs build-args" in script
    assert script.count("docker buildx build") == 3
    assert "docker pull" not in script
    assert "skopeo copy" not in script


def test_build_outputs_are_verified_digest_references() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert 'digest = json.load(handle).get("containerimage.digest", "")' in script
    assert 'aws ecr describe-images \\' in script
    for name in ("ADAPTER_IMAGE", "CONTROLLER_IMAGE", "RUNTIME_IMAGE"):
        assert re.search(
            rf'{name}="\$\{{REGISTRY\}}/\$\{{[A-Z_]+REPOSITORY\}}'
            r'@\$\{[a-z_]+digest\}"',
            script,
        )

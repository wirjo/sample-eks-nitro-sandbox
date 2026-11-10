# CodeBuild image path

This stack creates three private ECR repositories and one CodeBuild project. The
repositories use immutable tags, a customer managed KMS key, and scan every pushed image.
CodeBuild clones this sample and OpenClaw Enterprise (OCE) at full commit SHAs,
builds all three images from source, and exports digest-qualified image references.

The default OCE revision is
`c6541831756ae40d0485d16d8f0ffeab9851372d`. Set `SampleGitRevision` to the full
commit SHA containing the adapter and this build directory.

Create or update the build resources:

```bash
aws cloudformation deploy \
  --stack-name openclaw-enterprise-images \
  --template-file examples/ai-agents/openclaw-enterprise/build/template.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides SampleGitRevision="$(git rev-parse HEAD)"
```

Start the source build:

```bash
project_name="$(
  aws cloudformation describe-stacks \
    --stack-name openclaw-enterprise-images \
    --query 'Stacks[0].Outputs[?OutputKey==`ProjectName`].OutputValue' \
    --output text
)"
build_id="$(
  aws codebuild start-build \
    --project-name "$project_name" \
    --query 'build.id' \
    --output text
)"
aws codebuild batch-get-builds \
  --ids "$build_id" \
  --query 'builds[0].{status:buildStatus,images:exportedEnvironmentVariables}'
```

Wait for `status` to become `SUCCEEDED`. The exported `ADAPTER_IMAGE`,
`CONTROLLER_IMAGE`, and `RUNTIME_IMAGE` values use
`repository@sha256:<digest>` form. Use those immutable values in deployments,
not the temporary build tags.

The CodeBuild role can write only its logs and the three repositories. The
project accepts only public GitHub repository URLs and exact lowercase commit
SHAs; it has no source credential or local Docker path.

#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 3 ]; then
  echo "usage: $0 REGION WORKER_ECR_URL PROBE_ECR_URL" >&2
  exit 2
fi
region="$1"
worker_repo="$2"
probe_repo="$3"
registry="${worker_repo%%/*}"
if [ "${probe_repo%%/*}" != "$registry" ]; then
  echo "worker and probe repositories must be in the same ECR registry" >&2
  exit 2
fi
cd "$(dirname "$0")/.."
tag="$(date -u +%Y%m%d%H%M%S)"
aws ecr get-login-password --region "$region" | docker login --username AWS --password-stdin "$registry"
docker buildx build --platform linux/amd64 --push -t "${worker_repo}:${tag}" -f Dockerfile .
docker buildx build --platform linux/amd64 --push -t "${probe_repo}:${tag}" -f Dockerfile.testtask .
worker_digest="$(aws ecr describe-images --region "$region" --repository-name "${worker_repo#*/}" --image-ids "imageTag=${tag}" --query 'imageDetails[0].imageDigest' --output text)"
probe_digest="$(aws ecr describe-images --region "$region" --repository-name "${probe_repo#*/}" --image-ids "imageTag=${tag}" --query 'imageDetails[0].imageDigest' --output text)"
if [ "$worker_digest" = "None" ] || [ "$probe_digest" = "None" ]; then
  echo "ECR did not return both image digests" >&2
  exit 1
fi
printf 'worker_image_uri = "%s@%s"\n' "$worker_repo" "$worker_digest"
printf 'probe_image_uri = "%s@%s"\n' "$probe_repo" "$probe_digest"

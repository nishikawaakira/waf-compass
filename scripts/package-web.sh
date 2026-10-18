#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p infra/terraform/build
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
cp webfunction/index.js webfunction/package.json webfunction/package-lock.json "$work_dir/"
cp web/index.html web/terms.html web/privacy.html "$work_dir/"
(
  cd "$work_dir"
  npm ci --omit=dev --ignore-scripts --silent
  zip -X -q -r "$OLDPWD/infra/terraform/build/web.zip" index.js index.html terms.html privacy.html package.json package-lock.json node_modules
)

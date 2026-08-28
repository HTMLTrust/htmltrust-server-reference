#!/usr/bin/env bash
# Run the unit and conformance suites inside a disposable Node container.
# The repository is mounted read-only. The test copy and every dependency
# install live in the container, so a test run leaves the checkout unchanged.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${HTMLTRUST_TEST_IMAGE:-node:22-bookworm}"
CHECKOUT_ID="$(printf '%s' "$REPO_ROOT" | cksum | awk '{print $1}')"
CONTAINER_NAME="htmltrust-server-${CHECKOUT_ID}-$$"
CACHE_PREFIX="htmltrust-server-${CHECKOUT_ID}"

echo "Running HTMLTrust tests in ${IMAGE}"
exec docker run --rm --init --interactive \
  --name "${CONTAINER_NAME}" \
  --volume "${REPO_ROOT}:/repo:ro" \
  --volume "${CACHE_PREFIX}-npm:/root/.npm" \
  --volume "${CACHE_PREFIX}-mongodb:/var/cache/mongodb" \
  --env MONGOMS_DOWNLOAD_DIR=/var/cache/mongodb \
  "${IMAGE}" \
  bash -s <<'CONTAINER_SCRIPT'
set -euo pipefail

mkdir -p /workspace /var/cache/mongodb
# Keep all npm output and generated files in the disposable container. The
# source mount is read-only, which also catches accidental checkout writes.
tar --exclude=.git --exclude=node_modules -cf - -C /repo . | tar -xf - -C /workspace
cd /workspace

npm ci --ignore-scripts --no-audit --no-fund
npm --prefix conformance/runner ci --ignore-scripts --no-audit --no-fund

echo "== npm test =="
npm test

echo "== npm run openapi:lint =="
npm run openapi:lint

echo "== npm run conformance =="
npm run conformance
CONTAINER_SCRIPT

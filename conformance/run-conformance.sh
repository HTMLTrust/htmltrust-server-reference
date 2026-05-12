#!/usr/bin/env bash
# Convenience script: start a Mongo container, start the Node reference
# server, run the conformance suite against it, and tear everything
# down. Idempotent — safe to re-run.
#
# Requirements: docker, node 18+, npm.
#
# Usage:
#   ./run-conformance.sh                 # full lifecycle
#   ./run-conformance.sh --keep-running  # leave server + mongo running on exit

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFORMANCE_DIR="$REPO_ROOT/conformance"
MONGO_CONTAINER="${MONGO_CONTAINER:-htmltrust-conformance-mongo}"
MONGO_PORT="${MONGO_PORT:-37017}"
SERVER_PORT="${SERVER_PORT:-3000}"
GENERAL_API_KEY="${GENERAL_API_KEY:-conformance_general_key}"
ADMIN_API_KEY="${ADMIN_API_KEY:-conformance_admin_key}"
KEEP_RUNNING=0

for arg in "$@"; do
  case "$arg" in
    --keep-running) KEEP_RUNNING=1 ;;
  esac
done

server_pid=""

cleanup() {
  if [[ "$KEEP_RUNNING" == "1" ]]; then
    echo "--keep-running set; leaving server (pid $server_pid) and mongo ($MONGO_CONTAINER) up"
    return
  fi
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    echo "stopping reference server (pid $server_pid)"
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if docker ps --format '{{.Names}}' | grep -qx "$MONGO_CONTAINER"; then
    echo "stopping mongo container $MONGO_CONTAINER"
    docker rm -f "$MONGO_CONTAINER" >/dev/null
  fi
}
trap cleanup EXIT INT TERM

# ---- 1. Start MongoDB ------------------------------------------------------
if docker ps -a --format '{{.Names}}' | grep -qx "$MONGO_CONTAINER"; then
  echo "removing stale mongo container $MONGO_CONTAINER"
  docker rm -f "$MONGO_CONTAINER" >/dev/null
fi
echo "starting mongo on localhost:$MONGO_PORT (container: $MONGO_CONTAINER)"
docker run -d --rm \
  --name "$MONGO_CONTAINER" \
  -p "$MONGO_PORT:27017" \
  mongo:7 >/dev/null

# Wait for mongo to accept connections.
echo -n "waiting for mongo"
for i in $(seq 1 30); do
  if docker exec "$MONGO_CONTAINER" mongosh --quiet --eval "db.adminCommand('ping').ok" >/dev/null 2>&1; then
    echo " — ready"
    break
  fi
  echo -n "."
  sleep 1
  if [[ "$i" == "30" ]]; then
    echo
    echo "ERROR: mongo did not become ready in 30s" >&2
    exit 1
  fi
done

# ---- 2. Install + start the Node reference server -------------------------
cd "$REPO_ROOT"
if [[ ! -d node_modules ]]; then
  echo "installing reference server deps"
  npm install --no-audit --no-fund --silent
fi

echo "starting reference server on port $SERVER_PORT"
MONGO_URI="mongodb://localhost:$MONGO_PORT/htmltrust-conformance" \
  PORT="$SERVER_PORT" \
  GENERAL_API_KEY="$GENERAL_API_KEY" \
  ADMIN_API_KEY="$ADMIN_API_KEY" \
  NODE_ENV="test" \
  node src/server.js > "$CONFORMANCE_DIR/.server.log" 2>&1 &
server_pid=$!

# Wait for the server to start responding.
echo -n "waiting for server"
for i in $(seq 1 30); do
  if curl -sf -o /dev/null "http://localhost:$SERVER_PORT/api/claims"; then
    echo " — ready"
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo
    echo "ERROR: server exited; last 50 lines of log:" >&2
    tail -n 50 "$CONFORMANCE_DIR/.server.log" >&2
    exit 1
  fi
  echo -n "."
  sleep 1
  if [[ "$i" == "30" ]]; then
    echo
    echo "ERROR: server did not become ready in 30s" >&2
    tail -n 50 "$CONFORMANCE_DIR/.server.log" >&2
    exit 1
  fi
done

# ---- 3. Install runner deps and execute -----------------------------------
cd "$CONFORMANCE_DIR/runner"
if [[ ! -d node_modules ]]; then
  echo "installing conformance runner deps"
  npm install --no-audit --no-fund --silent
fi

cd "$REPO_ROOT"
echo
node "$CONFORMANCE_DIR/runner/run.mjs" \
  --target-url "http://localhost:$SERVER_PORT" \
  --base-path /api \
  --general-api-key "$GENERAL_API_KEY" \
  --admin-api-key "$ADMIN_API_KEY" \
  --accept-mongo-ids \
  "$@"

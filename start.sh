#!/usr/bin/env bash
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Starting PostgreSQL..."
cd "$ROOT_DIR"
docker compose up -d

echo "Starting API..."
cd "$ROOT_DIR/api"
npm install >/dev/null 2>&1 || true
nohup bash -c 'while true; do npm run dev; sleep 1; done' > "$ROOT_DIR/api.log" 2>&1 &

echo "Starting Web..."
cd "$ROOT_DIR/web"
npm install >/dev/null 2>&1 || true
nohup bash -c 'while true; do npm run dev -- --host 0.0.0.0; sleep 1; done' > "$ROOT_DIR/web.log" 2>&1 &

echo "Done."
echo "API health: http://localhost:3001/health"
echo "Web: http://localhost:5100"
echo "Logs: $ROOT_DIR/api.log and $ROOT_DIR/web.log"
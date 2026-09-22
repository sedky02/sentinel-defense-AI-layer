#!/usr/bin/env bash
# One-command demo: starts the live dashboard, waits for it, runs the scenario
# script against it, and opens the browser. Ctrl+C stops the dashboard too.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PAUSE="${1:-2}"
PORT=3000
URL="http://localhost:${PORT}"

if [ ! -d dashboard/node_modules ]; then
  echo "Installing dashboard dependencies..."
  (cd dashboard && npm install)
fi

echo "Starting live dashboard on ${URL} ..."
(cd dashboard && npm run dev -- --port "${PORT}") &
DASHBOARD_PID=$!
trap 'kill "${DASHBOARD_PID}" 2>/dev/null || true' EXIT

echo "Waiting for dashboard to come up..."
for _ in $(seq 1 60); do
  if curl -s -o /dev/null "${URL}"; then
    break
  fi
  sleep 0.5
done

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "${URL}" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "${URL}" >/dev/null 2>&1 || true
else
  echo "Open ${URL} in your browser to watch the live trace."
fi

echo "Running demo scenarios (pause=${PAUSE}s between decisions)..."
python -m sentinel_soc_defense.demo --pause "${PAUSE}"

echo
echo "Demo finished. Dashboard is still running at ${URL} -- press Ctrl+C to stop it."
wait "${DASHBOARD_PID}"

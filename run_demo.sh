#!/usr/bin/env bash
# One-command SOC scenario run: starts the adapter and live dashboard, runs all
# public SOC scenarios, and opens the browser. Ctrl+C stops both services.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PORT=3000
URL="http://localhost:${PORT}"
ADAPTER_PORT=8080
SCENARIO_DIR="${SCENARIO_DIR:-/tmp/sentinel_starter_kit/scenarios/public/soc}"
TRACE_PATH="${TRACE_PATH:-results/soc_trace.jsonl}"
RESULTS_PATH="${RESULTS_PATH:-results/scenario_results.csv}"

if [[ "${TRACE_PATH}" != /* ]]; then
  TRACE_PATH="$(pwd)/${TRACE_PATH}"
fi

if [ ! -d "${SCENARIO_DIR}" ]; then
  echo "Scenario directory not found: ${SCENARIO_DIR}" >&2
  exit 1
fi

rm -f "${TRACE_PATH}"

if [ ! -d dashboard/node_modules ]; then
  echo "Installing dashboard dependencies..."
  (cd dashboard && npm install)
fi

echo "Starting SENTINEL adapter on http://127.0.0.1:${ADAPTER_PORT} ..."
python -m sentinel_soc_defense.adapter --port "${ADAPTER_PORT}" --trace "${TRACE_PATH}" &
ADAPTER_PID=$!

echo "Starting live dashboard on ${URL} ..."
(cd dashboard && TRACE_PATH="${TRACE_PATH}" npm run dev -- --port "${PORT}") &
DASHBOARD_PID=$!
trap 'kill "${DASHBOARD_PID}" "${ADAPTER_PID}" 2>/dev/null || true' EXIT

echo "Waiting for dashboard to come up..."
for _ in $(seq 1 60); do
  if curl -s -o /dev/null "${URL}"; then
    break
  fi
  sleep 0.5
done

echo "Waiting for adapter to come up..."
for _ in $(seq 1 60); do
  if curl -s -o /dev/null "http://127.0.0.1:${ADAPTER_PORT}/healthz"; then
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

echo "Running all public SOC scenarios..."
python -m sentinel_soc_defense.batch_runner \
  "${SCENARIO_DIR}" \
  --defense-url "http://127.0.0.1:${ADAPTER_PORT}" \
  --trace "${TRACE_PATH}" \
  --results "${RESULTS_PATH}"

echo
echo "Scenario run finished. Dashboard is still running at ${URL} -- press Ctrl+C to stop it."
wait "${DASHBOARD_PID}"

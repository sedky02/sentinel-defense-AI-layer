#!/usr/bin/env bash
# One-command SOC demo run: starts the adapter and live dashboard, opens the
# browser, and populates the trace. If the official SENTINEL starter-kit
# scenario library is available locally (SCENARIO_DIR), it runs the full
# public SOC scenario batch against the adapter; otherwise it falls back to
# the repo's own bundled demo scenarios (sentinel_soc_defense.demo), which
# need no external checkout. Ctrl+C stops both services.
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

USE_SCENARIO_BATCH=1
if [ ! -d "${SCENARIO_DIR}" ]; then
  USE_SCENARIO_BATCH=0
  echo "Scenario directory not found: ${SCENARIO_DIR}" >&2
  echo "Falling back to the bundled demo scenarios (sentinel_soc_defense.demo)." >&2
  echo "Set SCENARIO_DIR to a local checkout of the SENTINEL starter-kit scenarios to run the full public SOC batch instead." >&2
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
(cd dashboard && TRACE_PATH="${TRACE_PATH}" ADAPTER_URL="http://127.0.0.1:${ADAPTER_PORT}" npm run dev -- --port "${PORT}") &
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

if [ "${USE_SCENARIO_BATCH}" -eq 1 ]; then
  echo "Running all public SOC scenarios..."
  python -m sentinel_soc_defense.batch_runner \
    "${SCENARIO_DIR}" \
    --defense-url "http://127.0.0.1:${ADAPTER_PORT}" \
    --trace "${TRACE_PATH}" \
    --results "${RESULTS_PATH}"
else
  echo "Running bundled demo scenarios (no external scenario library required)..."
  python -m sentinel_soc_defense.demo --trace "${TRACE_PATH}"
fi

echo
echo "Scenario run finished. Dashboard is still running at ${URL} -- press Ctrl+C to stop it."
wait "${DASHBOARD_PID}"

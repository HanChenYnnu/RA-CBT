#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON:-python}"
PORT="${GATEWAY_PORT:-8000}"
RESULTS_DIR="${RESULTS_DIR:-results}"
BENIGN_N="${BENIGN_N:-50}"
EXPERIMENT_REQUESTS="${EXPERIMENT_REQUESTS:-30}"
LOGS_FILE="${LOGS_FILE:-gateway/logs/requests.jsonl}"
CALIBRATION_FILE="${CALIBRATION_FILE:-results/calibration.json}"

mkdir -p gateway/logs

cleanup() {
  if [[ -n "${GATEWAY_PID:-}" ]] && kill -0 "${GATEWAY_PID}" 2>/dev/null; then
    kill "${GATEWAY_PID}" >/dev/null 2>&1 || true
    wait "${GATEWAY_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

rm -f "${LOGS_FILE}"

echo "[1/6] starting gateway in background"
if "${PYTHON_BIN}" -c "import uvicorn" >/dev/null 2>&1; then
  "${PYTHON_BIN}" -m uvicorn gateway.app:app --host 127.0.0.1 --port "${PORT}" >/tmp/ra_cbt_gateway.log 2>&1 &
  GATEWAY_PID=$!

  GATEWAY_PORT="${PORT}" "${PYTHON_BIN}" - <<'PY'
import os
import time
import urllib.request

url = f"http://127.0.0.1:{os.environ['GATEWAY_PORT']}/health"
for _ in range(80):
    try:
        with urllib.request.urlopen(url, timeout=0.5) as r:
            if r.status == 200:
                break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit("gateway did not become healthy in time")
PY
else
  echo "warning: uvicorn is not available; skipping live gateway bootstrap"
fi

echo "[2/6] generating benign traffic"
"${PYTHON_BIN}" scripts/gen_traffic_benign.py --n "${BENIGN_N}"

echo "[3/6] calibrating thresholds"
"${PYTHON_BIN}" scripts/calibrate_quantiles.py --input "${LOGS_FILE}" --output "${CALIBRATION_FILE}" --alpha 0.01 --beta 0.05

echo "[4/6] running all baselines x scenarios"
"${PYTHON_BIN}" -m experiments.runner --all --requests "${EXPERIMENT_REQUESTS}" --output "${RESULTS_DIR}"

echo "[5/6] reports + plots available in ${RESULTS_DIR}/"

test -f "${RESULTS_DIR}/report.csv"
test -f "${RESULTS_DIR}/report.md"
test -f "${RESULTS_DIR}/plots/attack_success_rate.svg"
test -f "${RESULTS_DIR}/plots/cost_leakage_tokens.svg"
test -f "${RESULTS_DIR}/plots/throttle_rate.svg"

echo "[6/6] stopping gateway"
cleanup
trap - EXIT

echo "done: generated ${RESULTS_DIR}/report.csv, ${RESULTS_DIR}/report.md and plots"

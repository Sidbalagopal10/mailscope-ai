#!/usr/bin/env bash

set -e

PORT="${PORT:-8501}"

echo "Starting MailScope AI"
echo "Public Streamlit port: $PORT"
echo "Internal FastAPI port: 8000"

python -m uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --log-level info &

FASTAPI_PID=$!

cleanup() {
    echo "Stopping MailScope AI services..."
    kill "$FASTAPI_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

echo "Waiting for FastAPI..."

python - <<'PY'
import time
import urllib.request

url = "http://127.0.0.1:8000/health"

for attempt in range(60):
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            if response.status == 200:
                print("FastAPI is ready.")
                break
    except Exception:
        pass

    time.sleep(1)
else:
    raise SystemExit("FastAPI failed to start.")
PY

echo "Starting MailScope AI dashboard..."

python -m streamlit run dashboard/dashboard.py \
    --server.address 0.0.0.0 \
    --server.port "$PORT" \
    --server.headless true \
    --browser.gatherUsageStats false

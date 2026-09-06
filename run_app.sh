#!/bin/zsh

set -u

PROJECT_DIR="$HOME/ai-mail-phishing-detector"
LOG_DIR="$PROJECT_DIR/logs"
PID_DIR="$PROJECT_DIR/.pids"

FASTAPI_LOG="$LOG_DIR/fastapi.log"
STREAMLIT_LOG="$LOG_DIR/streamlit.log"

FASTAPI_PID_FILE="$PID_DIR/fastapi.pid"
STREAMLIT_PID_FILE="$PID_DIR/streamlit.pid"

cd "$PROJECT_DIR" || exit 1

mkdir -p "$LOG_DIR" "$PID_DIR"

if [[ -f ".venv/bin/activate" ]]; then
    source .venv/bin/activate
else
    echo "❌ Virtual environment not found at .venv"
    exit 1
fi

stop_existing_process() {
    local pid_file="$1"
    local service_name="$2"

    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(cat "$pid_file")"

        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping existing $service_name process: $pid"
            kill "$pid" 2>/dev/null || true

            for _ in {1..10}; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    break
                fi

                sleep 0.5
            done

            if kill -0 "$pid" 2>/dev/null; then
                kill -9 "$pid" 2>/dev/null || true
            fi
        fi

        rm -f "$pid_file"
    fi
}

wait_for_url() {
    local url="$1"
    local service_name="$2"
    local log_file="$3"

    for _ in {1..40}; do
        if curl -fsS "$url" >/dev/null 2>&1; then
            echo "✅ $service_name is ready"
            return 0
        fi

        sleep 0.5
    done

    echo "❌ $service_name failed to start"
    echo ""
    echo "Last 50 log lines:"
    tail -50 "$log_file"
    return 1
}

echo "Stopping old project processes..."

stop_existing_process \
    "$FASTAPI_PID_FILE" \
    "FastAPI"

stop_existing_process \
    "$STREAMLIT_PID_FILE" \
    "Streamlit"

pkill -f \
    "uvicorn app.main:app.*--port 8000" \
    2>/dev/null || true

pkill -f \
    "streamlit run dashboard/dashboard.py" \
    2>/dev/null || true

sleep 1

echo ""
echo "Checking FastAPI imports..."

python - <<'PY'
from app.main import app

required = "/email-security-pipeline/analyze"

if required not in app.openapi()["paths"]:
    raise SystemExit(
        f"Required route is missing: {required}"
    )

print("✅ Application imports successfully")
print("✅ Unified email pipeline route is registered")
PY

echo ""
echo "Starting FastAPI..."

nohup python -m uvicorn app.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --log-level info \
    > "$FASTAPI_LOG" 2>&1 &

FASTAPI_PID=$!
echo "$FASTAPI_PID" > "$FASTAPI_PID_FILE"

if ! wait_for_url \
    "http://127.0.0.1:8000/openapi.json" \
    "FastAPI" \
    "$FASTAPI_LOG"
then
    exit 1
fi

echo ""
echo "Starting Streamlit..."

nohup python -m streamlit run \
    dashboard/dashboard.py \
    --server.address 127.0.0.1 \
    --server.port 8501 \
    --server.headless true \
    > "$STREAMLIT_LOG" 2>&1 &

STREAMLIT_PID=$!
echo "$STREAMLIT_PID" > "$STREAMLIT_PID_FILE"

if ! wait_for_url \
    "http://127.0.0.1:8501" \
    "Streamlit" \
    "$STREAMLIT_LOG"
then
    kill "$FASTAPI_PID" 2>/dev/null || true
    exit 1
fi

echo ""
open "http://127.0.0.1:8501"

echo "=================================================="
echo "MAILSCOPE AI IS RUNNING"
echo "=================================================="
echo ""
echo "Dashboard:"
echo "  http://127.0.0.1:8501"
echo ""
echo "FastAPI:"
echo "  http://127.0.0.1:8000"
echo ""
echo "API documentation:"
echo "  http://127.0.0.1:8000/docs"
echo ""
echo "FastAPI PID:   $FASTAPI_PID"
echo "Streamlit PID: $STREAMLIT_PID"
echo ""
echo "Logs:"
echo "  $FASTAPI_LOG"
echo "  $STREAMLIT_LOG"
echo ""
echo "Run ./stop_app.sh to stop both services."
echo "Run ./status_app.sh to check their status."

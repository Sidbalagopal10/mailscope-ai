#!/bin/zsh

PROJECT_DIR="$HOME/ai-mail-phishing-detector"
PID_DIR="$PROJECT_DIR/.pids"

stop_service() {
    local name="$1"
    local pid_file="$2"

    if [[ ! -f "$pid_file" ]]; then
        echo "$name: no PID file found"
        return
    fi

    local pid
    pid="$(cat "$pid_file")"

    if kill -0 "$pid" 2>/dev/null; then
        echo "Stopping $name: $pid"
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

        echo "✅ $name stopped"
    else
        echo "$name was not running"
    fi

    rm -f "$pid_file"
}

stop_service \
    "FastAPI" \
    "$PID_DIR/fastapi.pid"

stop_service \
    "Streamlit" \
    "$PID_DIR/streamlit.pid"

pkill -f \
    "uvicorn app.main:app.*--port 8000" \
    2>/dev/null || true

pkill -f \
    "streamlit run dashboard/dashboard.py" \
    2>/dev/null || true

echo "✅ Application stopped"

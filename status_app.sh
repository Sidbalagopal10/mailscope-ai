#!/bin/zsh

PROJECT_DIR="$HOME/ai-mail-phishing-detector"
PID_DIR="$PROJECT_DIR/.pids"

check_service() {
    local name="$1"
    local pid_file="$2"
    local url="$3"

    if [[ -f "$pid_file" ]]; then
        local pid
        pid="$(cat "$pid_file")"

        if kill -0 "$pid" 2>/dev/null; then
            if curl -fsS "$url" >/dev/null 2>&1; then
                echo "✅ $name running — PID $pid — $url"
            else
                echo "⚠️  $name process exists but URL is unavailable — PID $pid"
            fi

            return
        fi
    fi

    echo "❌ $name is not running"
}

check_service \
    "FastAPI" \
    "$PID_DIR/fastapi.pid" \
    "http://127.0.0.1:8000/openapi.json"

check_service \
    "Streamlit" \
    "$PID_DIR/streamlit.pid" \
    "http://127.0.0.1:8501"

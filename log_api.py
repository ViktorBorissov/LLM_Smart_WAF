#!/usr/bin/env python3
"""
Log API — runs on WAF VM
Exposes recent ModSecurity audit log lines over HTTP.
Endpoint: GET /logs?lines=150
Auth: X-API-Key header
"""

from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# --- Config ---
LOG_FILE = "/var/log/modsec_audit.log"
API_KEY = "" #PLACE YOUR AUTH KEY STRING
DEFAULT_LINES = 150
MAX_LINES = 500

# --- Auth check ---
def is_authorized():
    return request.headers.get("X-API-Key") == API_KEY

# --- Read last N lines from log file efficiently ---
def tail(filepath, n):
    if not os.path.exists(filepath):
        return []
    with open(filepath, "rb") as f:
        # Seek from end to avoid reading entire file into memory
        f.seek(0, 2)
        file_size = f.tell()
        block_size = 4096
        data = b""
        position = file_size
        lines_found = 0

        while position > 0 and lines_found < n + 1:
            read_size = min(block_size, position)
            position -= read_size
            f.seek(position)
            chunk = f.read(read_size)
            data = chunk + data
            lines_found = data.count(b"\n")

        lines = data.decode("utf-8", errors="replace").splitlines()
        return lines[-n:] if len(lines) >= n else lines

# --- Routes ---
@app.route("/logs", methods=["GET"])
def get_logs():
    if not is_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        n = int(request.args.get("lines", DEFAULT_LINES))
        n = min(n, MAX_LINES)  # Cap at MAX_LINES
    except ValueError:
        return jsonify({"error": "Invalid 'lines' parameter"}), 400

    lines = tail(LOG_FILE, n)

    return jsonify({
        "log_file": LOG_FILE,
        "lines_returned": len(lines),
        "logs": lines
    })

@app.route("/health", methods=["GET"])
def health():
    exists = os.path.exists(LOG_FILE)
    return jsonify({
        "status": "ok",
        "log_file_accessible": exists
    })

if __name__ == "__main__":
    # Bind only to the private network interface, not 0.0.0.0
    app.run(host="192.168.32.15", port=5001)  # <-- Replace WAF_IP with actual IP

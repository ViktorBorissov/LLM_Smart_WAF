#!/usr/bin/env python3
"""
Log API — runs on WAF VM
Serves last N lines of ModSecurity log, stripped of noisy content.
"""
from urllib.parse import unquote
from flask import Flask, request, jsonify
import os
import re

app = Flask(__name__)

LOG_FILE = "/var/log/modsec_audit.log"
API_KEY = "vborisov123"
DEFAULT_LINES = 30

def is_authorized():
    return request.headers.get("X-API-Key") == API_KEY

def get_clean_lines(filepath, n):
    if not os.path.exists(filepath):
        return []

    # Read last N lines efficiently
    with open(filepath, "rb") as f:
        f.seek(0, 2)
        block, data = 4096, b""
        pos = f.tell()
        while pos > 0 and data.count(b"\n") < n + 1:
            read = min(block, pos)
            pos -= read
            f.seek(pos)
            data = f.read(read) + data
        lines = data.decode("utf-8", errors="replace").splitlines()[-n:]

    clean = []
    for line in lines:
        # Skip lines that are just noise
        if any(skip in line for skip in [
            "Cookie:", "User-Agent:", "Accept:", "Authorization:",
            "token=", "ETag:", "If-None-Match", "---", "Connection:",
            "Upgrade-Insecure", "Accept-Encoding", "Accept-Language",
            "Feature-Policy", "X-Frame", "X-Content", "X-Recruiting"
        ]):
            continue

        # Shorten URL-encoded URIs
        line = unquote(line)

        # Truncate very long lines
        if len(line) > 1000:
            line = line[:1000] + "..."

        line = line.strip()
        if line:
            clean.append(line)

    return clean

@app.route("/logs", methods=["GET"])
def get_logs():
    if not is_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    lines = get_clean_lines(LOG_FILE, DEFAULT_LINES)
    return jsonify({
        "lines_returned": len(lines),
        "logs": "\n".join(lines)
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "log_file_accessible": os.path.exists(LOG_FILE)})

if __name__ == "__main__":
    app.run(host="192.168.32.WAF_IP", port=5001)  # <-- Replace WAF_IP

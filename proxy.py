#!/usr/bin/env python3
"""
Prompt Enrichment Proxy — runs on LLM VM
Fetches WAF logs, injects into prompt, forwards to Ollama.
Users call :11435 instead of Ollama's :11434.
"""

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
LOG_API_URL = "http://192.168.64.15:5001/logs"  # <-- Replace WAF_IP
LOG_API_KEY = "vborisov123"          # Must match log_api.py

def fetch_logs():
    try:
        resp = requests.get(
            LOG_API_URL,
            headers={"X-API-Key": LOG_API_KEY},
            timeout=5
        )
        if resp.status_code == 200:
            return resp.json().get("logs", "")
    except Exception as e:
        print(f"[WARN] Could not fetch logs: {e}")
    return None  # Fail open — proxy still works without logs

def build_prompt(user_prompt, logs):
    if not logs:
        return user_prompt  # No logs — just pass prompt through unchanged

    return (
        "You are a security analyst assistant. "
        "Use the WAF log entries below to answer the user's question. "
        "If the answer is not in the logs, say so.\n\n"
        "--- WAF LOGS ---\n"
        f"{logs}\n"
        "--- END LOGS ---\n\n"
        f"Question: {user_prompt}"
    )

@app.route("/api/generate", methods=["POST"])
def proxy_generate():
    body = request.get_json()
    if not body or "prompt" not in body:
        return jsonify({"error": "Missing 'prompt' in request body"}), 400

    logs = fetch_logs()
    enriched = build_prompt(body["prompt"], logs)

    try:
        resp = requests.post(OLLAMA_URL, json={**body, "prompt": enriched}, timeout=120)
        return (resp.content, resp.status_code, {"Content-Type": "application/json"})
    except Exception as e:
        return jsonify({"error": f"Ollama unreachable: {e}"}), 502

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=11435)

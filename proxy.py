#!/usr/bin/env python3
"""
Prompt Enrichment Proxy — runs on LLM VM
Drop-in replacement for Ollama's /api/generate endpoint.
Fetches WAF logs, injects them into the prompt, forwards to Ollama.

Users call this on :11435 instead of Ollama on :11434.
"""

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# --- Config ---
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
LOG_API_URL = "http://192.168.32.15:5001/logs"  # <-- Replace WAF_IP with actual IP
LOG_API_KEY = "vborisov123"      
LOG_LINES = 100
LOG_FETCH_TIMEOUT = 5  # seconds — fail fast if WAF VM unreachable

# --- Fetch logs from WAF VM ---
def fetch_logs():
    try:
        resp = requests.get(
            LOG_API_URL,
            headers={"X-API-Key": LOG_API_KEY},
            params={"lines": LOG_LINES},
            timeout=LOG_FETCH_TIMEOUT
        )
        if resp.status_code == 200:
            data = resp.json()
            return "\n".join(data.get("logs", []))
        else:
            print(f"[WARN] Log API returned {resp.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[WARN] Could not reach Log API: {e}")
        return None  # Fail open — still answer without logs

# --- Build enriched prompt ---
def build_prompt(original_prompt, log_content):
    if not log_content:
        # No logs available — answer without context, note it to the model
        return (
            "You are a security analyst assistant. "
            "WAF log data is currently unavailable. "
            "Answer the following question as best you can without log context.\n\n"
            f"User question: {original_prompt}"
        )

    return (
        "You are a security analyst assistant. "
        "Below are recent ModSecurity WAF audit log entries. "
        "Use them to answer the user's question if relevant. "
        "If the answer is not found in the logs, say so clearly — do not guess.\n\n"
        "--- WAF LOGS (recent entries) ---\n"
        f"{log_content}\n"
        "--- END OF WAF LOGS ---\n\n"
        f"User question: {original_prompt}"
    )

# --- Proxy endpoint ---
@app.route("/api/generate", methods=["POST"])
def proxy_generate():
    body = request.get_json()
    if not body or "prompt" not in body:
        return jsonify({"error": "Missing 'prompt' in request body"}), 400

    original_prompt = body["prompt"]

    # Fetch logs and enrich prompt
    log_content = fetch_logs()
    enriched_prompt = build_prompt(original_prompt, log_content)

    # Forward to Ollama with enriched prompt
    ollama_body = {**body, "prompt": enriched_prompt}

    try:
        ollama_resp = requests.post(
            OLLAMA_URL,
            json=ollama_body,
            timeout=120  # LLM inference can be slow
        )
        return (ollama_resp.content, ollama_resp.status_code, {"Content-Type": "application/json"})
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Ollama unreachable: {e}"}), 502

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "proxy": "running"})

if __name__ == "__main__":
    # Listen on localhost only — expose via firewall rules as needed
    app.run(host="127.0.0.1", port=11435)

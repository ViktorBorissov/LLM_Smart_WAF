# LLM_Smart_WAF
Python FlaskAPI Service &amp; API LogCaller for Ollama LLM
#For proxy.py
Prompt Enrichment Proxy — runs on LLM VM
Drop-in replacement for Ollama's /api/generate endpoint.
Fetches WAF logs, injects them into the prompt, forwards to Ollama.

Users call this on :11435 instead of Ollama on :11434.
#For WAF Modsec Log
Log API — runs on WAF VM
Exposes recent ModSecurity audit log lines over HTTP.
Endpoint: GET /logs?lines=150
Auth: X-API-Key header
API key needs to Match on both ends

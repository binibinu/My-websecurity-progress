"""
Nano WAF — small reverse-proxy Web Application Firewall for local dev/demo use.

Sits in front of a Flask (or any HTTP) app, inspects incoming requests for
common attack patterns, rate-limits by IP, and forwards clean traffic on.

NOT a replacement for a real WAF (ModSecurity, Cloudflare, AWS WAF, etc.) —
use this for learning / local testing, not production perimeter defense.
"""

import logging
import os
import threading
import time
from collections import defaultdict
from urllib.parse import unquote

import re
import requests
from flask import Flask, request, Response

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Config (override via environment variables)
# ---------------------------------------------------------------------------
UPSTREAM_APP = os.environ.get("WAF_UPSTREAM", "http://127.0.0.1:5000")
LISTEN_HOST = os.environ.get("WAF_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("WAF_PORT", "8080"))

RATE_LIMIT = int(os.environ.get("WAF_RATE_LIMIT", "30"))       # requests
RATE_WINDOW = int(os.environ.get("WAF_RATE_WINDOW", "60"))     # seconds

MAX_BODY_BYTES = int(os.environ.get("WAF_MAX_BODY", str(1 * 1024 * 1024)))  # 1 MB
UPSTREAM_TIMEOUT = float(os.environ.get("WAF_UPSTREAM_TIMEOUT", "10"))      # seconds

# Trust X-Forwarded-For only if the WAF is itself behind a trusted proxy/LB.
# Leave False for a direct-facing demo setup.
TRUST_X_FORWARDED_FOR = os.environ.get("WAF_TRUST_XFF", "false").lower() == "true"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("nano_waf")

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------
# Each rule: (id, compiled pattern). Patterns run against the URL, decoded
# query string, decoded body, and header values.
RULES = [
    ("SQLI-001", re.compile(
        r"(?i)(union\s+select|select\s+.*\s+from|or\s+1\s*=\s*1|'\s*or\s*'|"
        r"drop\s+table|insert\s+into|update\s+.*\s+set|--\s|/\*.*\*/|;\s*--)"
    )),
    ("XSS-001", re.compile(
        r"(?i)(<script[^>]*>|javascript:|on(error|load|click|mouseover)\s*=|"
        r"<iframe|<svg[^>]*onload|document\.cookie)"
    )),
    ("PATH-001", re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE)),
    ("CMD-001", re.compile(
        r"(?i)([;&|`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b|\$\(.*\)|`.*`)"
    )),
    ("SSRF-001", re.compile(
        r"(?i)(file://|gopher://|dict://|169\.254\.169\.254|metadata\.google\.internal)"
    )),
    ("LOG4J-001", re.compile(r"(?i)\$\{jndi:")),
]

# Headers we actually want to scan; scanning everything (e.g. cookies with
# session tokens) is noisy and can leak sensitive data into logs on a hit.
SCANNED_HEADERS = {"user-agent", "referer", "x-forwarded-for", "cookie"}

# ---------------------------------------------------------------------------
# Rate limiting (thread-safe, self-cleaning)
# ---------------------------------------------------------------------------
_rate_lock = threading.Lock()
request_counts = defaultdict(list)
_last_cleanup = time.time()
_CLEANUP_INTERVAL = 300  # sweep stale IPs every 5 min


def _cleanup_stale_ips(now):
    stale = [ip for ip, times in request_counts.items() if not times or now - times[-1] > RATE_WINDOW]
    for ip in stale:
        del request_counts[ip]


def rate_limited(ip):
    now = time.time()
    global _last_cleanup

    with _rate_lock:
        request_counts[ip] = [t for t in request_counts[ip] if now - t < RATE_WINDOW]

        if now - _last_cleanup > _CLEANUP_INTERVAL:
            _cleanup_stale_ips(now)
            _last_cleanup = now

        if len(request_counts[ip]) >= RATE_LIMIT:
            return True

        request_counts[ip].append(now)
        return False


def get_client_ip():
    if TRUST_X_FORWARDED_FOR:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr


# ---------------------------------------------------------------------------
# Inspection
# ---------------------------------------------------------------------------
def _decoded(value):
    try:
        return unquote(value)
    except Exception:
        return value


def inspect_request(body_bytes):
    targets = [request.full_path, _decoded(request.full_path)]

    for name, value in request.headers:
        if name.lower() in SCANNED_HEADERS:
            targets.append(value)

    if body_bytes:
        try:
            targets.append(body_bytes.decode("utf-8", errors="ignore"))
        except Exception:
            pass

    blob = "\n".join(targets)

    for rule_id, pattern in RULES:
        if pattern.search(blob):
            return rule_id

    return None


def add_security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


# ---------------------------------------------------------------------------
# Main proxy route
# ---------------------------------------------------------------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
def waf(path):
    client_ip = get_client_ip()

    # --- Rate limiting -----------------------------------------------------
    if rate_limited(client_ip):
        log.warning("BLOCK RATE-LIMIT ip=%s path=%s", client_ip, request.full_path)
        return add_security_headers(
            Response("WAF BLOCKED: Rate limit exceeded\n", status=429)
        )

    # --- Body size guard -----------------------------------------------------
    body = request.get_data()
    if len(body) > MAX_BODY_BYTES:
        log.warning("BLOCK BODY-TOO-LARGE ip=%s size=%d", client_ip, len(body))
        return add_security_headers(
            Response("WAF BLOCKED: Request body too large\n", status=413)
        )

    # --- Signature inspection ----------------------------------------------
    rule = inspect_request(body)
    if rule:
        log.warning(
            "BLOCK %s ip=%s method=%s path=%s",
            rule, client_ip, request.method, request.full_path,
        )
        return add_security_headers(
            Response(f"WAF BLOCKED\nRule: {rule}\n", status=403)
        )

    # --- Forward to upstream -------------------------------------------------
    url = UPSTREAM_APP.rstrip("/") + "/" + path

    try:
        upstream_resp = requests.request(
            method=request.method,
            url=url,
            params=request.args,
            data=body,
            headers={
                key: value
                for key, value in request.headers
                if key.lower() not in ("host", "content-length")
            },
            allow_redirects=False,
            timeout=UPSTREAM_TIMEOUT,
        )

        log.info("ALLOW %s %s -> %d", request.method, request.full_path, upstream_resp.status_code)

        excluded_headers = {"content-encoding", "content-length", "transfer-encoding", "connection"}
        headers = [
            (key, value)
            for key, value in upstream_resp.headers.items()
            if key.lower() not in excluded_headers
        ]

        return add_security_headers(
            Response(upstream_resp.content, upstream_resp.status_code, headers)
        )

    except requests.Timeout:
        log.error("UPSTREAM TIMEOUT path=%s", request.full_path)
        return add_security_headers(Response("WAF ERROR: Upstream timeout\n", status=504))

    except requests.RequestException as e:
        log.error("UPSTREAM ERROR path=%s err=%s", request.full_path, e)
        return add_security_headers(Response(f"WAF ERROR: Cannot reach upstream\n{e}\n", status=502))


if __name__ == "__main__":
    print("================================")
    print("       NANO WAF STARTED")
    print("================================")
    print(f"WAF:      http://{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"Upstream: {UPSTREAM_APP}")
    print(f"Rate limit: {RATE_LIMIT} req / {RATE_WINDOW}s")
    print("================================")

    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False)

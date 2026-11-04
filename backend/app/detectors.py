"""Heuristic detectors.

They are tuned for recall: each one flags traffic worth a closer look and records the literal
evidence that triggered it. Muse Spark then decides whether a signal is a real issue.
Detectors only read captured traffic. They never send requests.
"""
from __future__ import annotations

import base64
import html
import json
import re
from collections import defaultdict
from urllib.parse import parse_qsl

from .filters import ID_SEGMENT, path_template
from .models import HttpExchange, Signal, VulnClass

# ---------------------------------------------------------------- helpers


def _snippet(text: str, needle: str, width: int = 60) -> str:
    i = text.find(needle)
    if i < 0:
        return ""
    return text[max(0, i - width): i + len(needle) + width]


def _auth_value(ex: HttpExchange) -> str:
    return ex.header("Authorization", response=False) or ex.header("Cookie", response=False) or ""


def _jwt_claims(ex: HttpExchange) -> dict:
    """Decode (without verifying) a bearer JWT so we know which user the session belongs to."""
    auth = ex.header("Authorization", response=False) or ""
    m = re.search(r"eyJ[\w-]+\.([\w-]+)\.[\w-]*", auth)
    if not m:
        return {}
    payload = m.group(1) + "=" * (-len(m.group(1)) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _params(ex: HttpExchange) -> list[tuple[str, str]]:
    params = parse_qsl(ex.query, keep_blank_values=False)
    ctype = (ex.header("Content-Type", response=False) or "").lower()
    if ex.request_body:
        if "json" in ctype:
            try:
                body = json.loads(ex.request_body)
                if isinstance(body, dict):
                    params += [(k, str(v)) for k, v in body.items() if isinstance(v, (str, int, float))]
            except json.JSONDecodeError:
                pass
        else:
            params += parse_qsl(ex.request_body, keep_blank_values=False)
    return params


def _is_html(ex: HttpExchange) -> bool:
    ctype = (ex.header("Content-Type") or ex.mime or "").lower()
    return "html" in ctype


# ---------------------------------------------------------------- detectors


def detect_reflected_input(exchanges: list[HttpExchange]) -> list[Signal]:
    out = []
    for ex in exchanges:
        if not ex.response_body:
            continue
        for name, value in _params(ex):
            if len(value) < 4 or value.isdigit():
                continue  # short or numeric values reflect by coincidence
            if value not in ex.response_body:
                continue
            has_special = any(c in value for c in "<>\"'")
            encoded = html.escape(value) != value and html.escape(value) in ex.response_body
            if has_special and not encoded:
                score = 0.85 if _is_html(ex) else 0.5
            else:
                score = 0.4 if _is_html(ex) else 0.2
            out.append(Signal(
                vuln_class=VulnClass.REFLECTED_INPUT,
                exchange_ids=[ex.id],
                reason=f"Parameter '{name}' is reflected in the response"
                       + (" without HTML encoding, including special characters" if has_special and not encoded else ""),
                evidence=[f"{name}={value}", _snippet(ex.response_body, value)],
                score=score,
            ))
            break  # one signal per exchange is enough for review
    return out


ERROR_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at [\w.$]+\([\w]+\.java:\d+\)",
    r"SQLSTATE\[\w+\]",
    r"ORA-\d{5}",
    r"You have an error in your SQL syntax",
    r"SQLITE_ERROR",
    r"syntax error at or near \"",
    r"PG::\w+Error",
    r"System\.\w+Exception",
    r"Fatal error: .+ in /[\w/.-]+ on line \d+",
    r"(?:Django|Laravel|Express) (?:debug|version) [\d.]+",
    r"node_modules/[\w@./-]+:\d+",
]
ERROR_RE = re.compile("|".join(ERROR_PATTERNS))


def detect_verbose_errors(exchanges: list[HttpExchange]) -> list[Signal]:
    out = []
    for ex in exchanges:
        m = ERROR_RE.search(ex.response_body)
        if not m:
            continue
        out.append(Signal(
            vuln_class=VulnClass.VERBOSE_ERROR,
            exchange_ids=[ex.id],
            reason="Response contains a stack trace or database error detail",
            evidence=[_snippet(ex.response_body, m.group(0), 80).strip()],
            score=0.7 if ex.status >= 500 else 0.55,
        ))
    return out


SECRET_PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "private key": r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "password field": r"\"(?:password|passwd|pwd)\"\s*:\s*\"[^\"]{3,}\"",
    "password hash": r"\"(?:password_hash|passwordHash|hash)\"\s*:\s*\"\$2[aby]\$[^\"]+\"",
    "API secret": r"\"(?:api_?key|secret|client_secret|access_token)\"\s*:\s*\"[\w\-.]{16,}\"",
    "SIN/SSN": r"\"(?:ssn|sin)\"\s*:\s*\"\d{3}-?\d{2,3}-?\d{3,4}\"",
}


def detect_sensitive_data(exchanges: list[HttpExchange]) -> list[Signal]:
    out = []
    for ex in exchanges:
        hits = []
        for label, pat in SECRET_PATTERNS.items():
            m = re.search(pat, ex.response_body, re.I)
            if m:
                hits.append((label, m.group(0)))
        if hits:
            out.append(Signal(
                vuln_class=VulnClass.SENSITIVE_DATA,
                exchange_ids=[ex.id],
                reason="Response exposes " + ", ".join(h[0] for h in hits),
                evidence=[h[1] for h in hits],
                score=0.8,
            ))
    return out


def detect_cors(exchanges: list[HttpExchange]) -> list[Signal]:
    out = []
    for ex in exchanges:
        acao = ex.header("Access-Control-Allow-Origin")
        if not acao:
            continue
        creds = (ex.header("Access-Control-Allow-Credentials") or "").lower() == "true"
        origin = ex.header("Origin", response=False)
        reflected = origin and acao == origin and ex.host not in origin
        if (reflected or acao == "null") and creds:
            out.append(Signal(
                vuln_class=VulnClass.CORS,
                exchange_ids=[ex.id],
                reason=f"Origin '{acao}' is trusted with credentials allowed",
                evidence=[f"Access-Control-Allow-Origin: {acao}", "Access-Control-Allow-Credentials: true"]
                         + ([f"Origin: {origin}"] if origin else []),
                score=0.8,
            ))
        elif reflected:
            out.append(Signal(
                vuln_class=VulnClass.CORS,
                exchange_ids=[ex.id],
                reason="Arbitrary request Origin is reflected (no credentials)",
                evidence=[f"Access-Control-Allow-Origin: {acao}", f"Origin: {origin}"],
                score=0.35,
            ))
    return out


def detect_idor(exchanges: list[HttpExchange]) -> list[Signal]:
    """Two patterns:
    1. The session's own user id (JWT 'sub' or 'user_id') differs from the object id in the path,
       and the server returned 2xx.
    2. One session got 2xx for several ids on the same route, with different owner fields in the bodies.
    """
    out = []
    by_route: dict[tuple, list[HttpExchange]] = defaultdict(list)
    for ex in exchanges:
        if not _auth_value(ex):
            continue
        ids = [seg for seg in ex.path.split("/") if ID_SEGMENT.match(seg)]
        if not ids:
            continue
        by_route[(ex.method, path_template(ex.path), _auth_value(ex))].append(ex)

        claims = _jwt_claims(ex)
        me = str(claims.get("sub") or claims.get("user_id") or claims.get("uid") or "")
        if me and 200 <= ex.status < 300 and "/users/" in ex.path.lower() and me not in ids:
            out.append(Signal(
                vuln_class=VulnClass.IDOR,
                exchange_ids=[ex.id],
                reason=f"Session for user {me} received {ex.status} for another user's object ({ex.path})",
                evidence=[f"{ex.method} {ex.path}", f"JWT sub={me}", f"HTTP/1.1 {ex.status}"],
                score=0.85,
            ))

    owner_re = re.compile(r"\"(?:owner_?id|user_?id|account_?id|email)\"\s*:\s*\"?([^\",}]+)", re.I)
    flagged = {i for s in out for i in s.exchange_ids}
    for (method, tmpl, _), group in by_route.items():
        ok = [e for e in group if 200 <= e.status < 300 and e.id not in flagged]
        owners = {}
        for e in ok:
            m = owner_re.search(e.response_body)
            if m:
                owners[e.id] = m.group(0)
        if len(set(owners.values())) >= 2:
            ids = list(owners)
            out.append(Signal(
                vuln_class=VulnClass.IDOR,
                exchange_ids=ids,
                reason=f"One session read {len(ids)} objects on {method} {tmpl} belonging to different owners",
                evidence=[f"{e.method} {e.path}" for e in ok if e.id in owners] + list(owners.values()),
                score=0.75,
            ))
    return out


SENSITIVE_KEYS = re.compile(r"\"(?:email|role|ssn|sin|phone|address|is_admin|balance|users)\"\s*:", re.I)


def detect_missing_auth(exchanges: list[HttpExchange]) -> list[Signal]:
    """Flag API routes that answered 2xx with user data to a request carrying no credentials,
    especially when the same route is also called with credentials elsewhere in the history."""
    out = []
    authed_routes = {(e.method, path_template(e.path)) for e in exchanges if _auth_value(e)}
    for ex in exchanges:
        if _auth_value(ex) or not (200 <= ex.status < 300):
            continue
        if "/api/" not in ex.path and "/admin" not in ex.path:
            continue
        m = SENSITIVE_KEYS.search(ex.response_body)
        if not m:
            continue
        paired = (ex.method, path_template(ex.path)) in authed_routes
        out.append(Signal(
            vuln_class=VulnClass.MISSING_AUTH,
            exchange_ids=[ex.id],
            reason=("Unauthenticated request returned user data on a route that is normally called with credentials"
                    if paired else "Unauthenticated request returned user data"),
            evidence=[f"{ex.method} {ex.path}", "(no Authorization or Cookie header)", _snippet(ex.response_body, m.group(0), 50)],
            score=0.8 if paired or "/admin" in ex.path else 0.55,
        ))
    return out


ALL_DETECTORS = [
    detect_idor,
    detect_missing_auth,
    detect_reflected_input,
    detect_verbose_errors,
    detect_sensitive_data,
    detect_cors,
]


def run_detectors(exchanges: list[HttpExchange]) -> list[Signal]:
    signals: list[Signal] = []
    for det in ALL_DETECTORS:
        signals.extend(det(exchanges))
    return sorted(signals, key=lambda s: -s.score)

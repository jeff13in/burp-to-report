"""Parse Burp Suite XML exports and HAR files into HttpExchange objects."""
from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

from .models import HttpExchange

MAX_BODY = 200_000  # chars kept per body; huge downloads aren't useful for triage


class ParseError(ValueError):
    pass


def _decode(text: str | None, is_b64: bool) -> str:
    if not text:
        return ""
    if is_b64:
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:  # malformed base64: keep raw
            return text
    return text


def _split_raw_http(raw: str) -> tuple[str, dict[str, str], str]:
    """Split a raw HTTP message into (start line, headers, body)."""
    raw = raw.replace("\r\n", "\n")
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    start = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    return start, headers, body[:MAX_BODY]


def parse_burp_xml(data: str) -> list[HttpExchange]:
    """Burp: Proxy > HTTP history > select items > 'Save items' (base64 on or off)."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ParseError(f"Not valid Burp XML: {e}") from e

    out: list[HttpExchange] = []
    for i, item in enumerate(root.iter("item")):
        url = (item.findtext("url") or "").strip()
        req_el, resp_el = item.find("request"), item.find("response")
        req_raw = _decode(req_el.text if req_el is not None else "",
                          req_el is not None and req_el.get("base64") == "true")
        resp_raw = _decode(resp_el.text if resp_el is not None else "",
                           resp_el is not None and resp_el.get("base64") == "true")
        _, req_headers, req_body = _split_raw_http(req_raw)
        start, resp_headers, resp_body = _split_raw_http(resp_raw)
        status_text = item.findtext("status") or (start.split(" ")[1] if len(start.split(" ")) > 1 else "0")
        parts = urlsplit(url)
        out.append(HttpExchange(
            id=i,
            method=(item.findtext("method") or "GET").upper(),
            url=url,
            host=parts.hostname or (item.findtext("host") or ""),
            path=parts.path or "/",
            query=parts.query,
            request_headers=req_headers,
            request_body=req_body,
            status=int(status_text) if status_text.strip().isdigit() else 0,
            response_headers=resp_headers,
            response_body=resp_body,
            mime=(item.findtext("mimetype") or "").lower(),
        ))
    return out


def parse_har(data: str) -> list[HttpExchange]:
    try:
        har = json.loads(data)
        entries = har["log"]["entries"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise ParseError(f"Not a valid HAR file: {e}") from e

    out: list[HttpExchange] = []
    for i, e in enumerate(entries):
        req, resp = e.get("request", {}), e.get("response", {})
        content = resp.get("content", {}) or {}
        body = content.get("text", "") or ""
        if content.get("encoding") == "base64":
            body = _decode(body, True)
        parts = urlsplit(req.get("url", ""))
        out.append(HttpExchange(
            id=i,
            method=req.get("method", "GET").upper(),
            url=req.get("url", ""),
            host=parts.hostname or "",
            path=parts.path or "/",
            query=parts.query,
            request_headers={h["name"]: h["value"] for h in req.get("headers", [])},
            request_body=((req.get("postData") or {}).get("text") or "")[:MAX_BODY],
            status=int(resp.get("status", 0) or 0),
            response_headers={h["name"]: h["value"] for h in resp.get("headers", [])},
            response_body=body[:MAX_BODY],
            mime=(content.get("mimeType") or "").lower(),
        ))
    return out


def parse_export(data: str, filename: str = "") -> list[HttpExchange]:
    """Detect the format from the content, not just the extension."""
    stripped = data.lstrip()
    if stripped.startswith("<"):
        return parse_burp_xml(data)
    if stripped.startswith("{"):
        return parse_har(data)
    raise ParseError(f"Unrecognised export format for {filename or 'upload'}: expected Burp XML or HAR")

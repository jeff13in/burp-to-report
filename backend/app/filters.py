"""Cut noise before anything reaches the model: static assets, out-of-scope hosts, duplicates."""
from __future__ import annotations

import re

from .models import HttpExchange

STATIC_EXT = re.compile(r"\.(css|js|map|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|webp|mp4|mp3|pdf)$", re.I)
STATIC_MIME = ("image/", "font/", "text/css", "video/", "audio/")
ID_SEGMENT = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24,})$", re.I)


def path_template(path: str) -> str:
    """/api/users/42/orders -> /api/users/{id}/orders"""
    return "/".join("{id}" if ID_SEGMENT.match(seg) else seg for seg in path.split("/"))


def is_static(ex: HttpExchange) -> bool:
    if STATIC_EXT.search(ex.path):
        return True
    return any(ex.mime.startswith(m) for m in STATIC_MIME) or ex.mime in ("script", "css", "image")


def in_scope(ex: HttpExchange, scope: list[str]) -> bool:
    if not scope:
        return True
    return any(ex.host == s or ex.host.endswith("." + s) for s in scope)


def clean(exchanges: list[HttpExchange], scope: list[str] | None = None) -> tuple[list[HttpExchange], dict]:
    """Drop static and out-of-scope traffic. Exact duplicates (same method, URL, body, status, credentials)
    are collapsed. Two users requesting the same URL are not duplicates: that is what IDOR looks like.
    Distinct IDs on the same template are kept on purpose: the IDOR detector needs them."""
    scope = scope or []
    stats = {"total": len(exchanges), "static": 0, "out_of_scope": 0, "duplicate": 0}
    seen: set[tuple] = set()
    kept: list[HttpExchange] = []
    for ex in exchanges:
        if not in_scope(ex, scope):
            stats["out_of_scope"] += 1
            continue
        if is_static(ex):
            stats["static"] += 1
            continue
        key = (ex.method, ex.url, ex.request_body, ex.status, _auth(ex))
        if key in seen:
            stats["duplicate"] += 1
            continue
        seen.add(key)
        kept.append(ex)
    stats["kept"] = len(kept)
    return kept, stats


def _auth(ex: HttpExchange) -> str:
    return ex.header("Authorization", response=False) or ex.header("Cookie", response=False) or ""

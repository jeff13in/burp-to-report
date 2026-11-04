"""Record a HAR of normal Juice Shop use by two customers, plus visits to known-vulnerable pages.

    docker run -d -p 127.0.0.1:3000:3000 bkimminich/juice-shop
    python eval/capture_juiceshop.py
    python eval/run_eval.py --sample samples/juiceshop.har --truth samples/juiceshop_truth.json

Only point this at a Juice Shop instance you run yourself. It writes samples/juiceshop.har and fills
the placeholder paths in samples/juiceshop_truth.json into samples/juiceshop_truth.resolved.json.
"""
from __future__ import annotations

import argparse
import http.client
import json
import secrets
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


class Recorder:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.entries: list[dict] = []

    def send(self, method: str, path: str, token: str | None = None, body: dict | None = None,
             headers: dict | None = None) -> tuple[int, str]:
        url = self.base + path
        req_headers = {"User-Agent": UA, "Accept": "application/json, text/plain, */*"}
        if token:
            req_headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            req_headers["Content-Type"] = "application/json"
        req_headers.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=req_headers)
        try:
            resp = urllib.request.urlopen(req, timeout=15)
            status, resp_headers = resp.status, list(resp.headers.items())
            try:
                raw = resp.read()
            except http.client.IncompleteRead as e:  # /ftp sends a too-long Content-Length
                raw = e.partial
        except urllib.error.HTTPError as e:
            status, resp_headers, raw = e.code, list(e.headers.items()), e.read()
        text = raw.decode("utf-8", "replace")
        mime = dict((k.lower(), v) for k, v in resp_headers).get("content-type", "").split(";")[0]
        self.entries.append({
            "startedDateTime": datetime.now(timezone.utc).isoformat(),
            "time": 0,
            "request": {
                "method": method, "url": url, "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in req_headers.items()],
                "queryString": [], "cookies": [], "headersSize": -1,
                "bodySize": len(data or b""),
                **({"postData": {"mimeType": "application/json", "text": data.decode()}} if data else {}),
            },
            "response": {
                "status": status, "statusText": "", "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in resp_headers],
                "cookies": [], "content": {"size": len(raw), "mimeType": mime, "text": text},
                "redirectURL": "", "headersSize": -1, "bodySize": len(raw),
            },
            "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
        })
        return status, text

    def har(self) -> dict:
        return {"log": {"version": "1.2", "creator": {"name": "b2r-capture", "version": "1"},
                        "entries": self.entries}}


def customer(r: Recorder, name: str) -> dict:
    email = f"{name}.{secrets.token_hex(3)}@juice-sh.op"
    password = "Test-" + secrets.token_hex(6)
    r.send("POST", "/api/Users", body={
        "email": email, "password": password, "passwordRepeat": password,
        "securityQuestion": {"id": 1}, "securityAnswer": "blue"})
    _, text = r.send("POST", "/rest/user/login", body={"email": email, "password": password})
    auth = json.loads(text)["authentication"]
    return {"token": auth["token"], "bid": auth["bid"]}


def main(base: str) -> None:
    r = Recorder(base)

    # Anonymous browsing: page shell, static assets, public catalogue, a normal search.
    r.send("GET", "/", headers={"Accept": "text/html"})
    r.send("GET", "/main.js")
    r.send("GET", "/styles.css")
    r.send("GET", "/api/Products")
    r.send("GET", "/api/Products")  # exact duplicate, should be collapsed
    r.send("GET", "/rest/products/search?q=apple")
    r.send("GET", "/rest/admin/application-version")

    alice, bob = customer(r, "alice"), customer(r, "bob")

    # Each customer uses their own data (decoys: legitimate access).
    for c in (alice, bob):
        r.send("GET", "/rest/user/whoami", token=c["token"])
        r.send("GET", f"/rest/basket/{c['bid']}", token=c["token"])
        r.send("POST", "/api/BasketItems", token=c["token"],
               body={"ProductId": 1 if c is alice else 2, "BasketId": str(c["bid"]), "quantity": 1})
        r.send("GET", f"/rest/basket/{c['bid']}", token=c["token"])

    # Cross-origin request to a public endpoint: wildcard CORS without credentials (decoy).
    r.send("GET", "/api/Products/1", headers={"Origin": "https://example.org"})

    # Known-vulnerable pages.
    r.send("GET", f"/rest/basket/{bob['bid']}", token=alice["token"])            # View Basket
    r.send("GET", "/api/Users", token=alice["token"])                             # user list
    r.send("GET", "/rest/products/search?q=" + quote("';"))                      # SQLITE_ERROR
    r.send("GET", "/rest/qwertz")                                                 # Error Handling
    xss = '<iframe src="javascript:alert(`xss`)">'
    xss_path = "/rest/track-order/" + quote(xss, safe="")
    r.send("GET", xss_path)                                                       # Reflected XSS
    r.send("GET", "/ftp", headers={"Accept": "text/html"})                       # Confidential Document
    r.send("GET", "/metrics")                                                     # Exposed Metrics

    out = ROOT / "samples" / "juiceshop.har"
    out.write_text(json.dumps(r.har(), indent=1))

    truth = json.loads((ROOT / "samples" / "juiceshop_truth.json").read_text())
    for t in truth:
        t["path"] = (t["path"].replace("{other_bid}", str(bob["bid"]))
                     .replace("{xss_id}", urlsplit(base + xss_path).path.rsplit("/", 1)[1]))
    (ROOT / "samples" / "juiceshop_truth.resolved.json").write_text(json.dumps(truth, indent=1))
    print(f"wrote {out} ({len(r.entries)} requests)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:3000")
    main(ap.parse_args().base)

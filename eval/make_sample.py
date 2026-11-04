"""Generate a synthetic HAR from a fictional practice shop ("ShopLab") with planted bugs and decoys.

Writes samples/shoplab.har and samples/shoplab_truth.json. All data is fake.
Decoys are traffic that looks suspicious but is fine; a good triage keeps them out of the report.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST = "shoplab.test"


def b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


def jwt(sub: int) -> str:
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': str(sub), 'role': 'customer'})}.fakesignature"


ALICE = f"Bearer {jwt(1001)}"


def entry(method, path, status, body="", *, auth=None, req_body=None, ctype="application/json",
          req_headers=None, resp_headers=None):
    headers = [{"name": "Host", "value": HOST}, {"name": "User-Agent", "value": "Mozilla/5.0"}]
    if auth:
        headers.append({"name": "Authorization", "value": auth})
    for k, v in (req_headers or {}).items():
        headers.append({"name": k, "value": v})
    req = {"method": method, "url": f"https://{HOST}{path}", "headers": headers}
    if req_body is not None:
        req["postData"] = {"mimeType": "application/json", "text": json.dumps(req_body)}
        headers.append({"name": "Content-Type", "value": "application/json"})
    rh = [{"name": "Content-Type", "value": ctype}] + [{"name": k, "value": v} for k, v in (resp_headers or {}).items()]
    return {"request": req, "response": {"status": status, "headers": rh,
                                         "content": {"mimeType": ctype, "text": body}}}


def J(d) -> str:
    return json.dumps(d)


entries = [
    # noise
    entry("GET", "/static/app.js", 200, "console.log(1)", ctype="application/javascript"),
    entry("GET", "/static/logo.png", 200, "", ctype="image/png"),
    entry("GET", "/", 200, "<html><body>ShopLab</body></html>", ctype="text/html"),
    entry("GET", "/", 200, "<html><body>ShopLab</body></html>", ctype="text/html"),  # duplicate
    entry("POST", "/api/login", 200, J({"token": "issued"}), req_body={"username": "alice", "password": "x"}),

    # PLANTED 1: IDOR, Alice (1001) reads Bob's profile
    entry("GET", "/api/users/1002", 200, J({"id": 1002, "email": "bob@shoplab.test", "phone": "555-0102"}), auth=ALICE),
    # DECOY: Alice reads her own profile
    entry("GET", "/api/users/1001", 200, J({"id": 1001, "email": "alice@shoplab.test"}), auth=ALICE),

    # PLANTED 2: IDOR on orders: same session, different owners
    entry("GET", "/api/orders/5001", 200, J({"id": 5001, "owner_id": "1001", "total": 42.0}), auth=ALICE),
    entry("GET", "/api/orders/5002", 200, J({"id": 5002, "owner_id": "1007", "total": 310.5}), auth=ALICE),

    # PLANTED 3: admin route with no credentials
    entry("GET", "/api/admin/users", 200,
          J({"users": [{"id": 1, "email": "admin@shoplab.test", "role": "admin"}]})),
    # DECOY: public catalogue without credentials
    entry("GET", "/api/products", 200, J([{"id": 1, "name": "Trail shoe", "price": 89}])),

    # PLANTED 4: reflected input, unencoded, in HTML
    entry("GET", "/search?q=%3Cb%3Eshoe%22%3E", 200,
          '<html><body><h1>Results for <b>shoe"></h1></body></html>', ctype="text/html"),
    # DECOY: same search, output encoded
    entry("GET", "/search?q=%3Ci%3Eboot", 200,
          "<html><body><h1>Results for &lt;i&gt;boot</h1></body></html>", ctype="text/html"),
    # DECOY: harmless alphanumeric echo in JSON
    entry("POST", "/api/newsletter", 200, J({"subscribed": "alice_news"}), req_body={"name": "alice_news"}),

    # PLANTED 5: verbose error with stack trace
    entry("POST", "/api/cart", 500,
          'Traceback (most recent call last):\n  File "/srv/shoplab/cart.py", line 88, in add\n'
          "    qty = int(payload['qty'])\nValueError: invalid literal for int()",
          auth=ALICE, req_body={"product": 1, "qty": "two"}, ctype="text/plain"),

    # PLANTED 6: password hash returned to the client
    entry("GET", "/api/me", 200,
          J({"id": 1001, "email": "alice@shoplab.test",
             "password_hash": "$2b$12$abcdefghijklmnopqrstuuFAKEFAKEFAKEFAKEFAKEFAKEFAKE"}), auth=ALICE),

    # PLANTED 7: CORS reflects arbitrary origin with credentials
    entry("GET", "/api/account", 200, J({"id": 1001, "balance": 120}), auth=ALICE,
          req_headers={"Origin": "https://attacker.example"},
          resp_headers={"Access-Control-Allow-Origin": "https://attacker.example",
                        "Access-Control-Allow-Credentials": "true"}),
    # DECOY: CORS wildcard on public data, no credentials
    entry("GET", "/api/products/1", 200, J({"id": 1, "name": "Trail shoe"}),
          req_headers={"Origin": "https://partner.example"},
          resp_headers={"Access-Control-Allow-Origin": "*"}),
]

truth = [
    {"id": "idor-user", "vuln_class": "idor", "path": "/api/users/1002"},
    {"id": "idor-order", "vuln_class": "idor", "path": "/api/orders/5002"},
    {"id": "noauth-admin", "vuln_class": "missing_authorization", "path": "/api/admin/users"},
    {"id": "xss-search", "vuln_class": "reflected_input", "path": "/search", "query_contains": "%3Cb%3E"},
    {"id": "error-cart", "vuln_class": "verbose_error", "path": "/api/cart"},
    {"id": "hash-me", "vuln_class": "sensitive_data_exposure", "path": "/api/me"},
    {"id": "cors-account", "vuln_class": "cors_misconfiguration", "path": "/api/account"},
]

if __name__ == "__main__":
    (ROOT / "samples").mkdir(exist_ok=True)
    har = {"log": {"version": "1.2", "creator": {"name": "make_sample.py"}, "entries": entries}}
    (ROOT / "samples" / "shoplab.har").write_text(json.dumps(har, indent=1))
    (ROOT / "samples" / "shoplab_truth.json").write_text(json.dumps(truth, indent=1))
    print(f"wrote {len(entries)} entries, {len(truth)} planted issues")

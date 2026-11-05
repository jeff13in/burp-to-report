import asyncio
import base64
import json
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.detectors import run_detectors
from app.filters import clean, path_template
from app.llm import LLMClient, LLMConfig, extract_json
from app.models import VulnClass
from app.parsers import ParseError, parse_burp_xml, parse_export
from app.pipeline import analyze
from app.rag import Retriever
from app.triage import redact, validate

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = (ROOT / "samples" / "shoplab.har").read_text()


def llm_with(handler) -> LLMClient:
    cfg = LLMConfig(base_url="https://api.test/v1", api_key="k", model="muse-spark-test", mode="cloud", max_retries=1)
    return LLMClient(cfg, transport=httpx.MockTransport(handler))


def reply(obj) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(obj)}}]})


# ---------------- parsing and filtering

def test_parse_burp_xml_base64():
    req = base64.b64encode(b"GET /api/x?id=1 HTTP/1.1\r\nHost: a.test\r\nCookie: s=1\r\n\r\n").decode()
    resp = base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":1}").decode()
    xml = f"""<items><item><url>https://a.test/api/x?id=1</url><host>a.test</host><method>GET</method>
    <status>200</status><mimetype>JSON</mimetype><request base64="true">{req}</request>
    <response base64="true">{resp}</response></item></items>"""
    [ex] = parse_burp_xml(xml)
    assert ex.path == "/api/x" and ex.query == "id=1" and ex.status == 200
    assert ex.header("Cookie", response=False) == "s=1"
    assert ex.response_body == '{"ok":1}'


def test_unknown_format_rejected():
    with pytest.raises(ParseError):
        parse_export("hello", "x.txt")


def test_clean_drops_static_and_duplicates():
    kept, stats = clean(parse_export(SAMPLE))
    assert stats["static"] == 2 and stats["duplicate"] == 1
    assert all(not e.path.startswith("/static") for e in kept)


def test_clean_keeps_same_url_from_different_sessions():
    def entry(token):
        return {"request": {"method": "GET", "url": "https://a.test/rest/basket/9",
                            "headers": [{"name": "Authorization", "value": f"Bearer {token}"}]},
                "response": {"status": 200, "headers": [], "content": {"mimeType": "application/json", "text": "{}"}}}
    har = json.dumps({"log": {"entries": [entry("bob"), entry("alice"), entry("alice")]}})
    kept, stats = clean(parse_export(har, "x.har"))
    assert len(kept) == 2 and stats["duplicate"] == 1


def test_path_template():
    assert path_template("/api/users/42/orders") == "/api/users/{id}/orders"


# ---------------- detectors

def test_detectors_find_planted_and_skip_decoys():
    kept, _ = clean(parse_export(SAMPLE))
    sigs = run_detectors(kept)
    by_path = {(s.vuln_class, kept[[e.id for e in kept].index(s.exchange_ids[0])].path) for s in sigs}
    assert (VulnClass.IDOR, "/api/users/1002") in by_path
    assert (VulnClass.IDOR, "/api/users/1001") not in by_path  # own profile
    assert (VulnClass.MISSING_AUTH, "/api/products") not in by_path  # public data
    assert not any(s.vuln_class == VulnClass.CORS and s.score > 0.5 and "partner" in str(s.evidence) for s in sigs)


# ---------------- redaction and validation

def test_redact_masks_tokens_but_keeps_jwt_claims():
    text = "GET / HTTP/1.1\nAuthorization: Bearer eyJhbGc.eyJzdWIiOiIxIn0.sig\nCookie: session=abc123"
    out = redact(text)
    assert "abc123" not in out and "sig" not in out.split("payload")[0]
    assert "eyJzdWIiOiIxIn0" in out  # payload kept for identity reasoning
    assert redact(text) == out  # deterministic placeholders


def test_redact_masks_secrets_in_bodies_and_query():
    jwt = "eyJhbGc.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"
    text = ("POST /login?api_key=k3y123&q=shoes HTTP/1.1\nContent-Type: application/json\n\n"
            '{"email": "a@x.test", "password": "hunter2"}\n'
            f'{{"authentication":{{"token":"{jwt}"}}}}\n'
            "email=a%40x.test&password=hunter2\nid AKIAABCDEFGHIJKLMNOP\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----")
    out = redact(text)
    for secret in ("hunter2", "k3y123", "c2lnbmF0dXJl", "AKIAABCDEFGHIJKLMNOP", "MIIEow"):
        assert secret not in out
    assert "q=shoes" in out and '"email": "a@x.test"' in out  # non-secret fields untouched
    assert "eyJzdWIiOiIxIn0" in out  # jwt claims still readable
    assert redact(text) == out


def test_model_prompt_has_no_body_secrets():
    def handler(req):
        user = json.loads(req.content)["messages"][1]["content"]
        assert "s3cr3t-pass" not in user and "c2lnbmF0dXJl" not in user
        return reply({"is_vulnerability": False, "confidence": 0.9, "rationale": "x"})
    entry = {"request": {"method": "POST", "url": "https://a.test/api/login",
                         "headers": [{"name": "Content-Type", "value": "application/json"}],
                         "postData": {"text": '{"password": "s3cr3t-pass"}'}},
             "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "text/html"}],
                          "content": {"mimeType": "text/html",
                                      "text": '<p>s3cr3t-pass</p>{"token": "eyJhbGc.eyJzdWIiOiIxIn0.c2lnbmF0dXJl"}'}}}
    har = json.dumps({"log": {"entries": [entry]}})
    result = asyncio.run(analyze(har, "x.har", llm_with(handler), Retriever.from_dir()))
    assert result["stats"]["signals"] >= 1


def _har(entries) -> str:
    def entry(url, req_headers, resp_headers, body="{}"):
        return {"request": {"method": "GET", "url": url,
                            "headers": [{"name": k, "value": v} for k, v in req_headers.items()]},
                "response": {"status": 200, "headers": [{"name": k, "value": v} for k, v in resp_headers.items()],
                             "content": {"mimeType": "application/json", "text": body}}}
    return json.dumps({"log": {"entries": [entry(*e) for e in entries]}})


def test_cors_suffix_origin_is_flagged_but_same_origin_is_not():
    creds = {"Access-Control-Allow-Credentials": "true"}
    har = _har([
        ("https://shop.test/api/me", {"Origin": "https://shop.test.evil.example", "Cookie": "s=1"},
         {"Access-Control-Allow-Origin": "https://shop.test.evil.example", **creds}),
        ("https://shop.test/api/cart", {"Origin": "https://shop.test", "Cookie": "s=1"},
         {"Access-Control-Allow-Origin": "https://shop.test", **creds}),
    ])
    sigs = [s for s in run_detectors(parse_export(har)) if s.vuln_class == VulnClass.CORS]
    assert [s.exchange_ids for s in sigs] == [[0]]


def test_idor_on_user_collections_and_nested_jwt_id():
    def bearer(claims):
        b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
        return {"Authorization": f"Bearer {b64({'alg': 'RS256'})}.{b64(claims)}.sig"}
    har = _har([
        ("https://a.test/api/accounts/7/settings", bearer({"sub": "3"}), {}),
        ("https://a.test/api/Users/9", bearer({"data": {"id": 3, "email": "a@x.test"}}), {}),
        ("https://a.test/api/Users/3", bearer({"data": {"id": 3}}), {}),     # own object
        ("https://a.test/api/orders/7", bearer({"sub": "3"}), {}),           # not a user object
    ])
    sigs = [s for s in run_detectors(parse_export(har)) if s.vuln_class == VulnClass.IDOR]
    assert sorted(i for s in sigs for i in s.exchange_ids) == [0, 1]


def test_validate_drops_fabricated_evidence_and_citations():
    traffic = 'HTTP/1.1 200\n{"email": "bob@x.test"}'
    ev, refs, notes = validate({"evidence": ['"email": "bob@x.test"', "made up line"],
                                "references": ["idor", "owasp-made-up"]}, traffic, {"idor"})
    assert ev == ['"email": "bob@x.test"'] and refs == ["idor"] and len(notes) == 2


def test_extract_json_handles_fences():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! {"a": 2} hope this helps') == {"a": 2}


# ---------------- triage with a mocked model

def test_model_can_suppress_and_confirm():
    def handler(req):
        body = json.loads(req.content)
        user = body["messages"][1]["content"]
        assert "Bearer eyJ" not in user  # credentials never leave unredacted
        if "verbose_error" in user:
            return reply({"is_vulnerability": False, "confidence": 0.8, "rationale": "test env"})
        return reply({"is_vulnerability": True, "confidence": 0.9, "severity": "high", "title": "T",
                      "rationale": "R", "impact": "I", "evidence": ["HTTP/1.1 200"],
                      "references": ["idor", "fake-ref"], "remediation": "Fix"})

    result = asyncio.run(analyze(SAMPLE, "s.har", llm_with(handler), Retriever.from_dir()))
    assert result["stats"]["suppressed_by_model"] == 1
    assert all(f.vuln_class != VulnClass.VERBOSE_ERROR for f in result["findings"])
    f = result["findings"][0]
    assert f.triaged_by == "muse-spark-test" and "fake-ref" not in f.references


def test_model_failure_falls_back_to_heuristics():
    result = asyncio.run(analyze(SAMPLE, "s.har", llm_with(lambda r: httpx.Response(503)), Retriever.from_dir()))
    assert result["findings"] and all(f.triaged_by == "heuristic" for f in result["findings"])


def test_ungrounded_model_claim_is_downgraded():
    handler = lambda r: reply({"is_vulnerability": True, "confidence": 1.0, "severity": "critical",
                               "evidence": ["nothing like this exists"], "references": []})
    result = asyncio.run(analyze(SAMPLE, "s.har", llm_with(handler), Retriever.from_dir()))
    assert all(f.confidence <= 0.6 for f in result["findings"])


# ---------------- API

def test_api_end_to_end(monkeypatch):
    from app import main
    monkeypatch.setattr(main, "llm", LLMClient(LLMConfig("", "", "", "off")))
    c = TestClient(main.app)
    r = c.post("/api/projects", files={"file": ("shoplab.har", SAMPLE)}, data={"name": "ShopLab"})
    assert r.status_code == 200
    p = r.json()
    fid = p["findings"][0]["id"]
    assert c.patch(f"/api/projects/{p['id']}/findings/{fid}", json={"status": "accepted"}).json()["status"] == "accepted"
    md = c.get(f"/api/projects/{p['id']}/report").text
    assert "## " in md and "Steps to reproduce" in md and "Bearer eyJ" not in md
    assert c.post("/api/projects", files={"file": ("x.txt", "nope")}).status_code == 400


# ---------------- hardening against malformed model output and uploads

def test_validate_rejects_non_list_evidence_and_bad_refs():
    ev, refs, notes = validate({"evidence": "zzz HTTP", "references": [{"a": 1}, "idor"]}, "HTTP/1.1 200", {"idor"})
    assert ev == [] and refs == ["idor"] and notes
    ev, _, _ = validate({"evidence": ["200", "HTTP/1.1 200"]}, "HTTP/1.1 200", set())
    assert ev == ["HTTP/1.1 200"]  # too-short quotes prove nothing


def test_extract_json_requires_object():
    with pytest.raises(ValueError):
        extract_json('[{"a": 1}]')


def test_odd_model_reply_falls_back_instead_of_crashing():
    handler = lambda r: reply({"is_vulnerability": True, "references": [{"x": 1}], "evidence": {"a": 1},
                               "confidence": "high", "severity": ["x"]})
    result = asyncio.run(analyze(SAMPLE, "s.har", llm_with(handler), Retriever.from_dir()))
    assert result["findings"] and all(f.confidence <= 0.6 for f in result["findings"])


@pytest.mark.parametrize("bad", ['{"log":{"entries":[{"request":{"headers":[{"x":1}]}}]}}',
                                 '{"log":{"entries":[1]}}', '{"log":{"entries":{}}}',
                                 '{"log":{"entries":[{"response":{"status":"abc"}}]}}'])
def test_malformed_har_is_a_parse_error(bad):
    with pytest.raises(ParseError):
        parse_export(bad, "x.har")


def test_report_redacts_evidence_and_cannot_be_broken_by_backticks():
    from app.models import Finding, Severity, Status
    from app.report import build_report
    f = Finding(id="f", vuln_class=VulnClass.SENSITIVE_DATA, title="Leak | in table", severity=Severity.HIGH,
                confidence=0.9, endpoint="GET a.test/x", exchange_ids=[], rationale="r",
                evidence=['"password": "hunter22"', "a ``` b `c`"], status=Status.ACCEPTED)
    md = build_report({"name": "t", "exchanges": [], "findings": [f]}, Retriever.from_dir())
    assert "hunter22" not in md and "Leak \\| in table" in md
    assert "- ```` a ``` b `c` ````" in md


def test_project_ids_are_unguessable_and_bounded(monkeypatch):
    from app import main
    monkeypatch.setattr(main, "PROJECTS", {})
    for _ in range(main.MAX_PROJECTS + 3):
        p = main._store("x", {"exchanges": [], "findings": [], "suppressed": [], "stats": {}})
    assert len(p["id"]) == 32 and len(main.PROJECTS) == main.MAX_PROJECTS

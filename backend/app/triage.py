"""Turn heuristic signals into reviewed findings.

For each signal: retrieve reference docs, send redacted traffic to the model, then validate
the answer. Evidence quotes must appear verbatim in the captured traffic and citations must
point at docs we actually supplied. Anything that fails validation is dropped or downgraded,
and every finding records why. If the model is unavailable, the heuristic result is kept.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import uuid
from urllib.parse import unquote_plus

from .filters import path_template
from .llm import LLMClient, LLMError
from .models import Finding, HttpExchange, Severity, Signal, VulnClass
from .rag import Retriever

DEFAULT_SEVERITY = {
    VulnClass.IDOR: Severity.HIGH,
    VulnClass.MISSING_AUTH: Severity.HIGH,
    VulnClass.SENSITIVE_DATA: Severity.HIGH,
    VulnClass.CORS: Severity.MEDIUM,
    VulnClass.REFLECTED_INPUT: Severity.MEDIUM,
    VulnClass.VERBOSE_ERROR: Severity.LOW,
}

TITLES = {
    VulnClass.IDOR: "IDOR: other users' objects readable on {ep}",
    VulnClass.MISSING_AUTH: "Missing authorization on {ep}",
    VulnClass.REFLECTED_INPUT: "Reflected input (possible XSS) on {ep}",
    VulnClass.VERBOSE_ERROR: "Verbose error / stack trace on {ep}",
    VulnClass.SENSITIVE_DATA: "Sensitive data exposed by {ep}",
    VulnClass.CORS: "CORS misconfiguration on {ep}",
}

REMEDIATION = {
    VulnClass.IDOR: "Enforce object-level authorization server-side; derive ownership from the session, not client input.",
    VulnClass.MISSING_AUTH: "Require authentication by default on API routes and check permissions per function.",
    VulnClass.REFLECTED_INPUT: "Apply context-aware output encoding and a strict Content-Security-Policy.",
    VulnClass.VERBOSE_ERROR: "Disable debug output in production and return generic error messages.",
    VulnClass.SENSITIVE_DATA: "Return data through explicit allow-list serializers and rotate exposed secrets.",
    VulnClass.CORS: "Validate Origin against an exact allow-list; never reflect arbitrary origins with credentials.",
}

SYSTEM_PROMPT = """You assist a security tester who is authorized to test the target application.
You review ONE candidate issue flagged by a heuristic in captured HTTP traffic and decide whether it is a real, reportable vulnerability.

Rules:
- Judge only from the traffic and reference documents provided. Do not invent requests or responses.
- "evidence" must be short strings copied EXACTLY (character for character) from the traffic shown. They are checked automatically.
- "references" may only contain ids from the REFERENCE DOCUMENTS list.
- Be skeptical: public data, encoded output, test placeholders and same-user access are false positives.
- Do not write exploit code or payloads. Describe the issue and its impact.

Return a JSON object with exactly these keys:
{"is_vulnerability": bool, "confidence": number 0-1, "severity": "critical|high|medium|low|info",
 "title": str, "rationale": str (2-4 sentences), "impact": str (1-2 sentences),
 "evidence": [str], "references": [str], "remediation": str}"""

SECRET_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization",
                  "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token"}
MAX_CHARS = 3500

# Field names whose values are credentials, in JSON bodies and in query/form parameters.
_SECRET_KEYS = (r"password|passwd|pwd|pass|new_?password|current_?password|password_?hash|"
                r"secret|client_?secret|api_?key|apikey|access_?token|refresh_?token|id_?token|"
                r"auth_?token|token|session_?id|sessionid|private_?key|totp_?secret|otp")
JSON_SECRET = re.compile(rf'("(?:{_SECRET_KEYS})"\s*:\s*")((?:[^"\\]|\\.)+)(")', re.I)
PARAM_SECRET = re.compile(rf"((?:^|[?&\s])(?:{_SECRET_KEYS})=)([^&\s]+)", re.I)
JWT = re.compile(r"eyJ[\w-]+\.([\w-]+)\.[\w-]*")
AWS_KEY = re.compile(r"AKIA[0-9A-Z]{16}")
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S)


def _mask(value: str) -> str:
    return f"<redacted:{hashlib.sha256(value.encode()).hexdigest()[:8]}>"


def _mask_secret(value: str) -> str:
    """Mask a credential. If it contains a JWT, keep the payload readable (see redact)."""
    if value.startswith("<redacted:"):
        return value
    masked = _mask(value.strip())
    jwt = JWT.search(value)
    if jwt:
        masked += f" (jwt payload: {jwt.group(1)})"
    return masked


def _redact_inline(line: str) -> str:
    line = JSON_SECRET.sub(lambda m: m.group(1) + _mask_secret(m.group(2)) + m.group(3), line)
    line = PARAM_SECRET.sub(lambda m: m.group(1) + _mask_secret(m.group(2)), line)
    line = JWT.sub(lambda m: _mask_secret(m.group(0)), line)
    return AWS_KEY.sub(lambda m: _mask(m.group(0)), line)


def redact(text: str) -> str:
    """Mask credentials before traffic leaves the machine: secret headers, secret fields in JSON
    bodies and query/form parameters, bare JWTs, AWS keys and private keys. The hash keeps values
    distinguishable (same token -> same placeholder) without revealing them. JWT payload claims stay
    readable because they identify the user the session belongs to, which IDOR review needs."""
    text = PEM.sub(lambda m: "-----BEGIN PRIVATE KEY----- " + _mask(m.group(0)), text)
    out = []
    for line in text.split("\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() in SECRET_HEADERS:
            line = f"{name}: {_mask_secret(value.strip())}"
        else:
            line = _redact_inline(line)
        out.append(line)
    return "\n".join(out)


MIN_SCRUB_LEN = 5  # shorter values would mask ordinary words


def secret_values(text: str) -> set[str]:
    """Credential values found in raw traffic (secret headers, secret fields). Used to mask the same
    values wherever else they appear, e.g. a password reflected into an HTML page."""
    found = set()
    for line in text.split("\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() in SECRET_HEADERS:
            found.add(value.strip())
    found |= {m.group(2) for m in JSON_SECRET.finditer(text)}
    for m in PARAM_SECRET.finditer(text):
        found |= {m.group(2), unquote_plus(m.group(2))}
    return {v for v in found if len(v) >= MIN_SCRUB_LEN}


def scrub(text: str, secrets: set[str]) -> str:
    for v in sorted(secrets, key=len, reverse=True):
        text = text.replace(v, _mask(v.strip()))
    return text


def _render_exchange(ex: HttpExchange) -> str:
    req = redact(ex.request_text())[:MAX_CHARS]
    resp = redact(ex.response_text())[:MAX_CHARS]
    return f"--- exchange #{ex.id} ---\n[REQUEST]\n{req}\n[RESPONSE]\n{resp}\n"


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def validate(result: dict, traffic: str, allowed_refs: set[str]) -> tuple[list[str], list[str], list[str]]:
    """Return (valid evidence, valid references, notes)."""
    notes = []
    corpus = _norm(traffic)
    evidence = []
    raw_evidence = result.get("evidence")
    if not isinstance(raw_evidence, list):
        if raw_evidence:
            notes.append("Dropped evidence: model did not return a list")
        raw_evidence = []
    for e in raw_evidence:
        # Very short quotes ("200", "id") match almost any traffic and prove nothing.
        if isinstance(e, str) and len(_norm(e)) >= 4 and _norm(e) in corpus:
            evidence.append(e.strip())
        else:
            notes.append(f"Dropped evidence not found verbatim in traffic: {str(e)[:80]!r}")
    refs = []
    raw_refs = result.get("references")
    for r in raw_refs if isinstance(raw_refs, list) else []:
        if isinstance(r, str) and r in allowed_refs:
            refs.append(r)
        else:
            notes.append(f"Dropped citation to unknown reference {r!r}")
    return evidence, refs, notes


def _endpoint(exchanges: list[HttpExchange]) -> str:
    ex = exchanges[0]
    return f"{ex.method} {ex.host}{path_template(ex.path)}"


def heuristic_finding(sig: Signal, exs: list[HttpExchange], refs: list[str], note: str) -> Finding:
    ep = _endpoint(exs)
    return Finding(
        id=uuid.uuid4().hex[:10],
        vuln_class=sig.vuln_class,
        title=TITLES[sig.vuln_class].format(ep=ep.split(" ", 1)[1]),
        severity=DEFAULT_SEVERITY[sig.vuln_class],
        confidence=round(sig.score * 0.8, 2),
        endpoint=ep,
        exchange_ids=sig.exchange_ids,
        rationale=sig.reason + ". Needs manual confirmation.",
        evidence=[e for e in sig.evidence if e],
        references=refs,
        remediation=REMEDIATION[sig.vuln_class],
        triaged_by="heuristic",
        validation_notes=[note],
    )


class Triage:
    def __init__(self, llm: LLMClient, retriever: Retriever, concurrency: int = 4):
        self.llm, self.retriever = llm, retriever
        self.sem = asyncio.Semaphore(concurrency)

    async def review(self, sig: Signal, by_id: dict[int, HttpExchange]) -> tuple[Finding | None, dict | None]:
        exs = [by_id[i] for i in sig.exchange_ids if i in by_id][:4]
        docs = self.retriever.search(f"{sig.vuln_class.value.replace('_', ' ')} {sig.reason}", k=3)
        if self.retriever.get("severity-guide") and all(d.id != "severity-guide" for d in docs):
            docs.append(self.retriever.get("severity-guide"))
        ref_ids = [d.id for d in docs]

        if not self.llm.enabled:
            return heuristic_finding(sig, exs, ref_ids[:2], "Model triage off; heuristic result only."), None

        traffic = "\n".join(_render_exchange(e) for e in exs)
        ref_block = "\n\n".join(f"[{d.id}] {d.text}" for d in docs)
        user = (f"HEURISTIC SIGNAL: {sig.vuln_class.value}: {sig.reason}\n"
                f"Heuristic evidence: {[redact(e) for e in sig.evidence]}\n\n"
                f"REFERENCE DOCUMENTS (cite by id):\n{ref_block}\n\nTRAFFIC:\n{traffic}")
        secrets = secret_values("\n".join(e.request_text() + "\n" + e.response_text() for e in exs))
        user = scrub(user, secrets)
        traffic = scrub(traffic, secrets)  # validation must see the same text the model saw
        try:
            async with self.sem:
                result = await self.llm.chat_json(SYSTEM_PROMPT, user)
        except (LLMError, ValueError) as e:
            return heuristic_finding(sig, exs, ref_ids[:2], f"Model unavailable ({e.__class__.__name__}); heuristic fallback."), None
        try:
            return self._finding_from_model(sig, exs, result, traffic, ref_ids)
        except Exception as e:  # malformed model output must not abort the whole analysis
            return heuristic_finding(sig, exs, ref_ids[:2], f"Model reply unusable ({e.__class__.__name__}); heuristic fallback."), None

    def _finding_from_model(self, sig: Signal, exs: list[HttpExchange], result: dict, traffic: str,
                            ref_ids: list[str]) -> tuple[Finding | None, dict | None]:
        evidence, refs, notes = validate(result, traffic, set(ref_ids))
        try:
            confidence = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
        except (TypeError, ValueError):
            confidence = 0.5
        if not result.get("is_vulnerability"):
            return None, {"signal": sig.model_dump(), "model_rationale": result.get("rationale", ""),
                          "confidence": confidence}
        if not evidence:
            # The model claimed a bug but could not ground it: keep the heuristic evidence, lower trust.
            evidence = [e for e in sig.evidence if e]
            confidence *= 0.6
            notes.append("No model evidence survived validation; using heuristic evidence and lowering confidence.")
        try:
            severity = Severity(str(result.get("severity", "")).lower())
        except ValueError:
            severity = DEFAULT_SEVERITY[sig.vuln_class]
            notes.append("Model severity invalid; class default used.")

        rationale = str(result.get("rationale", sig.reason)).strip()
        if result.get("impact"):
            rationale += f"\n\nImpact: {str(result['impact']).strip()}"
        return Finding(
            id=uuid.uuid4().hex[:10],
            vuln_class=sig.vuln_class,
            title=str(result.get("title") or TITLES[sig.vuln_class].format(ep=_endpoint(exs).split(" ", 1)[1]))[:140],
            severity=severity,
            confidence=round(confidence, 2),
            endpoint=_endpoint(exs),
            exchange_ids=sig.exchange_ids,
            rationale=rationale,
            evidence=evidence,
            references=refs,
            remediation=str(result.get("remediation") or REMEDIATION[sig.vuln_class]),
            triaged_by=self.llm.cfg.model,
            validation_notes=notes,
        ), None

    async def run(self, signals: list[Signal], exchanges: list[HttpExchange]) -> tuple[list[Finding], list[dict]]:
        by_id = {e.id: e for e in exchanges}
        results = await asyncio.gather(*(self.review(s, by_id) for s in signals))
        findings = [f for f, _ in results if f]
        suppressed = [s for _, s in results if s]
        sev_rank = {s: i for i, s in enumerate(Severity)}
        findings.sort(key=lambda f: (sev_rank[f.severity], -f.confidence))
        return findings, suppressed

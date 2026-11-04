"""FastAPI service for Burp-to-Report."""
from __future__ import annotations

import uuid
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .llm import LLMClient
from .models import FindingUpdate
from .parsers import ParseError
from .pipeline import analyze
from .rag import Retriever
from .report import build_report
from .triage import redact

MAX_UPLOAD = 50 * 1024 * 1024

app = FastAPI(title="Burp-to-Report", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_methods=["*"], allow_headers=["*"])

retriever = Retriever.from_dir()
llm = LLMClient()
PROJECTS: dict[str, dict] = {}  # in-memory; traffic is sensitive, so nothing is written to disk


def _project(pid: str) -> dict:
    if pid not in PROJECTS:
        raise HTTPException(404, "project not found")
    return PROJECTS[pid]


@app.get("/api/health")
def health():
    return {"ok": True, "mode": llm.cfg.mode, "model": llm.cfg.model if llm.enabled else None,
            "kb_docs": len(retriever.docs)}


@app.post("/api/projects")
async def create_project(file: UploadFile = File(...), name: str = Form("Untitled assessment"),
                         scope: str = Form("")):
    raw = await file.read(MAX_UPLOAD + 1)
    if len(raw) > MAX_UPLOAD:
        raise HTTPException(413, "export larger than 50 MB")
    try:
        result = await analyze(raw.decode("utf-8", errors="replace"), file.filename or "",
                               llm, retriever, [s.strip() for s in scope.split(",") if s.strip()])
    except ParseError as e:
        raise HTTPException(400, str(e))
    pid = uuid.uuid4().hex[:8]
    PROJECTS[pid] = {"id": pid, "name": name, **result}
    return _summary(PROJECTS[pid])


def _summary(p: dict) -> dict:
    return {"id": p["id"], "name": p["name"], "stats": p["stats"],
            "findings": [f.model_dump() for f in p["findings"]],
            "suppressed": p["suppressed"]}


SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "shoplab.har"


@app.post("/api/demo")
async def demo():
    """Analyze the bundled ShopLab sample (fake practice data) so the UI can be tried instantly."""
    if not SAMPLE.exists():
        raise HTTPException(404, "sample missing: run python eval/make_sample.py")
    result = await analyze(SAMPLE.read_text(), SAMPLE.name, llm, retriever)
    pid = uuid.uuid4().hex[:8]
    PROJECTS[pid] = {"id": pid, "name": "ShopLab demo", **result}
    return _summary(PROJECTS[pid])


@app.get("/api/projects/{pid}")
def get_project(pid: str):
    return _summary(_project(pid))


@app.get("/api/projects/{pid}/exchanges/{eid}")
def get_exchange(pid: str, eid: int):
    ex = next((e for e in _project(pid)["exchanges"] if e.id == eid), None)
    if not ex:
        raise HTTPException(404, "exchange not found")
    return {"id": ex.id, "url": ex.url, "request": redact(ex.request_text())[:20000],
            "response": redact(ex.response_text())[:20000]}


@app.patch("/api/projects/{pid}/findings/{fid}")
def update_finding(pid: str, fid: str, upd: FindingUpdate):
    p = _project(pid)
    for i, f in enumerate(p["findings"]):
        if f.id == fid:
            p["findings"][i] = f.model_copy(update=upd.model_dump(exclude_none=True))
            return p["findings"][i].model_dump()
    raise HTTPException(404, "finding not found")


@app.get("/api/projects/{pid}/report", response_class=PlainTextResponse)
def report(pid: str, include_pending: bool = False):
    return build_report(_project(pid), retriever, include_pending)


@app.delete("/api/projects/{pid}")
def delete_project(pid: str):
    PROJECTS.pop(pid, None)
    return {"deleted": pid}


DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if DIST.exists():
    app.mount("/", StaticFiles(directory=DIST, html=True), name="ui")

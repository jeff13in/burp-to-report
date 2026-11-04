"""End-to-end pipeline: export file -> findings."""
from __future__ import annotations

import time

from .detectors import run_detectors
from .filters import clean
from .llm import LLMClient
from .parsers import parse_export
from .rag import Retriever
from .triage import Triage

HEURISTIC_ONLY_MIN_SCORE = 0.3


async def analyze(data: str, filename: str, llm: LLMClient, retriever: Retriever,
                  scope: list[str] | None = None) -> dict:
    t0 = time.perf_counter()
    exchanges = parse_export(data, filename)
    kept, stats = clean(exchanges, scope)
    signals = run_detectors(kept)
    if not llm.enabled:
        # Without a model to filter weak signals, only keep the stronger heuristics.
        weak = [s for s in signals if s.score < HEURISTIC_ONLY_MIN_SCORE]
        signals = [s for s in signals if s.score >= HEURISTIC_ONLY_MIN_SCORE]
        stats["below_threshold"] = len(weak)
    findings, suppressed = await Triage(llm, retriever).run(signals, kept)
    stats.update({
        "signals": len(signals),
        "findings": len(findings),
        "suppressed_by_model": len(suppressed),
        "seconds": round(time.perf_counter() - t0, 2),
        "mode": llm.cfg.mode,
        "model": llm.cfg.model if llm.enabled else None,
    })
    return {"exchanges": kept, "findings": findings, "suppressed": suppressed, "stats": stats}

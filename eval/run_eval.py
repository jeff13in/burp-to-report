"""Score the pipeline against planted bugs.

    python eval/run_eval.py                 # heuristic-only (no API key needed)
    META_API_KEY=... python eval/run_eval.py   # with Muse Spark triage
    B2R_MODE=local LLM_MODEL=llama3.1:8b python eval/run_eval.py

A finding is a true positive if its class matches a planted issue and one of its exchanges
hits the planted path. Anything else in the report is a false positive.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.llm import LLMClient  # noqa: E402
from app.pipeline import analyze  # noqa: E402
from app.rag import Retriever  # noqa: E402


def match(finding, exchanges_by_id, truth) -> str | None:
    for t in truth:
        if finding.vuln_class.value != t["vuln_class"]:
            continue
        for eid in finding.exchange_ids:
            ex = exchanges_by_id.get(eid)
            if ex and ex.path == t["path"] and t.get("query_contains", "") in ex.query:
                return t["id"]
    return None


async def main(sample: Path, truth_path: Path) -> dict:
    truth = json.loads(truth_path.read_text())
    llm = LLMClient()
    result = await analyze(sample.read_text(), sample.name, llm, Retriever.from_dir())
    by_id = {e.id: e for e in result["exchanges"]}

    hit, fps = set(), []
    for f in result["findings"]:
        m = match(f, by_id, truth)
        if m:
            hit.add(m)
        else:
            fps.append(f"{f.vuln_class.value} {f.endpoint}")
    tp = len(hit)
    precision = tp / (tp + len(fps)) if (tp + len(fps)) else 0.0
    recall = tp / len(truth)
    summary = {
        "mode": result["stats"]["mode"], "model": result["stats"]["model"],
        "planted": len(truth), "found": tp, "false_positives": len(fps),
        "precision": round(precision, 2), "recall": round(recall, 2),
        "missed": sorted({t["id"] for t in truth} - hit), "fp_detail": fps,
        "suppressed_by_model": result["stats"]["suppressed_by_model"],
        "noise_filtered": {k: result["stats"][k] for k in ("total", "static", "duplicate", "kept")},
        "seconds": result["stats"]["seconds"],
    }
    return summary


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", type=Path, default=ROOT / "samples" / "shoplab.har")
    ap.add_argument("--truth", type=Path, default=ROOT / "samples" / "shoplab_truth.json")
    args = ap.parse_args()
    print(json.dumps(asyncio.run(main(args.sample, args.truth)), indent=2))

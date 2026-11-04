"""Small BM25 retriever over the local reference knowledge base.

No embedding service or vector DB is needed, so the tool works fully offline.
Each document has a stable id (its file name) that the model must cite.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

KB_DIR = Path(__file__).parent / "kb"
TOKEN = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return TOKEN.findall(text.lower())


@dataclass
class Doc:
    id: str
    title: str
    text: str


class Retriever:
    def __init__(self, docs: list[Doc], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.k1, self.b = k1, b
        self.tfs = [Counter(tokenize(d.title + " " + d.text)) for d in docs]
        self.lens = [sum(tf.values()) for tf in self.tfs]
        self.avg = sum(self.lens) / max(len(self.lens), 1)
        df: Counter = Counter()
        for tf in self.tfs:
            df.update(tf.keys())
        n = len(docs)
        self.idf = {t: math.log(1 + (n - c + 0.5) / (c + 0.5)) for t, c in df.items()}

    @classmethod
    def from_dir(cls, path: Path = KB_DIR) -> "Retriever":
        docs = []
        for f in sorted(path.glob("*.md")):
            text = f.read_text(encoding="utf-8")
            title = text.splitlines()[0].lstrip("# ").strip()
            docs.append(Doc(id=f.stem, title=title, text=text))
        return cls(docs)

    def search(self, query: str, k: int = 3) -> list[Doc]:
        q = tokenize(query)
        scores = []
        for i, tf in enumerate(self.tfs):
            s = 0.0
            for t in q:
                if t not in tf:
                    continue
                f = tf[t]
                s += self.idf[t] * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.lens[i] / self.avg))
            scores.append((s, i))
        scores.sort(reverse=True)
        return [self.docs[i] for s, i in scores[:k] if s > 0]

    def get(self, doc_id: str) -> Doc | None:
        return next((d for d in self.docs if d.id == doc_id), None)

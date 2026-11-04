"""Core data models shared across the pipeline."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class HttpExchange(BaseModel):
    """One request/response pair from a Burp or HAR export."""

    id: int
    method: str
    url: str
    host: str
    path: str
    query: str = ""
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str = ""
    status: int = 0
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body: str = ""
    mime: str = ""

    def header(self, name: str, *, response: bool = True) -> Optional[str]:
        headers = self.response_headers if response else self.request_headers
        for k, v in headers.items():
            if k.lower() == name.lower():
                return v
        return None

    def request_text(self) -> str:
        head = f"{self.method} {self.path}{'?' + self.query if self.query else ''} HTTP/1.1\n"
        head += "\n".join(f"{k}: {v}" for k, v in self.request_headers.items())
        return head + ("\n\n" + self.request_body if self.request_body else "")

    def response_text(self) -> str:
        head = f"HTTP/1.1 {self.status}\n"
        head += "\n".join(f"{k}: {v}" for k, v in self.response_headers.items())
        return head + ("\n\n" + self.response_body if self.response_body else "")


class VulnClass(str, Enum):
    IDOR = "idor"
    MISSING_AUTH = "missing_authorization"
    REFLECTED_INPUT = "reflected_input"
    VERBOSE_ERROR = "verbose_error"
    SENSITIVE_DATA = "sensitive_data_exposure"
    CORS = "cors_misconfiguration"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class Signal(BaseModel):
    """A heuristic hit: cheap, high-recall, needs model review."""

    vuln_class: VulnClass
    exchange_ids: list[int]
    reason: str
    evidence: list[str] = Field(default_factory=list)  # literal snippets from the traffic
    score: float = 0.5


class Finding(BaseModel):
    id: str
    vuln_class: VulnClass
    title: str
    severity: Severity
    confidence: float
    endpoint: str
    exchange_ids: list[int]
    rationale: str
    evidence: list[str]
    references: list[str] = Field(default_factory=list)  # KB doc ids
    remediation: str = ""
    triaged_by: str = "heuristic"  # "heuristic" | model name
    validation_notes: list[str] = Field(default_factory=list)
    status: Status = Status.PENDING
    tester_notes: str = ""


class FindingUpdate(BaseModel):
    status: Optional[Status] = None
    title: Optional[str] = None
    severity: Optional[Severity] = None
    rationale: Optional[str] = None
    remediation: Optional[str] = None
    tester_notes: Optional[str] = None

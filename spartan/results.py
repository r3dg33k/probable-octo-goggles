from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanResult:
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_length: int = 0
    content_type: str = ""
    title: str = ""
    redirect_url: str = ""
    response_hash: str = ""
    elapsed_ms: float = 0.0
    detector: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    is_friendly_404: bool = False
    dummy_size: int = 0

    @property
    def is_success(self) -> bool:
        return self.status_code == 200 and not self.is_friendly_404

    @property
    def is_interesting(self) -> bool:
        if self.status_code in (200, 201, 202, 203, 204, 205, 206):
            return not self.is_friendly_404
        if self.status_code in (301, 302, 303, 307, 308):
            return bool(self.redirect_url)
        if self.status_code in (401, 403, 500):
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_type": self.content_type,
            "title": self.title,
            "redirect_url": self.redirect_url,
            "response_hash": self.response_hash,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "detector": self.detector,
            "evidence": self.evidence,
            "error": self.error,
            "is_friendly_404": self.is_friendly_404,
        }


@dataclass
class Finding:
    id: str = ""
    title: str = ""
    severity: str = "info"
    confidence: str = "tentative"
    url: str = ""
    evidence: str = ""
    recommendation: str = ""
    detector: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "url": self.url,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "detector": self.detector,
            "timestamp": self.timestamp,
        }

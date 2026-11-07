from abc import ABC, abstractmethod
from typing import List, Optional
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class BaseRule(ABC):
    rule_id: str
    name: str
    category: str
    default_severity: SeverityEnum
    default_confidence: ConfidenceEnum
    
    @abstractmethod
    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        """Analyzes Solidity source code and returns detected findings."""
        pass

    def extract_snippet(self, source_code: str, line_start: int, line_end: int) -> str:
        lines = source_code.splitlines()
        start = max(0, line_start - 1)
        end = min(len(lines), line_end)
        return "\n".join(lines[start:end])

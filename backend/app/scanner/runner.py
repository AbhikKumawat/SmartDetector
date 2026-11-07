import time
import uuid
from typing import List
from backend.app.models.scan import (
    ScanRequest, 
    ScanResponse, 
    ScanSummary, 
    Finding, 
    SeverityEnum,
    ConfidenceEnum
)
from backend.app.scanner.custom_engine import CustomRuleEngine
from backend.app.scanner.slither_engine import SlitherEngine

class ScanOrchestrator:
    def __init__(self):
        self.custom_engine = CustomRuleEngine()
        self.slither_engine = SlitherEngine()

    def run_scan(self, request: ScanRequest) -> ScanResponse:
        start_time = time.perf_counter()
        findings: List[Finding] = []
        slither_ok = False

        source = request.source_code or ""
        filename = request.filename or "Contract.sol"

        # 1. Run Custom Sentinel Rules
        if request.enable_custom_rules and source:
            custom_findings = self.custom_engine.scan(source, filename)
            findings.extend(custom_findings)

        # 2. Run Slither if requested
        if request.enable_slither and source:
            slither_findings, slither_ok = self.slither_engine.scan_source(source, filename)
            # Deduplicate or append Slither findings
            findings = self._merge_findings(findings, slither_findings)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Calculate counts
        crit = sum(1 for f in findings if f.severity == SeverityEnum.CRITICAL)
        high = sum(1 for f in findings if f.severity == SeverityEnum.HIGH)
        med = sum(1 for f in findings if f.severity == SeverityEnum.MEDIUM)
        low = sum(1 for f in findings if f.severity == SeverityEnum.LOW)
        info = sum(1 for f in findings if f.severity == SeverityEnum.INFORMATIONAL)

        # Calculate transparent security score (deductions)
        # Note: Disclaimers make clear this is an automated heuristic metric, not absolute proof of safety
        score = 100.0 - (crit * 30.0 + high * 15.0 + med * 7.0 + low * 2.0)
        score = max(0.0, min(100.0, score))

        summary = ScanSummary(
            total_findings=len(findings),
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            security_score=round(score, 1),
            execution_time_ms=round(elapsed_ms, 2),
            slither_available=self.slither_engine.is_available
        )

        return ScanResponse(
            scan_id=str(uuid.uuid4()),
            target_name=filename,
            summary=summary,
            findings=findings
        )

    def _merge_findings(self, base_findings: List[Finding], new_findings: List[Finding]) -> List[Finding]:
        merged = list(base_findings)
        for nf in new_findings:
            # Check for substantial duplicate by category and line range
            duplicate = False
            for bf in base_findings:
                if bf.category == nf.category and abs(bf.line_start - nf.line_start) <= 2:
                    duplicate = True
                    break
            if not duplicate:
                merged.append(nf)
        return merged

scanner = ScanOrchestrator()

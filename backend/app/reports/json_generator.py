import json
from datetime import datetime
from typing import Dict, Any
from backend.app.models.scan import ScanResponse

def generate_audit_json(scan_response: ScanResponse, lab_results: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Generates a structured, industry-standard JSON audit report.
    """
    findings_list = []
    for f in scan_response.findings:
        findings_list.append({
            "id": f.id,
            "title": f.name,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "category": f.category,
            "location": {
                "file": f.file_path,
                "contract": f.contract_name,
                "function": f.function_name,
                "line_start": f.line_start,
                "line_end": f.line_end
            },
            "description": f.description,
            "impact": f.impact,
            "reproduction": f.reproduction,
            "remediation": f.remediation,
            "code_snippet": f.code_snippet,
            "tool": f.tool
        })

    report = {
        "report_metadata": {
            "platform": "Web3 Sentinel - Smart Contract Security Analysis",
            "version": "1.0.0",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "scan_id": scan_response.scan_id,
            "target": scan_response.target_name
        },
        "executive_summary": {
            "security_score": scan_response.summary.security_score,
            "risk_level": "CRITICAL" if scan_response.summary.critical_count > 0 else (
                "HIGH" if scan_response.summary.high_count > 0 else (
                    "MEDIUM" if scan_response.summary.medium_count > 0 else "LOW"
                )
            ),
            "findings_count": {
                "total": scan_response.summary.total_findings,
                "critical": scan_response.summary.critical_count,
                "high": scan_response.summary.high_count,
                "medium": scan_response.summary.medium_count,
                "low": scan_response.summary.low_count,
                "informational": scan_response.summary.info_count
            },
            "execution_time_ms": scan_response.summary.execution_time_ms
        },
        "methodology": {
            "static_analysis": "Slither static analysis framework + Sentinel Custom AST heuristic rules",
            "controlled_reproduction": "Foundry local sandbox environment (forge test -vvvv)",
            "compliance_standards": ["SWC Registry", "OpenZeppelin Security Guidelines", "ConsenSys Best Practices"]
        },
        "findings": findings_list,
        "controlled_lab_results": lab_results or {},
        "disclaimer": (
            "This automated security analysis and audit report does not guarantee or provide any warranty "
            "regarding the complete safety, correctness, or exploit-free nature of the smart contracts analyzed. "
            "A comprehensive manual audit and multi-faceted formal verification is strongly advised prior to production deployment."
        )
    }

    return report

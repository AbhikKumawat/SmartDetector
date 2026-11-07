import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class TxOriginRule(BaseRule):
    rule_id = "SENTINEL-004"
    name = "tx.origin Authentication Misuse"
    category = "Authentication / Phishing"
    default_severity = SeverityEnum.HIGH
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        tx_origin_pattern = re.compile(r"\b(require|if|assert)\s*\(.*?\btx\.origin\s*==.*?\)")

        for idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            if trimmed.startswith("//") or trimmed.startswith("*"):
                continue

            if tx_origin_pattern.search(line):
                snippet = self.extract_snippet(source_code, max(1, idx - 1), min(len(lines), idx + 1))
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        name="Phishing Vector via tx.origin Authorization",
                        severity=SeverityEnum.HIGH,
                        confidence=ConfidenceEnum.CONFIRMED,
                        category="Authentication / Phishing",
                        contract_name="DetectedContract",
                        function_name="Authorization Scope",
                        file_path=filename,
                        line_start=idx,
                        line_end=idx,
                        description=(
                            f"At line {idx}, `tx.origin` is used for access control. Unlike `msg.sender`, "
                            "`tx.origin` references the original external account initiating the transaction."
                        ),
                        impact=(
                            "Vulnerable to phishing attacks: if the owner is lured into executing a transaction "
                            "on an intermediary malicious contract, that contract can impersonate the owner and drain assets."
                        ),
                        reproduction=(
                            "1. Attacker deploys a phishing contract pointing to this vulnerable contract.\n"
                            "2. Owner is tricked into calling the phishing contract.\n"
                            "3. Phishing contract calls this contract; tx.origin matches owner, allowing unauthorized transfer."
                        ),
                        remediation="Replace `tx.origin` with `msg.sender` for all authentication and access control logic.",
                        code_snippet=snippet,
                        tool="Web3 Sentinel Static Analyzer"
                    )
                )

        return findings

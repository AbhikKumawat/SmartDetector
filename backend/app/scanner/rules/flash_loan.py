import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class FlashLoanRule(BaseRule):
    rule_id = "SENTINEL-009"
    name = "Flash Loan Attack Surface / Callback Verification"
    category = "Flash Loan Risks"
    default_severity = SeverityEnum.HIGH
    default_confidence = ConfidenceEnum.POTENTIAL

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        callback_regex = re.compile(r"function\s+(executeOperation|onFlashLoan|uniswapV2Call|uniswapV3FlashCallback|pancakeCall)\s*\(")

        for idx, line in enumerate(lines, 1):
            match = callback_regex.search(line)
            if match:
                cb_name = match.group(1)
                
                # Check if caller verification is performed in body
                has_initiator_check = False
                for lookahead in range(idx, min(len(lines), idx + 20)):
                    l = lines[lookahead]
                    if re.search(r"\b(require|if)\s*\(.*?\b(msg\.sender\s*==\s*pool|initiator|lendingPool)\b", l):
                        has_initiator_check = True
                        break

                if not has_initiator_check:
                    snippet = self.extract_snippet(source_code, idx, min(len(lines), idx + 5))
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            name=f"Unverified Flash Loan Callback ({cb_name})",
                            severity=SeverityEnum.HIGH,
                            confidence=ConfidenceEnum.POTENTIAL,
                            category="Flash Loan Risks",
                            contract_name="DetectedContract",
                            function_name=cb_name,
                            file_path=filename,
                            line_start=idx,
                            line_end=min(len(lines), idx + 5),
                            description=(
                                f"At line {idx}, flash loan receiver callback `{cb_name}` does not verify that `msg.sender` "
                                "matches the legitimate lending pool or that initiator equals `address(this)`."
                            ),
                            impact="An attacker can directly invoke the callback to force arbitrary state operations or steal allowances.",
                            reproduction="Call the callback directly without going through the lending pool.",
                            remediation="Verify `msg.sender == address(lendingPool)` and assert `initiator == address(this)`.",
                            code_snippet=snippet,
                            tool="Web3 Sentinel Heuristic Analyzer"
                        )
                    )

        return findings

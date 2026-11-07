import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class DelegatecallRule(BaseRule):
    rule_id = "SENTINEL-008"
    name = "Dangerous Delegatecall Execution"
    category = "Delegatecall Risks"
    default_severity = SeverityEnum.CRITICAL
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        delegatecall_regex = re.compile(r"(\w+)\.delegatecall\s*\((.*?)\)")

        for idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            if trimmed.startswith("//") or trimmed.startswith("*"):
                continue

            match = delegatecall_regex.search(line)
            if match:
                target_var = match.group(1)
                
                # Check if target is a parameter in the function
                is_param = False
                for back_idx in range(idx - 1, max(0, idx - 15), -1):
                    back_line = lines[back_idx]
                    if "function " in back_line:
                        if target_var in back_line:
                            is_param = True
                        break

                snippet = self.extract_snippet(source_code, max(1, idx - 2), min(len(lines), idx + 2))
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        name="Controlled Delegatecall Target" if is_param else "Delegatecall Context Hijacking Risk",
                        severity=SeverityEnum.CRITICAL if is_param else SeverityEnum.HIGH,
                        confidence=ConfidenceEnum.CONFIRMED,
                        category="Delegatecall Risks",
                        contract_name="DetectedContract",
                        function_name="Proxy / Forwarder",
                        file_path=filename,
                        line_start=idx,
                        line_end=idx,
                        description=(
                            f"At line {idx}, `.delegatecall` is executed on `{target_var}`. "
                            f"{'The target is user-controlled via function parameters!' if is_param else 'Code executes in caller context.'} "
                            "Delegatecall preserves storage context, meaning the called logic can overwrite any state variable."
                        ),
                        impact="Complete takeover of contract state, storage slot collision, and loss of contract ownership or funds.",
                        reproduction="Deploy an exploit contract with state layout designed to overwrite slot 0, then forward call.",
                        remediation=(
                            "Never permit user-supplied target addresses in `delegatecall`. Use fixed immutable implementation "
                            "addresses and adhere to ERC-1967 structured storage slots for proxies."
                        ),
                        code_snippet=snippet,
                        tool="Web3 Sentinel Heuristic Analyzer"
                    )
                )

        return findings

import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class SelfdestructRule(BaseRule):
    rule_id = "SENTINEL-007"
    name = "Unprotected or Deprecated Self-Destruct Operation"
    category = "Contract Destruction"
    default_severity = SeverityEnum.CRITICAL
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        selfdestruct_regex = re.compile(r"\b(selfdestruct|suicide)\s*\((.*?)\)")

        for idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            if trimmed.startswith("//") or trimmed.startswith("*"):
                continue

            match = selfdestruct_regex.search(line)
            if match:
                # Check if enclosing function has onlyOwner
                # Scan backwards up to 15 lines to locate enclosing function signature
                has_auth = False
                for back_idx in range(idx - 1, max(0, idx - 15), -1):
                    back_line = lines[back_idx]
                    if "function " in back_line:
                        if re.search(r"\b(onlyOwner|onlyAdmin|onlyRole|_checkOwner)\b", back_line):
                            has_auth = True
                        break

                severity = SeverityEnum.MEDIUM if has_auth else SeverityEnum.CRITICAL
                confidence = ConfidenceEnum.CONFIRMED
                desc = (
                    f"At line {idx}, `{match.group(1)}` is executed. " +
                    ("However, the function lacks access controls, allowing ANY caller to terminate the contract." 
                     if not has_auth else 
                     "Note that `selfdestruct` behavior is deprecated and fundamentally altered post-Dencun (EIP-6780).")
                )

                snippet = self.extract_snippet(source_code, max(1, idx - 2), min(len(lines), idx + 2))
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        name="Unprotected Self-Destruct" if not has_auth else "Deprecated Self-Destruct Opcode (EIP-6780)",
                        severity=severity,
                        confidence=confidence,
                        category="Contract Destruction",
                        contract_name="DetectedContract",
                        function_name="Kill Function",
                        file_path=filename,
                        line_start=idx,
                        line_end=idx,
                        description=desc,
                        impact="Permanent contract bricking and theft or freezing of all contract ether balance.",
                        reproduction="Invoke the function directly from an external wallet and observe contract destruction.",
                        remediation="Remove `selfdestruct` completely. Use OpenZeppelin's Pausable and standard withdrawal patterns instead.",
                        code_snippet=snippet,
                        tool="Web3 Sentinel Static Analyzer"
                    )
                )

        return findings

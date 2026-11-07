import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class UncheckedCallRule(BaseRule):
    rule_id = "SENTINEL-003"
    name = "Unchecked Low-Level External Call"
    category = "Unchecked Calls"
    default_severity = SeverityEnum.HIGH
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        for idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            if trimmed.startswith("//") or trimmed.startswith("*"):
                continue

            # Case 1: Raw call/send without assignment (e.g. `recipient.call{value: amount}("");`)
            match_raw_call = re.search(r"(?<![=a-zA-Z0-9_])\b(\w+)\.(call|send|delegatecall)\s*[\(\{]", line)
            if match_raw_call:
                # Ensure it's not part of an assignment like `(bool s, ) = ...`
                if not re.search(r"=\s*.*?\b(call|send|delegatecall)", line):
                    snippet = self.extract_snippet(source_code, max(1, idx - 1), min(len(lines), idx + 1))
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            name="Unchecked Low-Level Call Return Value",
                            severity=SeverityEnum.HIGH,
                            confidence=ConfidenceEnum.CONFIRMED,
                            category="Unchecked Calls",
                            contract_name="DetectedContract",
                            function_name="Function Scope",
                            file_path=filename,
                            line_start=idx,
                            line_end=idx,
                            description=(
                                f"At line {idx}, low-level operation `.{match_raw_call.group(2)}` is executed without capturing "
                                "or verifying its return status. Low-level calls do not bubble up reverts automatically."
                            ),
                            impact="Silently failed transactions can lead to inconsistent accounting and locked assets.",
                            reproduction=(
                                "1. Call target with a contract recipient that reverts on receive or consumes excessive gas.\n"
                                "2. Observe that execution continues despite failure."
                            ),
                            remediation=(
                                "Always capture the boolean return value: `(bool success, ) = target.call(...)` "
                                "and assert `require(success, 'Call failed');` or `if (!success) revert CallFailed();`."
                            ),
                            code_snippet=snippet,
                            tool="Web3 Sentinel Heuristic Analyzer"
                        )
                    )
                    continue

            # Case 2: Assigned boolean variable that is never checked in subsequent lines
            match_assign = re.search(r"\(\s*bool\s+(\w+)\s*,?\s*.*?\)\s*=\s*.*?\.call", line)
            if match_assign:
                var_name = match_assign.group(1)
                # Look ahead 3 lines to see if require(var_name) or if (!var_name) exists
                checked = False
                for future_idx in range(idx, min(len(lines), idx + 4)):
                    future_line = lines[future_idx]
                    if re.search(rf"\b(require|if|assert)\s*\(.*?\b{var_name}\b", future_line):
                        checked = True
                        break

                if not checked:
                    snippet = self.extract_snippet(source_code, idx, min(len(lines), idx + 2))
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            name="Unchecked Low-Level Call Result (Assigned but Unverified)",
                            severity=SeverityEnum.HIGH,
                            confidence=ConfidenceEnum.CONFIRMED,
                            category="Unchecked Calls",
                            contract_name="DetectedContract",
                            function_name="Function Scope",
                            file_path=filename,
                            line_start=idx,
                            line_end=min(len(lines), idx + 2),
                            description=(
                                f"At line {idx}, return value `{var_name}` is captured from `.call` "
                                "but is never checked with `require()` or `if (!success)` in subsequent instructions."
                            ),
                            impact="The function continues execution even if the external transfer reverted.",
                            reproduction="Target an intentionally reverting contract and observe ignored failure.",
                            remediation=f"Validate `{var_name}` immediately: `require({var_name}, 'Transfer failed');`",
                            code_snippet=snippet,
                            tool="Web3 Sentinel Heuristic Analyzer"
                        )
                    )

        return findings

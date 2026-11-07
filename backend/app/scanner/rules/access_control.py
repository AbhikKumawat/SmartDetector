import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class AccessControlRule(BaseRule):
    rule_id = "SENTINEL-002"
    name = "Missing or Improper Access Control"
    category = "Access Control"
    default_severity = SeverityEnum.CRITICAL
    default_confidence = ConfidenceEnum.CONFIRMED

    SENSITIVE_FUNC_NAMES = {
        "setowner", "changeowner", "initowner", "transferownership",
        "withdrawall", "drain", "setadmin", "kill", "destruct"
    }

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        func_regex = re.compile(r"function\s+(\w+)\s*\((.*?)\)\s*([^{]*)\{")
        auth_patterns = re.compile(r"\b(onlyOwner|onlyRole|onlyAdmin|_checkOwner|auth)\b")

        for idx, line in enumerate(lines, 1):
            match = func_regex.search(line)
            if match:
                func_name = match.group(1)
                modifiers = match.group(3)

                is_public_or_external = "public" in modifiers or "external" in modifiers
                has_auth = bool(auth_patterns.search(modifiers))

                # Check if sensitive function is exposed without modifiers
                if is_public_or_external and not has_auth:
                    lower_name = func_name.lower()
                    if lower_name in self.SENSITIVE_FUNC_NAMES:
                        # Inspect function body for inline require(msg.sender == owner)
                        body_has_auth = False
                        brace_count = line.count("{") - line.count("}")
                        lookahead_lines = 1
                        while brace_count > 0 and (idx - 1 + lookahead_lines) < len(lines):
                            curr = lines[idx - 1 + lookahead_lines]
                            if re.search(r"require\s*\(\s*(msg\.sender|owner)\s*==\s*(owner|msg\.sender)", curr):
                                body_has_auth = True
                                break
                            brace_count += curr.count("{") - curr.count("}")
                            lookahead_lines += 1

                        if not body_has_auth:
                            snippet = self.extract_snippet(source_code, idx, min(len(lines), idx + lookahead_lines))
                            findings.append(
                                Finding(
                                    id=str(uuid.uuid4()),
                                    name="Unprotected Privileged Function (Missing Access Control)",
                                    severity=SeverityEnum.CRITICAL,
                                    confidence=ConfidenceEnum.CONFIRMED,
                                    category="Access Control",
                                    contract_name="DetectedContract",
                                    function_name=func_name,
                                    file_path=filename,
                                    line_start=idx,
                                    line_end=idx + min(lookahead_lines, 5),
                                    description=(
                                        f"The function '{func_name}' is declared public or external but does not enforce "
                                        "any authorization checks (missing `onlyOwner`, `onlyRole`, or `msg.sender == owner`)."
                                    ),
                                    impact="Any unauthorized user can invoke this function to hijack ownership or drain assets.",
                                    reproduction=(
                                        f"1. Connect with an unprivileged external address.\n"
                                        f"2. Call '{func_name}()' passing the attacker's address.\n"
                                        "3. Observe unrestricted state alteration."
                                    ),
                                    remediation=(
                                        "Implement OpenZeppelin's `Ownable` or `AccessControl` and add the `onlyOwner` modifier "
                                        "or custom check to restrict caller permissions."
                                    ),
                                    code_snippet=snippet,
                                    tool="Web3 Sentinel Heuristic Analyzer"
                                )
                            )
        return findings

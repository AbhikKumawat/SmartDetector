import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class ReentrancyRule(BaseRule):
    rule_id = "SENTINEL-001"
    name = "Reentrancy Vulnerability (Checks-Effects-Interactions Violation)"
    category = "Reentrancy"
    default_severity = SeverityEnum.CRITICAL
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        # Regular expressions
        func_start_regex = re.compile(r"function\s+(\w+)\s*\((.*?)\)\s*([^{]*)\{")
        external_call_regex = re.compile(r"(\.call\{value:|\.call\.value|\.send\(|\.transfer\()")
        state_write_regex = re.compile(r"(\w+\[[^\]]+\]\s*=|balances\[|\b\w+\s*=\s*0|\b\w+\s*-=)")

        current_func = None
        func_start_line = 0
        call_line = 0
        has_nonreentrant = False
        in_function = False
        brace_depth = 0

        for idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            
            # Check for function start
            match_func = func_start_regex.search(line)
            if match_func:
                current_func = match_func.group(1)
                func_start_line = idx
                in_function = True
                brace_depth = line.count("{") - line.count("}")
                modifiers = match_func.group(3)
                has_nonreentrant = "nonReentrant" in modifiers
                call_line = 0
                continue

            if in_function:
                brace_depth += line.count("{") - line.count("}")
                
                # Check for external call
                if external_call_regex.search(line):
                    call_line = idx

                # Check for subsequent state write after external call (Violation of CEI)
                if call_line > 0 and idx > call_line and not has_nonreentrant:
                    if state_write_regex.search(line):
                        snippet = self.extract_snippet(source_code, call_line, idx)
                        findings.append(
                            Finding(
                                id=str(uuid.uuid4()),
                                name="Reentrancy via Checks-Effects-Interactions Violation",
                                severity=SeverityEnum.CRITICAL,
                                confidence=ConfidenceEnum.CONFIRMED,
                                category="Reentrancy",
                                contract_name="DetectedContract",
                                function_name=current_func or "unknown",
                                file_path=filename,
                                line_start=call_line,
                                line_end=idx,
                                description=(
                                    f"In function '{current_func}', an external low-level call sends Ether "
                                    f"at line {call_line} before state variables are updated at line {idx}. "
                                    "A malicious receiver can recursively invoke this function before the state update occurs."
                                ),
                                impact="Complete drainage of contract funds through recursive external calls.",
                                reproduction=(
                                    "1. Deploy an attacking contract with a receive() callback that calls the vulnerable function.\n"
                                    "2. Deposit minimal funds.\n"
                                    "3. Call the withdraw function to trigger recursive execution until contract balance reaches zero."
                                ),
                                remediation=(
                                    "1. Apply the Checks-Effects-Interactions (CEI) pattern: update state variables before making external calls.\n"
                                    "2. Inherit OpenZeppelin's ReentrancyGuard and decorate the function with `nonReentrant`."
                                ),
                                code_snippet=snippet,
                                tool="Web3 Sentinel Heuristic Analyzer"
                            )
                        )
                        call_line = 0  # Avoid duplicate triggers for same function

                if brace_depth <= 0:
                    in_function = False
                    current_func = None
                    call_line = 0

        return findings

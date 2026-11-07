import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class IntegerOverflowRule(BaseRule):
    rule_id = "SENTINEL-006"
    name = "Integer Overflow / Underflow"
    category = "Arithmetic Flaws"
    default_severity = SeverityEnum.HIGH
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        # Check for legacy compiler version (<0.8.0)
        pragma_match = re.search(r"pragma\s+solidity\s+([^;]+);", source_code)
        if pragma_match:
            version_str = pragma_match.group(1).strip()
            # If version is explicitly 0.4.x, 0.5.x, 0.6.x, 0.7.x
            if re.search(r"0\.[4567]\.", version_str):
                has_safemath = "SafeMath" in source_code
                if not has_safemath:
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            name="Legacy Solidity Compiler with Unchecked Arithmetic",
                            severity=SeverityEnum.HIGH,
                            confidence=ConfidenceEnum.CONFIRMED,
                            category="Arithmetic Flaws",
                            contract_name="DetectedContract",
                            function_name="Global",
                            file_path=filename,
                            line_start=1,
                            line_end=1,
                            description=(
                                f"Solidity version '{version_str}' lacks default overflow/underflow checks. "
                                "SafeMath library is not imported or used across arithmetic operations."
                            ),
                            impact="Arithmetic operations will silently wrap around 0 or 2^256 - 1, enabling balance manipulation.",
                            reproduction="Provide an input exceeding the numerical type boundary and observe silent wrapping.",
                            remediation="Upgrade to Solidity ^0.8.0 or explicitly integrate OpenZeppelin's SafeMath library.",
                            code_snippet=pragma_match.group(0),
                            tool="Web3 Sentinel Static Analyzer"
                        )
                    )

        # Check for dangerous unchecked blocks in Solidity 0.8+
        unchecked_regex = re.compile(r"\bunchecked\s*\{")
        in_unchecked = False
        unchecked_start = 0
        brace_depth = 0

        for idx, line in enumerate(lines, 1):
            if unchecked_regex.search(line):
                in_unchecked = True
                unchecked_start = idx
                brace_depth = line.count("{") - line.count("}")
                continue

            if in_unchecked:
                brace_depth += line.count("{") - line.count("}")
                # Look for subtraction or decrement inside unchecked block
                if re.search(r"(-=|\bbalances\[.*?\]\s*-)", line):
                    snippet = self.extract_snippet(source_code, unchecked_start, idx)
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            name="Unchecked Arithmetic Block Underflow Risk",
                            severity=SeverityEnum.HIGH,
                            confidence=ConfidenceEnum.POTENTIAL,
                            category="Arithmetic Flaws",
                            contract_name="DetectedContract",
                            function_name="Arithmetic Scope",
                            file_path=filename,
                            line_start=unchecked_start,
                            line_end=idx,
                            description=(
                                f"At line {idx}, arithmetic subtraction occurs inside an `unchecked` block. "
                                "If the subtracted value exceeds the minuend, unsigned underflow to 2^256 - 1 occurs."
                            ),
                            impact="State balances or counters can wrap around to maximum integer values.",
                            reproduction="Call function with transfer amount greater than balance.",
                            remediation="Ensure boundary check (`require(balance >= amount)`) precedes the subtraction or remove the `unchecked` block.",
                            code_snippet=snippet,
                            tool="Web3 Sentinel Heuristic Analyzer"
                        )
                    )
                    in_unchecked = False

                if brace_depth <= 0:
                    in_unchecked = False

        return findings

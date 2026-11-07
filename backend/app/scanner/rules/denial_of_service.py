import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class DenialOfServiceRule(BaseRule):
    rule_id = "SENTINEL-010"
    name = "Denial of Service via Unbounded Loop External Calls"
    category = "Denial of Service"
    default_severity = SeverityEnum.HIGH
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        for_loop_regex = re.compile(r"for\s*\([^;]*;\s*(\w+)\s*<\s*(\w+)\.length\s*;[^)]*\)")
        external_transfer_regex = re.compile(r"(\.call\{value:|\.transfer\(|\.send\()")

        in_loop = False
        loop_start_line = 0
        brace_depth = 0
        array_name = ""

        for idx, line in enumerate(lines, 1):
            match = for_loop_regex.search(line)
            if match:
                in_loop = True
                loop_start_line = idx
                array_name = match.group(2)
                brace_depth = line.count("{") - line.count("}")
                continue

            if in_loop:
                brace_depth += line.count("{") - line.count("}")
                
                # Check for external transfer inside loop
                if external_transfer_regex.search(line):
                    snippet = self.extract_snippet(source_code, loop_start_line, idx)
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            name="Denial of Service via External Call in Loop (Push Pattern)",
                            severity=SeverityEnum.HIGH,
                            confidence=ConfidenceEnum.CONFIRMED,
                            category="Denial of Service",
                            contract_name="DetectedContract",
                            function_name="Loop Distribution Scope",
                            file_path=filename,
                            line_start=loop_start_line,
                            line_end=idx,
                            description=(
                                f"At lines {loop_start_line}-{idx}, an unbounded loop over `{array_name}` pushes external "
                                "Ether transfers to individual recipients. If any single recipient is a smart contract that "
                                "reverts upon receiving Ether, the entire transaction reverts, permanently blocking execution."
                            ),
                            impact="Permanent freezing of funds, inability to distribute dividends or complete auctions (DoS).",
                            reproduction="Register a malicious contract address that reverts in receive(), then invoke distribution.",
                            remediation=(
                                "Adopt the Pull-Payment pattern: record pending balances in state and permit users to "
                                "withdraw their individual allocations via dedicated claim functions."
                            ),
                            code_snippet=snippet,
                            tool="Web3 Sentinel Heuristic Analyzer"
                        )
                    )
                    in_loop = False  # Avoid duplicate alerts for the same loop

                if brace_depth <= 0:
                    in_loop = False

        return findings

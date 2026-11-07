import re
import uuid
from typing import List
from backend.app.scanner.rules.base import BaseRule
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum

class OracleManipulationRule(BaseRule):
    rule_id = "SENTINEL-005"
    name = "Oracle Manipulation via Spot AMM Reserves"
    category = "Price Oracle / Flash Loan"
    default_severity = SeverityEnum.CRITICAL
    default_confidence = ConfidenceEnum.CONFIRMED

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        findings = []
        lines = source_code.splitlines()

        # Patterns indicating spot AMM pricing
        spot_reserves_regex = re.compile(r"(\.getReserves\(\)|\breserveToken\b|\breserveETH\b|balanceOf\(address\(pair\)\))")
        spot_price_calc = re.compile(r"(\breserveETH\s*\*\s*1e18\s*\/\s*reserveToken|\breserve[01]\s*\*\s*1e18\s*\/\s*reserve)")

        for idx, line in enumerate(lines, 1):
            trimmed = line.strip()
            if trimmed.startswith("//") or trimmed.startswith("*"):
                continue

            if spot_reserves_regex.search(line) or spot_price_calc.search(line):
                # Check whether TWAP or Chainlink feed is present in source
                has_safe_oracle = bool(re.search(r"\b(consult|observe|latestRoundData|IAggregatorV3)\b", source_code))
                
                if not has_safe_oracle:
                    snippet = self.extract_snippet(source_code, max(1, idx - 2), min(len(lines), idx + 2))
                    findings.append(
                        Finding(
                            id=str(uuid.uuid4()),
                            name="Vulnerable Spot Price Oracle (Flash Loan Susceptible)",
                            severity=SeverityEnum.CRITICAL,
                            confidence=ConfidenceEnum.CONFIRMED,
                            category="Price Oracle / Flash Loan",
                            contract_name="DetectedContract",
                            function_name="Pricing Function",
                            file_path=filename,
                            line_start=idx,
                            line_end=min(len(lines), idx + 2),
                            description=(
                                f"At line {idx}, asset valuation or collateral ratio relies on instantaneous spot reserves "
                                "from a DEX pair. Spot reserves can be skewed in a single atomic transaction."
                            ),
                            impact="Attackers can use flash loans to artificially distort the price, borrow funds undercollateralized, and drain protocol liquidity.",
                            reproduction=(
                                "1. Flash-borrow high liquidity from Aave/Uniswap.\n"
                                "2. Swap massive volume to skew the DEX pool reserve ratio.\n"
                                "3. Deposit minimal collateral into target protocol and borrow all available assets.\n"
                                "4. Re-swap to restore pool and repay flash loan with massive profit."
                            ),
                            remediation=(
                                "1. Use decentralized oracles (e.g., Chainlink Price Feeds) with heartbeat and round validation.\n"
                                "2. If AMM pricing is required, use Uniswap v3 TWAP (Time-Weighted Average Price) over a sufficiently long window (e.g. 30 mins)."
                            ),
                            code_snippet=snippet,
                            tool="Web3 Sentinel Heuristic Analyzer"
                        )
                    )
                    break  # Avoid reporting repeatedly for same pair lookup

        return findings

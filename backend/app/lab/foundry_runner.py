import re
import uuid
import time
from typing import Dict, Any, List, Tuple
from backend.app.config import settings
from backend.app.models.scan import ExploitLabRunRequest, ExploitLabRunResponse
from backend.app.security.safe_subprocess import run_sandboxed_command

LAB_MAP = {
    "reentrancy": {
        "title": "Reentrancy Exploit & Defense Lab",
        "vulnerable_test": "testExploitReentrancy",
        "patched_test": "testPatchedBankPreventsReentrancy",
        "contract_pair": ("src/reentrancy/VulnerableBank.sol", "src/reentrancy/PatchedBank.sol"),
        "test_file": "test/Reentrancy.t.sol",
        "explanation": (
            "VulnerableBank executes external ether transfer before zeroing out the sender's balance. "
            "ReentrancyAttacker catches the incoming payment in its receive() fallback and recursively invokes withdraw() "
            "until the contract balance reaches zero. The patched version incorporates Checks-Effects-Interactions and ReentrancyGuard."
        )
    },
    "access_control": {
        "title": "Improper Access Control Lab",
        "vulnerable_test": "testExploitMissingAccessControl",
        "patched_test": "testPatchedVaultPreventsUnauthorized",
        "contract_pair": ("src/access_control/VulnerableVault.sol", "src/access_control/PatchedVault.sol"),
        "test_file": "test/AccessControl.t.sol",
        "explanation": (
            "VulnerableVault exposes public setOwner() without authorization checks. An attacker claims ownership "
            "and drains 25 ETH. PatchedVault implements Ownable2Step and protects all withdrawals."
        )
    },
    "unchecked_calls": {
        "title": "Unchecked Low-Level External Call Lab",
        "vulnerable_test": "testExploitUncheckedCallSilentFailure",
        "patched_test": "testPatchedAuctionPullPattern",
        "contract_pair": ("src/unchecked_calls/VulnerableAuction.sol", "src/unchecked_calls/PatchedAuction.sol"),
        "test_file": "test/UncheckedCalls.t.sol",
        "explanation": (
            "VulnerableAuction attempts direct pushes of refunds without verifying call return values. "
            "A malicious reverting bidder traps ether inside the contract without stopping execution. "
            "PatchedAuction applies the Pull-Payment pattern so bidders claim refunds independently."
        )
    },
    "oracle_manipulation": {
        "title": "Spot AMM Oracle Manipulation Lab",
        "vulnerable_test": "testExploitSpotPriceManipulation",
        "patched_test": "testPatchedLendingRejectsManipulatedOrStaleFeed",
        "contract_pair": ("src/oracle_manipulation/VulnerableLending.sol", "src/oracle_manipulation/PatchedLending.sol"),
        "test_file": "test/OracleManipulation.t.sol",
        "explanation": (
            "VulnerableLending determines collateral value from single-block AMM spot reserves. "
            "An attacker manipulates the reserves to inflate collateral 100x and drains 50 ETH. "
            "PatchedLending validates price data using a Chainlink aggregator with freshness checks."
        )
    },
    "tx_origin": {
        "title": "tx.origin Phishing Exploit Lab",
        "vulnerable_test": "testExploitTxOriginPhishing",
        "patched_test": "testPatchedWalletPreventsPhishing",
        "contract_pair": ("src/tx_origin/VulnerableWallet.sol", "src/tx_origin/PatchedWallet.sol"),
        "test_file": "test/TxOrigin.t.sol",
        "explanation": (
            "VulnerableWallet uses tx.origin == owner. When the owner calls an innocent-looking attacker contract, "
            "the attacker contract forwards the call to the wallet. Because tx.origin is still the owner, "
            "10 ETH is stolen. PatchedWallet replaces tx.origin with msg.sender."
        )
    }
}

class FoundryLabRunner:
    def __init__(self):
        self.forge_path = settings.FORGE_PATH
        self.contracts_dir = settings.CONTRACTS_DIR

    def run_lab(self, request: ExploitLabRunRequest) -> ExploitLabRunResponse:
        lab_info = LAB_MAP.get(request.lab_id)
        if not lab_info:
            raise ValueError(f"Unknown lab identifier: '{request.lab_id}'. Available: {list(LAB_MAP.keys())}")

        target_test = (
            lab_info["vulnerable_test"] 
            if request.target_type == "vulnerable" 
            else lab_info["patched_test"]
        )

        # Run forge test --match-test <target_test> -vvvv
        cmd = [
            self.forge_path,
            "test",
            "--match-test",
            target_test,
            "-vvvv"
        ]

        start_time = time.perf_counter()
        code, stdout, stderr = run_sandboxed_command(
            cmd,
            cwd=str(self.contracts_dir),
            timeout=settings.SUBPROCESS_TIMEOUT_SECONDS
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        raw_output = stdout + "\n" + stderr
        passed = "[PASS]" in raw_output
        
        # Extract gas used
        gas_match = re.search(r"\(gas:\s*(\d+)\)", raw_output)
        gas_used = int(gas_match.group(1)) if gas_match else 0

        # Parse logs and traces
        logs, traces, parsed_steps = self._parse_traces_and_logs(raw_output)
        state_diff = self._extract_state_diff(logs, request.lab_id, request.target_type)

        return ExploitLabRunResponse(
            run_id=str(uuid.uuid4()),
            lab_id=request.lab_id,
            target_type=request.target_type,
            passed=passed,
            gas_used=gas_used,
            duration_ms=round(elapsed_ms, 2),
            raw_logs=logs,
            call_traces=traces,
            parsed_trace=parsed_steps,
            state_diff=state_diff,
            explanation=lab_info["explanation"]
        )

    def _parse_traces_and_logs(self, output: str) -> Tuple[List[str], List[str], List[Dict[str, Any]]]:
        lines = output.splitlines()
        logs: List[str] = []
        traces: List[str] = []
        parsed_steps: List[Dict[str, Any]] = []

        in_logs = False
        in_traces = False

        trace_step_regex = re.compile(r"\[(\d+)\]\s+(?:→\s+)?(\w+)::(\w+)(?:\{value:\s*(\d+)\})?\((.*?)\)")

        for line in lines:
            trimmed = line.strip()
            if trimmed.startswith("Logs:"):
                in_logs = True
                in_traces = False
                continue
            elif trimmed.startswith("Traces:"):
                in_traces = True
                in_logs = False
                continue
            elif trimmed.startswith("Suite result:") or trimmed.startswith("Ran 1 test"):
                in_logs = False
                in_traces = False

            if in_logs and trimmed:
                logs.append(trimmed)

            if in_traces and trimmed:
                traces.append(line)
                # Attempt to parse structured trace step
                match = trace_step_regex.search(line)
                if match:
                    gas = int(match.group(1))
                    contract = match.group(2)
                    func = match.group(3)
                    val = match.group(4) or "0"
                    args = match.group(5)
                    depth = line.count("│") + line.count("├") + line.count("└")
                    parsed_steps.append({
                        "depth": depth,
                        "gas": gas,
                        "contract": contract,
                        "function": func,
                        "value_wei": val,
                        "arguments": args,
                        "status": "REVERT" if "revert" in line.lower() else "SUCCESS"
                    })

        return logs, traces, parsed_steps

    def _extract_state_diff(self, logs: List[str], lab_id: str, target_type: str) -> Dict[str, Any]:
        diff = {}
        for log in logs:
            if ":" in log:
                parts = log.split(":", 1)
                key = parts[0].strip()
                val = parts[1].strip()
                diff[key] = val
        return diff

lab_runner = FoundryLabRunner()

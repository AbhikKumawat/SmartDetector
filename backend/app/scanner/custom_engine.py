from typing import List
from backend.app.models.scan import Finding
from backend.app.scanner.rules.reentrancy import ReentrancyRule
from backend.app.scanner.rules.access_control import AccessControlRule
from backend.app.scanner.rules.unchecked_call import UncheckedCallRule
from backend.app.scanner.rules.tx_origin import TxOriginRule
from backend.app.scanner.rules.oracle_manipulation import OracleManipulationRule
from backend.app.scanner.rules.integer_overflow import IntegerOverflowRule
from backend.app.scanner.rules.selfdestruct import SelfdestructRule
from backend.app.scanner.rules.delegatecall import DelegatecallRule
from backend.app.scanner.rules.flash_loan import FlashLoanRule
from backend.app.scanner.rules.denial_of_service import DenialOfServiceRule

class CustomRuleEngine:
    def __init__(self):
        self.rules = [
            ReentrancyRule(),
            AccessControlRule(),
            UncheckedCallRule(),
            TxOriginRule(),
            OracleManipulationRule(),
            IntegerOverflowRule(),
            SelfdestructRule(),
            DelegatecallRule(),
            FlashLoanRule(),
            DenialOfServiceRule(),
        ]

    def scan(self, source_code: str, filename: str = "Contract.sol") -> List[Finding]:
        all_findings: List[Finding] = []
        for rule in self.rules:
            try:
                results = rule.analyze(source_code, filename)
                all_findings.extend(results)
            except Exception as e:
                # Log error without failing other rules
                print(f"[CustomEngine Error] Rule {rule.name} failed: {e}")
        return all_findings

import pytest
from pathlib import Path
from backend.app.scanner.rules.reentrancy import ReentrancyRule
from backend.app.scanner.rules.access_control import AccessControlRule
from backend.app.scanner.rules.unchecked_call import UncheckedCallRule
from backend.app.scanner.rules.tx_origin import TxOriginRule
from backend.app.scanner.rules.oracle_manipulation import OracleManipulationRule
from backend.app.scanner.rules.integer_overflow import IntegerOverflowRule
from backend.app.scanner.rules.selfdestruct import SelfdestructRule
from backend.app.scanner.rules.delegatecall import DelegatecallRule
from backend.app.scanner.rules.denial_of_service import DenialOfServiceRule
from backend.app.config import settings

CONTRACTS_DIR = Path(settings.CONTRACTS_DIR)

def test_reentrancy_detection():
    rule = ReentrancyRule()
    vuln_code = (CONTRACTS_DIR / "src/reentrancy/VulnerableBank.sol").read_text(encoding="utf-8")
    patched_code = (CONTRACTS_DIR / "src/reentrancy/PatchedBank.sol").read_text(encoding="utf-8")

    vuln_findings = rule.analyze(vuln_code, "VulnerableBank.sol")
    assert len(vuln_findings) >= 1
    assert vuln_findings[0].category == "Reentrancy"

    patched_findings = rule.analyze(patched_code, "PatchedBank.sol")
    assert len(patched_findings) == 0

def test_access_control_detection():
    rule = AccessControlRule()
    vuln_code = (CONTRACTS_DIR / "src/access_control/VulnerableVault.sol").read_text(encoding="utf-8")
    patched_code = (CONTRACTS_DIR / "src/access_control/PatchedVault.sol").read_text(encoding="utf-8")

    vuln_findings = rule.analyze(vuln_code, "VulnerableVault.sol")
    assert len(vuln_findings) >= 1
    assert vuln_findings[0].category == "Access Control"

    patched_findings = rule.analyze(patched_code, "PatchedVault.sol")
    assert len(patched_findings) == 0

def test_unchecked_call_detection():
    rule = UncheckedCallRule()
    vuln_code = (CONTRACTS_DIR / "src/unchecked_calls/VulnerableAuction.sol").read_text(encoding="utf-8")
    patched_code = (CONTRACTS_DIR / "src/unchecked_calls/PatchedAuction.sol").read_text(encoding="utf-8")

    vuln_findings = rule.analyze(vuln_code, "VulnerableAuction.sol")
    assert len(vuln_findings) >= 1
    assert vuln_findings[0].category == "Unchecked Calls"

def test_tx_origin_detection():
    rule = TxOriginRule()
    vuln_code = (CONTRACTS_DIR / "src/tx_origin/VulnerableWallet.sol").read_text(encoding="utf-8")
    patched_code = (CONTRACTS_DIR / "src/tx_origin/PatchedWallet.sol").read_text(encoding="utf-8")

    vuln_findings = rule.analyze(vuln_code, "VulnerableWallet.sol")
    assert len(vuln_findings) >= 1
    assert "tx.origin" in vuln_findings[0].description

    patched_findings = rule.analyze(patched_code, "PatchedWallet.sol")
    assert len(patched_findings) == 0

def test_oracle_manipulation_detection():
    rule = OracleManipulationRule()
    vuln_code = (CONTRACTS_DIR / "src/oracle_manipulation/VulnerableLending.sol").read_text(encoding="utf-8")
    patched_code = (CONTRACTS_DIR / "src/oracle_manipulation/PatchedLending.sol").read_text(encoding="utf-8")

    vuln_findings = rule.analyze(vuln_code, "VulnerableLending.sol")
    assert len(vuln_findings) >= 1

    patched_findings = rule.analyze(patched_code, "PatchedLending.sol")
    assert len(patched_findings) == 0

def test_selfdestruct_detection():
    rule = SelfdestructRule()
    vuln_code = (CONTRACTS_DIR / "src/selfdestruct/VulnerableVaultKill.sol").read_text(encoding="utf-8")
    findings = rule.analyze(vuln_code, "VulnerableVaultKill.sol")
    assert len(findings) >= 1
    assert findings[0].category == "Contract Destruction"

def test_delegatecall_detection():
    rule = DelegatecallRule()
    vuln_code = (CONTRACTS_DIR / "src/delegatecall/VulnerableProxy.sol").read_text(encoding="utf-8")
    findings = rule.analyze(vuln_code, "VulnerableProxy.sol")
    assert len(findings) >= 1

def test_denial_of_service_detection():
    rule = DenialOfServiceRule()
    vuln_code = (CONTRACTS_DIR / "src/denial_of_service/VulnerableDistributor.sol").read_text(encoding="utf-8")
    patched_code = (CONTRACTS_DIR / "src/denial_of_service/PatchedDistributor.sol").read_text(encoding="utf-8")

    vuln_findings = rule.analyze(vuln_code, "VulnerableDistributor.sol")
    assert len(vuln_findings) >= 1

    patched_findings = rule.analyze(patched_code, "PatchedDistributor.sol")
    assert len(patched_findings) == 0

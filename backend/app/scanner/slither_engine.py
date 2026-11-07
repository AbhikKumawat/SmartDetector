import os
import json
import uuid
import tempfile
from pathlib import Path
from typing import List, Tuple
from backend.app.config import settings
from backend.app.models.scan import Finding, SeverityEnum, ConfidenceEnum
from backend.app.security.safe_subprocess import run_sandboxed_command, SafeExecutionError

class SlitherEngine:
    def __init__(self):
        self.slither_path = settings.SLITHER_PATH
        self.is_available = self._check_availability()

    def _check_availability(self) -> bool:
        if os.path.exists(self.slither_path):
            return True
        # Check PATH
        import shutil
        return shutil.which("slither") is not None

    def scan_source(self, source_code: str, filename: str = "Contract.sol") -> Tuple[List[Finding], bool]:
        """
        Runs Slither on an isolated single Solidity file.
        Returns (findings, success_flag).
        """
        if not self.is_available:
            return [], False

        findings: List[Finding] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / filename
            file_path.write_text(source_code, encoding="utf-8")

            # Command: slither <file_path> --json -
            cmd = [
                self.slither_path,
                str(file_path),
                "--json",
                "-"
            ]

            try:
                code, stdout, stderr = run_sandboxed_command(
                    cmd, 
                    cwd=tmpdir, 
                    timeout=settings.SUBPROCESS_TIMEOUT_SECONDS
                )
                
                # Slither writes JSON to stdout or stderr depending on version
                json_str = stdout if stdout.strip().startswith("{") else stderr
                if "{" in json_str:
                    json_start = json_str.index("{")
                    parsed = json.loads(json_str[json_start:])
                    findings = self._parse_slither_json(parsed, filename)
                    return findings, True
            except Exception as e:
                print(f"[SlitherEngine Warning] Slither execution failed: {e}")
                return [], False

        return findings, True

    def scan_foundry_project(self, project_path: str) -> Tuple[List[Finding], bool]:
        """
        Runs Slither directly on a Foundry/Hardhat project directory.
        """
        if not self.is_available:
            return [], False

        findings = []
        cmd = [
            self.slither_path,
            project_path,
            "--json",
            "-"
        ]
        try:
            code, stdout, stderr = run_sandboxed_command(
                cmd,
                cwd=project_path,
                timeout=settings.SUBPROCESS_TIMEOUT_SECONDS * 2
            )
            raw = stdout if "{" in stdout else stderr
            if "{" in raw:
                start = raw.index("{")
                parsed = json.loads(raw[start:])
                findings = self._parse_slither_json(parsed, "FoundryProject")
                return findings, True
        except Exception as e:
            print(f"[SlitherEngine Project Error] {e}")
            return [], False

        return findings, True

    def _parse_slither_json(self, data: dict, filename: str) -> List[Finding]:
        findings = []
        detectors = data.get("results", {}).get("detectors", [])
        
        severity_map = {
            "High": SeverityEnum.HIGH,
            "Medium": SeverityEnum.MEDIUM,
            "Low": SeverityEnum.LOW,
            "Informational": SeverityEnum.INFORMATIONAL,
            "Optimization": SeverityEnum.INFORMATIONAL
        }

        confidence_map = {
            "High": ConfidenceEnum.CONFIRMED,
            "Medium": ConfidenceEnum.POTENTIAL,
            "Low": ConfidenceEnum.INFORMATIONAL
        }

        for det in detectors:
            check_name = det.get("check", "Unknown")
            description = det.get("description", "").strip()
            impact = det.get("impact", "Medium")
            confidence = det.get("confidence", "Medium")
            
            # Extract line numbers from first element
            elements = det.get("elements", [])
            line_start = 1
            line_end = 1
            contract_name = "Contract"
            func_name = "Global"

            if elements:
                first = elements[0]
                lines = first.get("source_mapping", {}).get("lines", [1])
                if lines:
                    line_start = min(lines)
                    line_end = max(lines)
                contract_name = first.get("type_specific_fields", {}).get("parent", {}).get("name", contract_name)
                func_name = first.get("name", func_name)

            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    name=f"Slither: {check_name}",
                    severity=severity_map.get(impact, SeverityEnum.MEDIUM),
                    confidence=confidence_map.get(confidence, ConfidenceEnum.POTENTIAL),
                    category=self._categorize_check(check_name),
                    contract_name=contract_name,
                    function_name=func_name,
                    file_path=filename,
                    line_start=line_start,
                    line_end=line_end,
                    description=description,
                    impact=f"Potential exploit via {check_name}.",
                    remediation=f"Review Slither security guidelines for detector '{check_name}'.",
                    tool="Slither Static Analyzer"
                )
            )

        return findings

    def _categorize_check(self, check: str) -> str:
        check_lower = check.lower()
        if "reentrancy" in check_lower:
            return "Reentrancy"
        elif "tx-origin" in check_lower:
            return "Authentication / Phishing"
        elif "suicidal" in check_lower or "selfdestruct" in check_lower:
            return "Contract Destruction"
        elif "delegatecall" in check_lower:
            return "Delegatecall Risks"
        elif "unchecked" in check_lower:
            return "Unchecked Calls"
        elif "arbitrary" in check_lower or "access" in check_lower:
            return "Access Control"
        return "Static Analysis Finding"

import os
import json
import uuid
from typing import List, Optional
from fastapi import FastAPI, Depends, UploadFile, File, Form, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import init_db, get_db, DBScan, DBFinding
from backend.app.models.scan import (
    ScanRequest,
    ScanResponse,
    ScanSummary,
    Finding,
    SeverityEnum,
    ConfidenceEnum,
    ExploitLabRunRequest,
    ExploitLabRunResponse
)
from backend.app.scanner.runner import scanner
from backend.app.lab.foundry_runner import lab_runner, LAB_MAP
from backend.app.reports.pdf_generator import generate_audit_pdf
from backend.app.reports.json_generator import generate_audit_json
from backend.app.security.input_validation import validate_solidity_source, sanitize_filename
from backend.app.security.rate_limiter import check_rate_limit

# Initialize DB tables
init_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Production-grade smart contract security analysis platform & controlled exploitation lab."
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get(f"{settings.API_PREFIX}/health")
async def health_check():
    return {
        "status": "healthy",
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "slither_installed": scanner.slither_engine.is_available,
        "forge_path": settings.FORGE_PATH,
        "foundry_ready": os.path.exists(settings.FORGE_PATH)
    }

@app.get(f"{settings.API_PREFIX}/contracts/samples")
async def get_sample_contracts():
    """Returns catalog of pre-loaded vulnerable and patched contract pairs for the IDE/Editor."""
    contracts_dir = settings.CONTRACTS_DIR
    samples = []
    
    pairs = [
        ("reentrancy", "VulnerableBank.sol", "src/reentrancy/VulnerableBank.sol", "src/reentrancy/PatchedBank.sol"),
        ("access_control", "VulnerableVault.sol", "src/access_control/VulnerableVault.sol", "src/access_control/PatchedVault.sol"),
        ("unchecked_calls", "VulnerableAuction.sol", "src/unchecked_calls/VulnerableAuction.sol", "src/unchecked_calls/PatchedAuction.sol"),
        ("oracle_manipulation", "VulnerableLending.sol", "src/oracle_manipulation/VulnerableLending.sol", "src/oracle_manipulation/PatchedLending.sol"),
        ("tx_origin", "VulnerableWallet.sol", "src/tx_origin/VulnerableWallet.sol", "src/tx_origin/PatchedWallet.sol"),
        ("integer_overflow", "VulnerableToken.sol", "src/integer_overflow/VulnerableToken.sol", "src/integer_overflow/PatchedToken.sol"),
        ("selfdestruct", "VulnerableVaultKill.sol", "src/selfdestruct/VulnerableVaultKill.sol", "src/selfdestruct/PatchedVaultKill.sol"),
        ("delegatecall", "VulnerableProxy.sol", "src/delegatecall/VulnerableProxy.sol", "src/delegatecall/PatchedProxy.sol"),
        ("denial_of_service", "VulnerableDistributor.sol", "src/denial_of_service/VulnerableDistributor.sol", "src/denial_of_service/PatchedDistributor.sol"),
    ]

    for lab_id, name, vuln_rel, patch_rel in pairs:
        vuln_path = os.path.join(contracts_dir, vuln_rel)
        patch_path = os.path.join(contracts_dir, patch_rel)
        
        vuln_code = ""
        patch_code = ""
        if os.path.exists(vuln_path):
            with open(vuln_path, "r", encoding="utf-8") as f:
                vuln_code = f.read()
        if os.path.exists(patch_path):
            with open(patch_path, "r", encoding="utf-8") as f:
                patch_code = f.read()

        samples.append({
            "id": lab_id,
            "name": name,
            "category": lab_id.replace("_", " ").title(),
            "vulnerable_code": vuln_code,
            "patched_code": patch_code
        })

    return samples

@app.post(f"{settings.API_PREFIX}/scan", response_model=ScanResponse, dependencies=[Depends(check_rate_limit)])
async def scan_contract(payload: ScanRequest, db: Session = Depends(get_db)):
    """Scans pasted Solidity source code and records the findings persistently."""
    clean_source = validate_solidity_source(payload.source_code)
    clean_filename = sanitize_filename(payload.filename)

    req = ScanRequest(
        source_code=clean_source,
        filename=clean_filename,
        enable_slither=payload.enable_slither,
        enable_custom_rules=payload.enable_custom_rules
    )

    result = scanner.run_scan(req)

    # Persist in DB
    db_scan = DBScan(
        id=result.scan_id,
        target_name=result.target_name,
        source_code=clean_source,
        total_findings=result.summary.total_findings,
        critical_count=result.summary.critical_count,
        high_count=result.summary.high_count,
        medium_count=result.summary.medium_count,
        low_count=result.summary.low_count,
        info_count=result.summary.info_count,
        security_score=result.summary.security_score,
        execution_time_ms=result.summary.execution_time_ms
    )
    db.add(db_scan)

    for f in result.findings:
        db_f = DBFinding(
            id=f.id,
            scan_id=result.scan_id,
            name=f.name,
            severity=f.severity.value,
            confidence=f.confidence.value,
            category=f.category,
            contract_name=f.contract_name,
            function_name=f.function_name,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            description=f.description,
            impact=f.impact,
            remediation=f.remediation,
            reproduction=f.reproduction,
            code_snippet=f.code_snippet,
            tool=f.tool
        )
        db.add(db_f)

    db.commit()
    return result

@app.post(f"{settings.API_PREFIX}/scan/upload", response_model=ScanResponse, dependencies=[Depends(check_rate_limit)])
async def upload_and_scan(
    file: UploadFile = File(...),
    enable_slither: bool = Form(True),
    enable_custom_rules: bool = Form(True),
    db: Session = Depends(get_db)
):
    """Uploads a Solidity .sol file, applies strict validation, and triggers scan."""
    clean_filename = sanitize_filename(file.filename)
    content_bytes = await file.read()
    
    try:
        source_code = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="Uploaded file is not valid UTF-8 text.")

    clean_source = validate_solidity_source(source_code)

    req = ScanRequest(
        source_code=clean_source,
        filename=clean_filename,
        enable_slither=enable_slither,
        enable_custom_rules=enable_custom_rules
    )

    result = scanner.run_scan(req)

    # Persist in DB
    db_scan = DBScan(
        id=result.scan_id,
        target_name=result.target_name,
        source_code=clean_source,
        total_findings=result.summary.total_findings,
        critical_count=result.summary.critical_count,
        high_count=result.summary.high_count,
        medium_count=result.summary.medium_count,
        low_count=result.summary.low_count,
        info_count=result.summary.info_count,
        security_score=result.summary.security_score,
        execution_time_ms=result.summary.execution_time_ms
    )
    db.add(db_scan)

    for f in result.findings:
        db_f = DBFinding(
            id=f.id,
            scan_id=result.scan_id,
            name=f.name,
            severity=f.severity.value,
            confidence=f.confidence.value,
            category=f.category,
            contract_name=f.contract_name,
            function_name=f.function_name,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            description=f.description,
            impact=f.impact,
            remediation=f.remediation,
            reproduction=f.reproduction,
            code_snippet=f.code_snippet,
            tool=f.tool
        )
        db.add(db_f)

    db.commit()
    return result

@app.get(f"{settings.API_PREFIX}/scans")
async def list_scans(limit: int = 20, db: Session = Depends(get_db)):
    """Returns historical scans and global stats for the cybersecurity dashboard."""
    scans = db.query(DBScan).order_by(DBScan.created_at.desc()).limit(limit).all()
    
    total_scanned = db.query(DBScan).count()
    total_findings = sum(s.total_findings for s in scans)
    crit = sum(s.critical_count for s in scans)
    high = sum(s.high_count for s in scans)
    med = sum(s.medium_count for s in scans)
    low = sum(s.low_count for s in scans)
    info = sum(s.info_count for s in scans)

    return {
        "metrics": {
            "total_contracts_scanned": total_scanned,
            "total_vulnerabilities": total_findings,
            "severity_distribution": {
                "critical": crit,
                "high": high,
                "medium": med,
                "low": low,
                "informational": info
            }
        },
        "recent_scans": [
            {
                "id": s.id,
                "target_name": s.target_name,
                "created_at": s.created_at.isoformat() + "Z",
                "total_findings": s.total_findings,
                "security_score": s.security_score,
                "critical_count": s.critical_count,
                "high_count": s.high_count,
                "medium_count": s.medium_count,
                "low_count": s.low_count
            }
            for s in scans
        ]
    }

@app.get(f"{settings.API_PREFIX}/scans/{{scan_id}}")
async def get_scan_details(scan_id: str, db: Session = Depends(get_db)):
    """Fetches full findings for a specific scan."""
    scan = db.query(DBScan).filter(DBScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    findings = [
        Finding(
            id=f.id,
            name=f.name,
            severity=SeverityEnum(f.severity),
            confidence=ConfidenceEnum(f.confidence),
            category=f.category,
            contract_name=f.contract_name,
            function_name=f.function_name,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            description=f.description,
            impact=f.impact,
            remediation=f.remediation,
            reproduction=f.reproduction,
            code_snippet=f.code_snippet,
            tool=f.tool
        )
        for f in scan.findings
    ]

    return ScanResponse(
        scan_id=scan.id,
        timestamp=scan.created_at,
        target_name=scan.target_name,
        summary=ScanSummary(
            total_findings=scan.total_findings,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            info_count=scan.info_count,
            security_score=scan.security_score,
            execution_time_ms=scan.execution_time_ms
        ),
        findings=findings
    )

@app.get(f"{settings.API_PREFIX}/reports/{{scan_id}}/pdf")
async def download_pdf_report(scan_id: str, db: Session = Depends(get_db)):
    """Generates and downloads vector PDF audit report."""
    scan = db.query(DBScan).filter(DBScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = [
        Finding(
            id=f.id,
            name=f.name,
            severity=SeverityEnum(f.severity),
            confidence=ConfidenceEnum(f.confidence),
            category=f.category,
            contract_name=f.contract_name,
            function_name=f.function_name,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            description=f.description,
            impact=f.impact,
            remediation=f.remediation,
            reproduction=f.reproduction,
            code_snippet=f.code_snippet,
            tool=f.tool
        )
        for f in scan.findings
    ]

    scan_res = ScanResponse(
        scan_id=scan.id,
        timestamp=scan.created_at,
        target_name=scan.target_name,
        summary=ScanSummary(
            total_findings=scan.total_findings,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            info_count=scan.info_count,
            security_score=scan.security_score,
            execution_time_ms=scan.execution_time_ms
        ),
        findings=findings
    )

    pdf_bytes = generate_audit_pdf(scan_res)
    filename = f"Web3Sentinel_Audit_{scan.target_name}_{scan.id[:8]}.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get(f"{settings.API_PREFIX}/reports/{{scan_id}}/json")
async def download_json_report(scan_id: str, db: Session = Depends(get_db)):
    """Downloads structured audit report in JSON format."""
    scan = db.query(DBScan).filter(DBScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")

    findings = [
        Finding(
            id=f.id,
            name=f.name,
            severity=SeverityEnum(f.severity),
            confidence=ConfidenceEnum(f.confidence),
            category=f.category,
            contract_name=f.contract_name,
            function_name=f.function_name,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            description=f.description,
            impact=f.impact,
            remediation=f.remediation,
            reproduction=f.reproduction,
            code_snippet=f.code_snippet,
            tool=f.tool
        )
        for f in scan.findings
    ]

    scan_res = ScanResponse(
        scan_id=scan.id,
        timestamp=scan.created_at,
        target_name=scan.target_name,
        summary=ScanSummary(
            total_findings=scan.total_findings,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            info_count=scan.info_count,
            security_score=scan.security_score,
            execution_time_ms=scan.execution_time_ms
        ),
        findings=findings
    )

    report_data = generate_audit_json(scan_res)
    return JSONResponse(
        content=report_data,
        headers={"Content-Disposition": f"attachment; filename=Web3Sentinel_Audit_{scan.id[:8]}.json"}
    )

@app.get(f"{settings.API_PREFIX}/lab/scenarios")
async def get_lab_scenarios():
    """Returns available educational exploitation scenarios."""
    scenarios = []
    for k, v in LAB_MAP.items():
        scenarios.append({
            "lab_id": k,
            "title": v["title"],
            "explanation": v["explanation"],
            "test_file": v["test_file"],
            "vulnerable_contract": v["contract_pair"][0],
            "patched_contract": v["contract_pair"][1]
        })
    return scenarios

@app.post(f"{settings.API_PREFIX}/lab/run", response_model=ExploitLabRunResponse)
async def run_exploit_lab(payload: ExploitLabRunRequest):
    """Executes a controlled Foundry exploit PoC or Patched verification in sandbox."""
    try:
        return lab_runner.run_lab(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Exploit execution failed: {str(e)}")

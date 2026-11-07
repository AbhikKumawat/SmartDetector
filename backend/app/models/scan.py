from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class SeverityEnum(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

class ConfidenceEnum(str, Enum):
    CONFIRMED = "Confirmed"
    POTENTIAL = "Potential"
    INFORMATIONAL = "Informational"

class Finding(BaseModel):
    id: str
    name: str
    severity: SeverityEnum
    confidence: ConfidenceEnum
    category: str
    contract_name: str = "Unknown"
    function_name: str = "Global / Contract Level"
    file_path: str = "input.sol"
    line_start: int = 1
    line_end: int = 1
    description: str
    impact: str
    reproduction: Optional[str] = None
    remediation: str
    code_snippet: Optional[str] = None
    tool: str = "Sentinel Core"

class ScanSummary(BaseModel):
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    security_score: float = 100.0
    execution_time_ms: float = 0.0
    slither_available: bool = True

class ScanRequest(BaseModel):
    source_code: Optional[str] = None
    filename: Optional[str] = "Contract.sol"
    project_path: Optional[str] = None
    enable_slither: bool = True
    enable_custom_rules: bool = True

class ScanResponse(BaseModel):
    scan_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    target_name: str
    summary: ScanSummary
    findings: List[Finding]

class ExploitLabRunRequest(BaseModel):
    lab_id: str  # e.g., 'reentrancy', 'access_control', 'unchecked_calls', 'oracle_manipulation', 'tx_origin'
    target_type: str = "vulnerable"  # 'vulnerable' or 'patched'

class ExploitTraceStep(BaseModel):
    depth: int
    call_type: str
    caller: str
    target: str
    function_signature: str
    value_wei: str = "0"
    gas_used: Optional[int] = None
    status: str = "SUCCESS"  # SUCCESS or REVERT

class ExploitLabRunResponse(BaseModel):
    run_id: str
    lab_id: str
    target_type: str
    passed: bool
    gas_used: int
    duration_ms: float
    raw_logs: List[str]
    call_traces: List[str]
    parsed_trace: List[Dict[str, Any]]
    state_diff: Dict[str, Any]
    explanation: str

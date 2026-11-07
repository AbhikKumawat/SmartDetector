import re
from pathlib import Path
from fastapi import HTTPException
from backend.app.config import settings

SAFE_FILENAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

def validate_solidity_source(source_code: str) -> str:
    """Validates Solidity source code size, encoding, and minimum syntax."""
    if not source_code or not source_code.strip():
        raise HTTPException(status_code=400, detail="Solidity source code cannot be empty.")
    
    encoded_bytes = source_code.encode("utf-8")
    if len(encoded_bytes) > settings.UPLOAD_MAX_SIZE_BYTES:
        raise HTTPException(
            status_code=413, 
            detail=f"Source code exceeds maximum allowed size ({settings.UPLOAD_MAX_SIZE_BYTES // 1024} KB)."
        )
    
    # Must look like Solidity code (contains pragma or contract/interface/library)
    if not re.search(r"\b(pragma\s+solidity|contract\s+\w+|interface\s+\w+|library\s+\w+)\b", source_code):
        raise HTTPException(
            status_code=400, 
            detail="Supplied content does not appear to be valid Solidity source code."
        )

    return source_code

def sanitize_filename(filename: str) -> str:
    """Ensures filename is safe and prevents path traversal attacks."""
    if not filename:
        return "Contract.sol"
    
    clean_name = Path(filename).name
    if not SAFE_FILENAME_REGEX.match(clean_name):
        clean_name = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", clean_name)
    
    if not clean_name.endswith(".sol"):
        clean_name += ".sol"
        
    return clean_name

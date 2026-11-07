import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_DIR = BASE_DIR.parent
CONTRACTS_DIR = WORKSPACE_DIR / "contracts"

class Settings(BaseModel):
    PROJECT_NAME: str = "Web3 Sentinel"
    VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"
    
    # Storage & DB
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/sentinel.db")
    UPLOAD_MAX_SIZE_BYTES: int = 500 * 1024  # 500 KB limit
    ALLOWED_EXTENSIONS: set = {".sol"}
    CONTRACTS_DIR: str = str(WORKSPACE_DIR / "contracts")
    
    # Binary Paths
    FOUNDRY_BIN_DIR: str = os.getenv(
        "FOUNDRY_BIN_DIR", 
        str(Path.home() / ".foundry" / "bin")
    )
    FORGE_PATH: str = os.getenv("FORGE_PATH", str(Path.home() / ".foundry" / "bin" / "forge.exe" if os.name == "nt" else "forge"))
    SLITHER_PATH: str = os.getenv("SLITHER_PATH", str(BASE_DIR / "venv" / "Scripts" / "slither.exe" if os.name == "nt" else "slither"))
    
    # Analysis limits
    SUBPROCESS_TIMEOUT_SECONDS: int = 30
    RATE_LIMIT_PER_MINUTE: int = 60
    
    # Lab Environment
    ANVIL_PORT: int = 8545

settings = Settings()

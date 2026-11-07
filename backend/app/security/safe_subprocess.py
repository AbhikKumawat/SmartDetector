import os
import subprocess
import shutil
import tempfile
from pathlib import Path
from typing import List, Tuple, Optional
from backend.app.config import settings

# Allowlisted commands and allowed binaries
ALLOWED_EXECUTABLES = {"forge", "forge.exe", "slither", "slither.exe", "anvil", "anvil.exe"}

class SafeExecutionError(Exception):
    pass

def run_sandboxed_command(
    command_args: List[str],
    cwd: Optional[str] = None,
    timeout: int = settings.SUBPROCESS_TIMEOUT_SECONDS,
    env_vars: Optional[dict] = None
) -> Tuple[int, str, str]:
    """
    Safely executes an allowlisted CLI binary with strict timeouts and environment confinement.
    Prevents command injection by passing arguments as an array (shell=False).
    """
    if not command_args:
        raise SafeExecutionError("Empty command requested.")
    
    executable_name = Path(command_args[0]).name.lower()
    if executable_name not in ALLOWED_EXECUTABLES:
        raise SafeExecutionError(f"Executable '{executable_name}' is not in the security allowlist.")
    
    # Merge safe environment variables
    env = os.environ.copy()
    if env_vars:
        env.update(env_vars)
    
    # Add foundry to PATH if present
    foundry_bin = settings.FOUNDRY_BIN_DIR
    if foundry_bin and foundry_bin not in env.get("PATH", ""):
        env["PATH"] = f"{foundry_bin}{os.pathsep}{env.get('PATH', '')}"

    try:
        process = subprocess.Popen(
            command_args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            env=env
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return process.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        process.kill()
        raise SafeExecutionError(f"Command execution timed out after {timeout} seconds.")
    except Exception as e:
        raise SafeExecutionError(f"Process execution failed: {str(e)}")

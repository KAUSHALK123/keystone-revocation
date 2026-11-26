"""Runtime and environment configuration for QuantumVault."""
import os
from pathlib import Path
import tempfile


def get_state_dir() -> Path:
    """Resolve the writable state directory according to Adapter Contract v1.
    
    Priority:
    1. TRACK4_STATE_DIR environment variable
    2. OS temporary directory fallback (TMPDIR, TEMP, TMP, or system temp)
    """
    state_dir_env = os.environ.get("TRACK4_STATE_DIR")
    if state_dir_env:
        path = Path(state_dir_env).resolve()
    else:
        path = Path(tempfile.gettempdir()).resolve() / "quantumvault-state"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_db_path(state_dir: Path | None = None) -> Path:
    """Get the path to the primary SQLite database."""
    base = state_dir or get_state_dir()
    return base / "quantumvault.db"


def get_vault_key_path(state_dir: Path | None = None) -> Path:
    """Get the path to the internal vault encryption key file."""
    base = state_dir or get_state_dir()
    return base / "vault_master.key"


def get_epoch_anchor_path(state_dir: Path | None = None) -> Path:
    """Get the path to the external monotonic cluster epoch anchor."""
    base = state_dir or get_state_dir()
    return base / ".cluster_epoch_anchor"


def get_checkpoint_key_path(state_dir: Path | None = None) -> Path:
    """Get the path to the external HMAC key for audit checkpoints."""
    base = state_dir or get_state_dir()
    return base / ".audit_checkpoint.key"


# Standard Adapter Contract limits
MAX_STREAM_BYTES = 65536  # 64 KiB
MAX_STDIN_BYTES = 10 * 1024 * 1024  # 10 MiB request safety cap
DEFAULT_TIMEOUT_SECONDS = 8.0

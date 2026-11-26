"""Helper utilities for tests_round2."""
from __future__ import annotations

import contextlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from quantumvault.config import get_db_path, get_vault_key_path
from quantumvault.core.service import QuantumVaultService


@contextlib.contextmanager
def open_service(state_dir: Path | None = None):
    """Context manager wrapper for QuantumVaultService to ensure clean SQLite connection closing."""
    svc = QuantumVaultService(state_dir=state_dir)
    try:
        yield svc
    finally:
        try:
            svc.close()
        except Exception:
            pass

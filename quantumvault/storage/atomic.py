"""Atomic, fsync-backed file persistence helpers for security anchors and snapshots."""
import os
from pathlib import Path
import tempfile


def atomic_write_bytes(target_path: Path, data: bytes) -> None:
    """Write bytes to target_path atomically via a same-directory temp file and os.replace."""
    target = Path(target_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(str(tmp_path), str(target))
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass
        raise


def atomic_write_text(target_path: Path, text: str, encoding: str = "utf-8") -> None:
    """Write text to target_path atomically via atomic_write_bytes."""
    atomic_write_bytes(target_path, text.encode(encoding))

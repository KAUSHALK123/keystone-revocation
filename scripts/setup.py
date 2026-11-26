#!/usr/bin/env python3
"""Setup script executing post-quantum environment verification."""
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    verify_script = Path(__file__).resolve().parent / "verify_setup.py"
    rc = subprocess.call([sys.executable, str(verify_script)] + sys.argv[1:])
    sys.exit(rc)

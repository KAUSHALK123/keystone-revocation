"""QuantumVault Core Service Adapter (Track 4: Trust, but verify).

One JSON request per process. Strictly implements Adapter Contract v1.
"""
from __future__ import annotations

import sys
if sys.version_info < (3, 11):
    sys.exit("QuantumVault requires Python 3.11 or newer (detected Python %d.%d.%d)." % sys.version_info[:3])

import json

from quantumvault.config import MAX_STREAM_BYTES
from quantumvault.core.dispatcher import dispatch


def reject_duplicates(pairs):
    """Reject duplicate JSON keys to enforce strict parser atomicity."""
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"Duplicate JSON key: {k}")
        d[k] = v
    return d


def reject_constant(c):
    """Reject non-standard JSON constants (NaN, Infinity)."""
    raise ValueError(f"Non-standard JSON constant: {c}")


def main() -> int:
    # Ensure standard streams strictly use UTF-8 across all operating systems
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    try:
        if hasattr(sys.stdin, "buffer"):
            raw_bytes = sys.stdin.buffer.read(MAX_STREAM_BYTES + 1)
            if len(raw_bytes) > MAX_STREAM_BYTES:
                print("Request failed; input exceeds maximum stream buffer size.", file=sys.stderr)
                return 1
            raw_input = raw_bytes.decode("utf-8-sig")
        else:
            raw_input = sys.stdin.read(MAX_STREAM_BYTES + 1)
            if len(raw_input) > MAX_STREAM_BYTES:
                print("Request failed; input exceeds maximum stream buffer size.", file=sys.stderr)
                return 1
            if raw_input.startswith("\ufeff"):
                raw_input = raw_input[1:]
        if not raw_input.strip():
            print("Request failed; empty standard input.", file=sys.stderr)
            return 1

        request = json.loads(
            raw_input,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant
        )
        if not isinstance(request, dict):
            print("Request failed; input must be a JSON object.", file=sys.stderr)
            return 1

        response = dispatch(request)
        if not isinstance(response, dict):
            print("Request failed; internal response must be a JSON object.", file=sys.stderr)
            return 1

        encoded = json.dumps(response, allow_nan=False, ensure_ascii=False)
        sys.stdout.buffer.write(encoded.encode("utf-8") + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Sanitize all exceptions to prevent secret or path leakage to stderr
        print("Request failed; inspect team application locally.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())


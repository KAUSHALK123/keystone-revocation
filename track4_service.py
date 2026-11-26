"""QuantumVault Official Judging Adapter (Track 4: Trust, but verify).

One JSON request per process. Strictly implements Adapter Contract v1.
"""
from __future__ import annotations

import sys
if sys.version_info < (3, 11):
    sys.exit("QuantumVault requires Python 3.11 or newer (detected Python %d.%d.%d)." % sys.version_info[:3])

import json

from quantumvault.core.dispatcher import dispatch


def main() -> int:
    try:
        if hasattr(sys.stdin, "buffer"):
            raw_bytes = sys.stdin.buffer.read()
            raw_input = raw_bytes.decode("utf-8-sig")
        else:
            raw_input = sys.stdin.read()
            if raw_input.startswith("\ufeff"):
                raw_input = raw_input[1:]

        if not raw_input.strip():
            print("Request failed; empty standard input.", file=sys.stderr)
            return 1

        request = json.loads(raw_input)
        if not isinstance(request, dict):
            print("Request failed; input must be a JSON object.", file=sys.stderr)
            return 1

        response = dispatch(request)
        if not isinstance(response, dict):
            print("Request failed; internal response must be a JSON object.", file=sys.stderr)
            return 1

        encoded = json.dumps(response, allow_nan=False, ensure_ascii=False)
    except Exception:
        # Sanitize all exceptions to prevent secret or path leakage to stderr
        print("Request failed; inspect team application locally.", file=sys.stderr)
        return 1

    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())

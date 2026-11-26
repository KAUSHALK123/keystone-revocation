"""QuantumVault Official Judging Adapter (Track 4: Trust, but verify).

One JSON request per process. Strictly implements Adapter Contract v1.
"""
import json
import sys

from quantumvault.config import MAX_STDIN_BYTES
from quantumvault.core.dispatcher import dispatch


def _reject_duplicate_keys_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject JSON objects with duplicate keys to prevent request smuggling."""
    obj: dict[str, object] = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"Duplicate JSON key: {k!r}")
        obj[k] = v
    return obj


def main() -> int:
    try:
        if hasattr(sys.stdin, "buffer"):
            raw_bytes = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
            if len(raw_bytes) > MAX_STDIN_BYTES:
                print("Request failed; input exceeded size limit.", file=sys.stderr)
                return 1
            raw_input = raw_bytes.decode("utf-8", errors="strict")
        else:
            raw_input = sys.stdin.read(MAX_STDIN_BYTES + 1)
            if len(raw_input) > MAX_STDIN_BYTES:
                print("Request failed; input exceeded size limit.", file=sys.stderr)
                return 1
        if not raw_input.strip():
            print("Request failed; empty standard input.", file=sys.stderr)
            return 1

        request = json.loads(raw_input, object_pairs_hook=_reject_duplicate_keys_hook)
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

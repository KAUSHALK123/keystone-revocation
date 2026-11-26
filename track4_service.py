"""QuantumVault Official Judging Adapter (Track 4: Trust, but verify).

One JSON request per process. Strictly implements Adapter Contract v1.
"""
import json
import sys

from quantumvault.config import MAX_STDIN_BYTES, MAX_STREAM_BYTES
from quantumvault.core.dispatcher import dispatch


def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys to enforce strict parser atomicity."""
    d: dict[str, object] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"Duplicate JSON key: {k!r}")
        d[k] = v
    return d


def reject_constant(c: str) -> None:
    """Reject non-standard JSON constants (NaN, Infinity)."""
    raise ValueError(f"Non-standard JSON constant: {c}")


def main() -> int:
    try:
        if hasattr(sys.stdin, "buffer"):
            raw_bytes = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
            raw_len = len(raw_bytes)
            if raw_len > MAX_STDIN_BYTES:
                print("Request failed; input exceeded size limit.", file=sys.stderr)
                return 1
            raw_input = raw_bytes.decode("utf-8", errors="strict")
        else:
            raw_input = sys.stdin.read(MAX_STDIN_BYTES + 1)
            raw_len = len(raw_input.encode("utf-8"))
            if raw_len > MAX_STDIN_BYTES:
                print("Request failed; input exceeded size limit.", file=sys.stderr)
                return 1
        if not raw_input.strip():
            print("Request failed; empty standard input.", file=sys.stderr)
            return 1

        request = json.loads(
            raw_input,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
        if not isinstance(request, dict):
            print("Request failed; input must be a JSON object.", file=sys.stderr)
            return 1

        # Enforce 64 KiB stream bound on single-record ops while allowing larger setup states per Contract v1
        if request.get("op") != "setup" and raw_len > MAX_STREAM_BYTES:
            print("Request failed; input exceeds maximum stream buffer size.", file=sys.stderr)
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

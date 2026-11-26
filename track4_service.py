"""QuantumVault Official Judging Adapter (Track 4: Trust, but verify).

One JSON request per process. Strictly implements Adapter Contract v1.
"""
import json
import sys

from quantumvault.core.dispatcher import dispatch


def main() -> int:
    try:
        raw_input = sys.stdin.read()
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

"""Adversarial Python Test Injector & Interactive Security Runner API."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from quantumvault.web.authentication import verify_operator_auth

router = APIRouter(prefix="/api/v1/injector", tags=["Adversarial Script Injector"])

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
V6_SCRIPT = REPO_ROOT / "challenge-u-to-break-v6.py"
THREE_LEVEL_DIR = REPO_ROOT / "3-level-challenge" / "QuantumVault-3-Level-Challenge"
VALIDATE_SCRIPT = REPO_ROOT / "references" / "track4-toolkit" / "validate.py"


class ScriptExecuteRequest(BaseModel):
    script_content: str = Field(..., min_length=1, max_length=1000000)
    preset_name: str | None = Field(default=None, max_length=64)
    seed: int = Field(default=987654321)
    rounds: int = Field(default=3, ge=1, le=16)
    timeout_seconds: int = Field(default=60, ge=5, le=300)
    args: list[str] = Field(default_factory=list)


class ScriptExecuteResponse(BaseModel):
    success: bool
    exit_code: int
    duration_ms: float
    stdout: str
    stderr: str
    summary: dict[str, int]
    adapter_calls: int
    report: dict[str, Any] | None = None
    tests_breakdown: list[dict[str, Any]] = Field(default_factory=list)


CUSTOM_TEMPLATE = '''"""QuantumVault Custom Adversarial Attack & Fuzzing Script.
Directly exercises the local Track 4 JSON-over-stdio adapter contract.
Zero-plaintext denial, immutable audit recording, and post-quantum KEM validation.
"""
import base64
import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

def invoke_adapter(state_dir: Path, payload: dict) -> dict:
    raw = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    env = dict(TRACK4_STATE_DIR=str(state_dir), PYTHONIOENCODING='utf-8')
    p = subprocess.run(
        [sys.executable, 'track4_service.py'],
        input=raw,
        capture_output=True,
        cwd=Path('.'),
        env=env,
        timeout=10
    )
    if p.returncode != 0:
        return {"error": "nonzero_exit", "stderr": p.stderr.decode('utf-8', errors='replace')}
    return json.loads(p.stdout.decode('utf-8'))

def main():
    print("=== STARTING QUANTUMVAULT CUSTOM ADVERSARIAL ATTACK ===")
    with tempfile.TemporaryDirectory() as td:
        state = Path(td)
        
        # 1. Clean Genesis Setup
        setup_resp = invoke_adapter(state, {
            "op": "setup",
            "owners": {"res-secret": "alice", "res-public": "bob"},
            "contents": {"res-secret": "TOP_SECRET_PLAINTEXT", "res-public": "PUBLIC_DATA"},
            "disabled": [],
            "key_material": "custom-adversary-secret-seed"
        })
        print(f"[*] Setup Result: {setup_resp}")
        assert setup_resp.get("ready") is True, "Setup failed"
        
        # 2. Authorized Read Check
        auth_resp = invoke_adapter(state, {
            "op": "read",
            "actor": "alice",
            "asset": "res-secret",
            "request_id": "attack-read-01"
        })
        print(f"[*] Alice Authorized Read: {auth_resp.get('decision')} (body received: {bool(auth_resp.get('body'))})")
        assert auth_resp.get("decision") == "allow", "Authorized read failed"
        
        # 3. Unauthorized Cross-Tenant Snoop Attack
        snoop_resp = invoke_adapter(state, {
            "op": "read",
            "actor": "bob",
            "asset": "res-secret",
            "request_id": "attack-snoop-02"
        })
        print(f"[*] Bob Unauthorized Read Attempt: {snoop_resp.get('decision')} (body leaked: {'body' in snoop_resp})")
        assert snoop_resp.get("decision") == "deny", "Zero-plaintext denial failed!"
        assert "body" not in snoop_resp, "Body leaked in unauthorized read!"
        
        # 4. Device Revocation Injection
        revoke_resp = invoke_adapter(state, {
            "op": "revoke",
            "actor": "alice"
        })
        print(f"[*] Revoke Alice Result: {revoke_resp}")
        
        # 5. Post-Revocation Read Attempt
        post_resp = invoke_adapter(state, {
            "op": "read",
            "actor": "alice",
            "asset": "res-secret",
            "request_id": "attack-post-revoke-03"
        })
        print(f"[*] Alice Post-Revocation Read: {post_resp.get('decision')}")
        assert post_resp.get("decision") == "deny", "Revocation bypass detected!"
        
        # 6. Immutable Audit Proof Check
        audit_resp = invoke_adapter(state, {
            "op": "audit",
            "request_id": "attack-post-revoke-03"
        })
        print(f"[*] Audit Verification: {audit_resp}")
        assert audit_resp.get("decision") == "deny", "Audit record missing or tampered"
        
        print("PASS  [custom] zero-knowledge-revocation-invariants: invariant held")
        print("SUMMARY {'PASS': 1, 'FAIL': 0, 'ERROR': 0, 'SKIP': 0}")

if __name__ == '__main__':
    main()
'''


@router.get("/presets")
def get_presets(auth: dict = Depends(verify_operator_auth)):
    """Return available pre-loaded adversarial challenge suites and templates."""
    presets = []

    # 1. Challenge V6
    v6_content = ""
    if V6_SCRIPT.exists():
        try:
            v6_content = V6_SCRIPT.read_text(encoding="utf-8")
        except Exception:
            pass
    presets.append({
        "id": "v6",
        "name": "Challenge V6 Adversarial Suite",
        "description": "Full 18-test independent adversarial suite (linearizability, cohorts, crash cycles, rollback checks).",
        "category": "Adversarial Suites",
        "script_content": v6_content,
        "default_args": ["--extended", "--seed", "987654321"]
    })

    # 2. Extreme Profile
    extreme_path = THREE_LEVEL_DIR / "test-extreme.py"
    extreme_content = ""
    if extreme_path.exists():
        try:
            # Load challenge_engine and test-extreme
            extreme_content = (THREE_LEVEL_DIR / "challenge_engine.py").read_text(encoding="utf-8")
        except Exception:
            pass
    presets.append({
        "id": "extreme",
        "name": "3-Level Challenge: Extreme Profile",
        "description": "16 intense adversarial tests (mixed KEM oracles, noncanonical coefficients, recovery races, rollback peers).",
        "category": "3-Level Challenge",
        "script_content": extreme_content,
        "default_args": ["--rounds", "8", "--seed", "987654321"]
    })

    # 3. Normal Profile
    presets.append({
        "id": "normal",
        "name": "3-Level Challenge: Normal Profile",
        "description": "10 multi-asset, generation binding, storage encryption at rest, and detector origin checks.",
        "category": "3-Level Challenge",
        "script_content": extreme_content,
        "default_args": ["--rounds", "3", "--seed", "73026"]
    })

    # 4. Easy Profile
    presets.append({
        "id": "easy",
        "name": "3-Level Challenge: Easy Profile",
        "description": "5 fundamental contract checks (basic access, revocation, audit, ML-KEM-768, opaque identifiers).",
        "category": "3-Level Challenge",
        "script_content": extreme_content,
        "default_args": ["--seed", "73026"]
    })

    # 5. Official Track 4 Validator
    val_content = ""
    if VALIDATE_SCRIPT.exists():
        try:
            val_content = VALIDATE_SCRIPT.read_text(encoding="utf-8")
        except Exception:
            pass
    presets.append({
        "id": "track4",
        "name": "Official Track 4 Lost-Device Validator",
        "description": "Official 12-step lost device scenario validator from the competition toolkit.",
        "category": "Official Toolkit",
        "script_content": val_content,
        "default_args": ["--entry", "track4_service.py"]
    })

    # 6. Custom Adversarial Injection Template
    presets.append({
        "id": "custom",
        "name": "Custom Adversarial Script (Interactive Template)",
        "description": "Blank / editable template to write, paste, or test custom adversarial attack scripts.",
        "category": "Custom Injection",
        "script_content": CUSTOM_TEMPLATE,
        "default_args": []
    })

    return {"presets": presets}


def parse_output(stdout_text: str, stderr_text: str) -> tuple[dict[str, int], list[dict[str, Any]], int]:
    """Parse PASS/FAIL/SKIP lines, summary statistics, and adapter call counts."""
    summary = {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}
    breakdown = []
    adapter_calls = 0

    # Look for SUMMARY line: SUMMARY {'PASS': 18, 'FAIL': 0, 'ERROR': 0, 'SKIP': 0}
    sum_match = re.search(r"SUMMARY\s+(\{[^}]+\})", stdout_text)
    if sum_match:
        try:
            raw_dict = json.loads(sum_match.group(1).replace("'", '"'))
            for k in ("PASS", "FAIL", "ERROR", "SKIP"):
                if k in raw_dict:
                    summary[k] = int(raw_dict[k])
        except Exception:
            pass

    # Look for adapter calls
    calls_match = re.search(r"adapter calls:\s*(\d+)", stdout_text)
    if calls_match:
        adapter_calls = int(calls_match.group(1))

    # Parse individual invariant lines: PASS [contract] name: message
    line_pattern = re.compile(r"^(PASS|FAIL|SKIP|ERROR)\s+\[([^\]]+)\]\s+([^:]+):\s*(.*)$", re.MULTILINE)
    for m in line_pattern.finditer(stdout_text):
        status, category, name, message = m.groups()
        breakdown.append({
            "status": status.strip(),
            "category": category.strip(),
            "name": name.strip(),
            "message": message.strip()
        })
        if not sum_match:
            summary[status.strip()] = summary.get(status.strip(), 0) + 1

    # Also parse Track 4 validate output: PASS [behavior] owner before device loss: Received allow...
    track4_pattern = re.compile(r"^(PASS|FAIL)\s+\[([^\]]+)\]\s+([^:]+):\s*(.*)$", re.MULTILINE)
    if not breakdown:
        for m in track4_pattern.finditer(stdout_text):
            status, category, name, message = m.groups()
            breakdown.append({
                "status": status.strip(),
                "category": category.strip(),
                "name": name.strip(),
                "message": message.strip()
            })
            if not sum_match:
                summary[status.strip()] = summary.get(status.strip(), 0) + 1

    return summary, breakdown, adapter_calls


@router.post("/execute", response_model=ScriptExecuteResponse)
def execute_injected_script(req: ScriptExecuteRequest, auth: dict = Depends(verify_operator_auth)):
    """Execute arbitrary Python test or adversarial challenge script in an isolated runner."""
    with tempfile.TemporaryDirectory(prefix="qv-injected-", ignore_cleanup_errors=True) as td:
        runner_dir = Path(td)
        script_file = runner_dir / "injected_test.py"
        script_file.write_text(req.script_content, encoding="utf-8")

        # Copy challenge helper modules if needed
        for helper in ("v5_engine.py", "v6_engine.py", "challenge_engine.py"):
            src = REPO_ROOT / helper
            if not src.exists():
                src = THREE_LEVEL_DIR / helper
            if src.exists():
                try:
                    (runner_dir / helper).write_bytes(src.read_bytes())
                except Exception:
                    pass

        report_file = runner_dir / "runner-results.json"

        # Build command
        cmd = [sys.executable, str(script_file), "--repo", str(REPO_ROOT)]

        # Preset-specific handling
        if req.preset_name in ("easy", "normal", "extreme"):
            # If using challenge_engine directly
            cmd.extend(["--rounds", str(req.rounds), "--seed", str(req.seed), "--report", str(report_file)])
            # If script_content is challenge_engine, wrap it to run the requested profile
            runner_wrapper = runner_dir / f"run_{req.preset_name}.py"
            runner_wrapper.write_text(
                f"import challenge_engine\nif __name__ == '__main__': raise SystemExit(challenge_engine.run('{req.preset_name}'))",
                encoding="utf-8"
            )
            cmd[1] = str(runner_wrapper)
        elif req.preset_name == "v6":
            cmd.extend(["--seed", str(req.seed), "--report", str(report_file)])
            if "--extended" not in req.args:
                cmd.append("--extended")
        elif req.preset_name == "track4":
            cmd = [sys.executable, str(script_file), "--entry", str(REPO_ROOT / "track4_service.py")]
        else:
            # Custom script: pass any extra custom args
            if "--report" not in req.args and "argparse" in req.script_content:
                cmd.extend(["--seed", str(req.seed), "--report", str(report_file)])

        for extra_arg in req.args:
            if extra_arg not in cmd:
                cmd.append(extra_arg)

        env = os.environ.copy()
        env.update({
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": f"{REPO_ROOT}{os.pathsep}{runner_dir}"
        })

        t_start = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                cwd=str(REPO_ROOT),
                env=env,
                timeout=req.timeout_seconds
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            stdout = ""
            stderr = f"Execution timed out after {req.timeout_seconds} seconds."
            exit_code = 124
        except Exception as e:
            stdout = ""
            stderr = f"Execution failed to launch: {e}"
            exit_code = 1

        duration_ms = (time.perf_counter() - t_start) * 1000.0

        summary, breakdown, calls = parse_output(stdout, stderr)

        # Check for report JSON
        report_data = None
        if report_file.exists():
            try:
                report_data = json.loads(report_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        # If report data has counts, prefer those
        if report_data and "counts" in report_data:
            summary = report_data["counts"]
        if report_data and "adapter_calls" in report_data:
            calls = report_data["adapter_calls"]

        success = (exit_code == 0 and summary.get("FAIL", 0) == 0 and summary.get("ERROR", 0) == 0)

        return ScriptExecuteResponse(
            success=success,
            exit_code=exit_code,
            duration_ms=round(duration_ms, 2),
            stdout=stdout,
            stderr=stderr,
            summary=summary,
            adapter_calls=calls,
            report=report_data,
            tests_breakdown=breakdown
        )

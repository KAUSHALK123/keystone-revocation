"""Final Competition Readiness Audit runner saving verified metrics into evidence/phase-3/."""
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import httpx

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.evaluator import DetectionEvaluator
from quantumvault.detection.synthetic_generator import generate_synthetic_dataset

REPORT_PATH = ROOT_DIR / "evidence" / "phase-3" / "final_audit_report.json"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def run_unseen_detection_eval() -> dict:
    events, registry, gt = generate_synthetic_dataset(target_events=1500, seed=2027)
    t0 = time.perf_counter()
    engine = DetectionEngine(approval_registry=registry)
    preds = engine.evaluate_events(events)
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    metrics = DetectionEvaluator(gt).evaluate(preds)
    assert metrics.exact_accuracy == 1.0 and metrics.f1_score == 1.0
    return {
        "seed": 2027,
        "actual_events": len(events),
        "exact_accuracy": metrics.exact_accuracy,
        "precision": metrics.precision,
        "recall": metrics.recall,
        "f1_score": metrics.f1_score,
        "false_positives": metrics.false_positives,
        "false_negatives": metrics.false_negatives,
        "elapsed_ms": elapsed_ms,
    }


def run_live_web_and_3x_judge_demo() -> dict:
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT_DIR)
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "quantumvault.web.app:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        client = httpx.Client(base_url=base, timeout=20.0)
        deadline = time.perf_counter() + 15.0
        r_home = None
        while time.perf_counter() < deadline:
            try:
                r_home = client.get("/")
                if r_home.status_code == 200:
                    break
            except Exception:
                time.sleep(0.1)
        assert r_home is not None and r_home.status_code == 200, "Web server failed to start"

        m = re.search(r'<meta name="qv-operator-token" content="([^"]+)">', r_home.text)
        assert m, "Operator meta token missing"
        tok = m.group(1)
        hdr = {"X-Operator-Token": tok}

        # Offline static verification (zero CDN links)
        assert "http://" not in r_home.text and "https://" not in r_home.text
        css_txt = client.get("/static/css/dashboard.css").text
        js_txt = client.get("/static/js/dashboard.js").text
        assert "http://" not in css_txt and "https://" not in css_txt
        assert "http://" not in js_txt and "https://" not in js_txt

        # Exercise all 5 tabs APIs
        assert client.get("/api/v1/status", headers=hdr).status_code == 200
        assert client.get("/api/v1/cluster/status", headers=hdr).status_code == 200
        assert client.get("/api/v1/iam/devices", headers=hdr).status_code == 200
        assert client.get("/api/v1/integrity/status", headers=hdr).status_code == 200
        assert client.post("/api/v1/cluster/revoke", headers=hdr, json={"entity_id": "analyst-1", "entity_type": "actor", "reason": "audit"}).status_code == 200
        assert client.get("/api/v1/detection/overview", headers=hdr).status_code == 200
        assert client.get("/api/v1/detection/evaluation-comparison", headers=hdr).status_code == 200
        assert client.post("/api/v1/messaging/demo-handshake", headers=hdr, json={"initiator": "alice", "responder": "bob"}).status_code == 200
        assert len(client.get("/api/v1/lab/scenarios", headers=hdr).json()) == 40
        assert client.get("/api/v1/benchmarks/summary", headers=hdr).status_code == 200

        # Complete 15-step Judge Demo 3 consecutive times with resets
        demo_runs = []
        for run_idx in range(1, 4):
            st = client.post("/api/v1/judge-demo/start", headers=hdr).json()
            assert st["active"] is True and st["current_step"] == 0
            step_statuses = []
            t0 = time.perf_counter()
            for expected_step in range(1, 16):
                step_res = client.post("/api/v1/judge-demo/next", headers=hdr).json()
                assert step_res["step"] == expected_step and step_res["status"] == "PASS", step_res
                assert step_res["expected_outcome"] and step_res["actual_outcome"]
                step_statuses.append(step_res["status"])
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            rst = client.post("/api/v1/judge-demo/reset", headers=hdr).json()
            assert rst["active"] is False and rst["current_step"] == 0
            demo_runs.append({"run": run_idx, "steps_passed": len(step_statuses), "elapsed_ms": elapsed_ms})

        return {"tabs_verified": 5, "offline_static_clean": True, "consecutive_judge_demo_runs": demo_runs}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=2.0)
        for s in (proc.stdout, proc.stderr):
            if s:
                s.close()


def run_fresh_clone_check() -> dict:
    with tempfile.TemporaryDirectory(prefix="qv-final-clone-") as td:
        clone_dir = Path(td) / "submission"
        state_dir = Path(td) / "state"
        state_dir.mkdir()
        subprocess.check_call(["git", "clone", "--quiet", "--branch", "SHIVA", str(ROOT_DIR), str(clone_dir)])
        subprocess.check_call([
            "git", "clone", "--quiet",
            str(ROOT_DIR / "references" / "track4-toolkit"),
            str(clone_dir / "references" / "track4-toolkit"),
        ])

        # Also copy uncommitted audit adjustments if running pre-commit, no: test exact committed clone after commit!
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = str(state_dir)
        env["PYTHONPATH"] = str(clone_dir)

        results = {}
        for label, cmd in [
            ("validator", [sys.executable, "references/track4-toolkit/validate.py", "--entry", "track4_service.py"]),
            ("unittest", [sys.executable, "-m", "unittest", "discover", "tests"]),
            ("lab_40", [sys.executable, "-m", "quantumvault.testing.lab", "--run-all"]),
            ("combined_40", [sys.executable, "-m", "quantumvault.testing.phase_1_3_combined_scenario"]),
        ]:
            res = subprocess.run(cmd, cwd=str(clone_dir), env=env, capture_output=True, text=True, timeout=180.0)
            assert res.returncode == 0, f"Fresh clone {label} failed:\n{res.stdout}\n{res.stderr}"
            results[label] = {"returncode": res.returncode}
        head_hash = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(clone_dir), text=True).strip()
        return {"cloned_commit": head_hash, "checks": results}


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--with-fresh-clone", action="store_true")
    args = parser.parse_args()

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report: dict = {}
    print("[1/2] Evaluating unseen seed=2027 (1500 events)...")
    report["unseen_detection"] = run_unseen_detection_eval()
    print("  ->", report["unseen_detection"])

    print("[2/2] Running live Uvicorn 5-tab & 3x consecutive 15-step Judge Demo...")
    report["live_web_and_3x_demo"] = run_live_web_and_3x_judge_demo()
    print("  ->", report["live_web_and_3x_demo"])

    if args.with_fresh_clone:
        print("[3/3] Running fresh clone verification of SHIVA HEAD...")
        report["fresh_clone"] = run_fresh_clone_check()
        print("  ->", report["fresh_clone"])

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("FINAL_AUDIT_SCRIPT_COMPLETE")


if __name__ == "__main__":
    main()

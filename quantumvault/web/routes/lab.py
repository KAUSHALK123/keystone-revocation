"""Security Laboratory and Evidence Viewer API routes."""
from pathlib import Path
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query
from quantumvault.testing.lab import SecurityLab
from quantumvault.testing.phase_1_3_combined_scenario import Phase13CombinedScenario
from quantumvault.web.authentication import verify_operator_auth
from quantumvault.web.schemas import (
    CombinedScenarioResponse,
    CombinedScenarioStepResult,
    LabRunResult,
    LabScenarioSummary,
)

router = APIRouter(prefix="/api/v1/lab", tags=["Security Laboratory"])

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
EVIDENCE_DIR = ROOT_DIR / "evidence"


def _categorize_scenario(name: str) -> str:
    if "pqc" in name or "dsa" in name or "crypto" in name or "dek" in name:
        return "Post-Quantum Cryptography"
    elif "device" in name or "auth" in name or "recovery" in name:
        return "Identity & Device Security"
    elif "cluster" in name or "node" in name or "revocation" in name or "partition" in name:
        return "Distributed Security"
    elif "rotation" in name or "grace" in name or "cutoff" in name or "retired" in name:
        return "Key Lifecycle"
    elif "backup" in name or "crash" in name or "wal" in name:
        return "Crash & Backup Resilience"
    elif "audit" in name or "checkpoint" in name:
        return "Audit Integrity"
    elif "role" in name or "lateral" in name or "clock" in name or "denial" in name or "practice" in name:
        return "Threat Detection"
    elif "message" in name or "replay" in name or "forward_secrecy" in name or "chunk" in name or "outbox" in name or "resumption" in name:
        return "Secure Messaging"
    return "Core Security"


@router.get("/scenarios", response_model=list[LabScenarioSummary])
def list_scenarios(auth: dict = Depends(verify_operator_auth)):
    """List all 40 registered security test scenarios with category and description."""
    lab = SecurityLab()
    scenarios = lab.list_scenarios()
    return [
        LabScenarioSummary(
            name=s["name"],
            category=_categorize_scenario(s["name"]),
            description=s["description"]
        )
        for s in scenarios
    ]


@router.post("/run", response_model=LabRunResult)
def run_scenario(name: str = Query(...), auth: dict = Depends(verify_operator_auth)):
    """Run an individual security laboratory scenario live."""
    lab = SecurityLab()
    try:
        res = lab.run_scenario(name)
        return LabRunResult(
            name=name,
            passed=(res.get("status") == "PASS"),
            duration_ms=round(res.get("elapsed_ms", 0.0), 2),
            detail=str(res.get("details", ""))
        )
    except Exception as e:
        return LabRunResult(
            name=name,
            passed=False,
            duration_ms=0.0,
            detail=f"Error executing scenario: {e}"
        )


@router.post("/run-all")
def run_all_scenarios(auth: dict = Depends(verify_operator_auth)):
    """Run all 40 registered security scenarios live and return consolidated results."""
    lab = SecurityLab()
    t_start = lab.list_scenarios()
    results = []
    total_passed = 0
    total_failed = 0

    for s in t_start:
        name = s["name"]
        res = lab.run_scenario(name)
        passed = (res.get("status") == "PASS")
        if passed:
            total_passed += 1
        else:
            total_failed += 1
        results.append({
            "name": name,
            "category": _categorize_scenario(name),
            "passed": passed,
            "duration_ms": round(res.get("elapsed_ms", 0.0), 2),
            "description": s["description"]
        })

    return {
        "total_scenarios": len(results),
        "total_passed": total_passed,
        "total_failed": total_failed,
        "all_passed": (total_failed == 0),
        "results": results
    }


@router.post("/run-combined", response_model=CombinedScenarioResponse)
def run_combined_scenario(auth: dict = Depends(verify_operator_auth)):
    """Execute the flagship 40-step combined failure scenario live."""
    scenario = Phase13CombinedScenario()
    res = scenario.run()

    step_results = [
        CombinedScenarioStepResult(
            step=s["step"],
            title=s["title"],
            status=s["status"],
            details=s.get("details", {})
        )
        for s in res.step_details
    ]

    return CombinedScenarioResponse(
        success=res.success,
        steps_passed=res.steps_passed,
        total_steps=res.total_steps,
        execution_time_ms=round(res.execution_time_ms, 2),
        steps=step_results
    )


@router.get("/evidence/list")
def list_evidence_files(auth: dict = Depends(verify_operator_auth)):
    """List verified evidence files available for inspection."""
    if not EVIDENCE_DIR.exists():
        return {"files": []}

    files = []
    for p in EVIDENCE_DIR.glob("**/*"):
        if p.is_file():
            rel_path = str(p.relative_to(EVIDENCE_DIR)).replace("\\", "/")
            files.append({
                "path": rel_path,
                "size_bytes": p.stat().st_size,
                "name": p.name
            })
    return {"files": sorted(files, key=lambda x: x["path"])}


@router.get("/evidence/view")
def view_evidence_file(file_path: str = Query(..., min_length=1, max_length=256),
                       auth: dict = Depends(verify_operator_auth)):
    """Retrieve content of an evidence file with strict traversal, sibling-prefix, and symlink guards."""
    evidence_root = EVIDENCE_DIR.resolve()
    candidate = EVIDENCE_DIR / file_path

    # Reject explicit parent references and symlinks anywhere along the relative path
    if ".." in Path(file_path).parts:
        raise HTTPException(status_code=403, detail="Access denied: Path traversal detected")

    target = candidate.resolve()
    try:
        is_inside = target.is_relative_to(evidence_root)
    except AttributeError:
        is_inside = evidence_root in target.parents or target == evidence_root

    if not is_inside or target == evidence_root:
        raise HTTPException(status_code=403, detail="Access denied: Path traversal detected")

    # Reject symlinks pointing outside evidence_root
    check_path = candidate
    while True:
        if check_path.is_symlink():
            raise HTTPException(status_code=403, detail="Access denied: Symlink escape prohibited")
        if check_path == EVIDENCE_DIR or check_path == check_path.parent:
            break
        check_path = check_path.parent

    if not target.is_file():
        raise HTTPException(status_code=404, detail=f"Evidence file '{file_path}' not found")

    try:
        content = target.read_text(encoding="utf-8")
        return {
            "path": file_path,
            "size_bytes": len(content),
            "content": content
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unable to read file: {e}")

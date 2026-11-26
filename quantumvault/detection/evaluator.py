"""Evaluation suite computing precision, recall, F1, confusion matrix, and alert latency."""
import statistics
from typing import Any

from quantumvault.detection.models import ClassificationResult, EvaluationMetrics

SUSPICIOUS_LABELS = {
    "unexpected_role_change",
    "review_after_role_change",
    "lateral_movement_candidate",
}


class DetectionEvaluator:
    """Evaluates classification performance against independent ground-truth labels."""

    def __init__(self, ground_truth_labels: dict[str, dict[str, str]]):
        self.ground_truth = ground_truth_labels

    def evaluate(self, results: list[ClassificationResult]) -> EvaluationMetrics:
        """Calculate comprehensive evaluation metrics."""
        total = len(results)
        exact_matches = 0
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        alert_latencies: list[float] = []

        confusion_matrix: dict[str, dict[str, int]] = {}

        for res in results:
            gt_info = self.ground_truth.get(res.event_id)
            if not gt_info:
                continue

            true_label = gt_info["label"]
            pred_label = res.label

            # Multi-class confusion matrix
            if true_label not in confusion_matrix:
                confusion_matrix[true_label] = {}
            confusion_matrix[true_label][pred_label] = confusion_matrix[true_label].get(pred_label, 0) + 1

            # Exact label match
            if pred_label == true_label:
                exact_matches += 1

            # Binary alert evaluation (Suspicious Threat vs Routine Activity)
            true_suspicious = true_label in SUSPICIOUS_LABELS
            pred_suspicious = pred_label in SUSPICIOUS_LABELS

            if pred_suspicious and true_suspicious:
                tp += 1
                alert_latencies.append(res.latency_ms)
            elif pred_suspicious and not true_suspicious:
                fp += 1
                alert_latencies.append(res.latency_ms)
            elif not pred_suspicious and not true_suspicious:
                tn += 1
            else:  # not pred_suspicious and true_suspicious
                fn += 1

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 1.0
        exact_acc = (exact_matches / total) if total > 0 else 0.0
        median_latency = statistics.median(alert_latencies) if alert_latencies else 0.0

        return EvaluationMetrics(
            total_events=total,
            exact_matches=exact_matches,
            exact_accuracy=exact_acc,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            median_time_to_alert_ms=median_latency,
            confusion_matrix=confusion_matrix
        )


def evaluate_practice_dataset(
    events_path: Any = None,
    labels_path: Any = None,
    approvals_path: Any = None,
    practice_dir: Any = None,
    **kwargs: Any
) -> dict[str, Any]:
    """Module-level evaluator for independent test suites and probes."""
    from pathlib import Path
    from quantumvault.detection.engine import DetectionEngine
    from quantumvault.detection.ingestion import (
        load_approvals_from_json,
        load_events_from_csv,
        load_labels_from_csv,
    )

    pdir = Path(practice_dir) if practice_dir else None
    epath = (
        events_path
        or kwargs.get("events_csv")
        or kwargs.get("events_file")
        or kwargs.get("events_csv_path")
        or (pdir / "events.csv" if pdir else None)
    )
    apath = (
        approvals_path
        or kwargs.get("approvals_json")
        or kwargs.get("approvals_file")
        or kwargs.get("approvals_json_path")
        or (pdir / "approvals.json" if pdir else None)
    )

    events = load_events_from_csv(epath)
    approvals = load_approvals_from_json(apath) if apath else {}

    engine = DetectionEngine(approval_registry=approvals)
    results = engine.evaluate_events(events)

    predictions = {r.event_id: r.label for r in results}
    return {
        "predictions": predictions,
        "results": [{"event_id": r.event_id, "predicted_label": r.label} for r in results],
    }

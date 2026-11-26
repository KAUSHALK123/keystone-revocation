"""Unit tests for Telemetry Ingestion, Threat Detection Engine, Graph Topology, and Metrics."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from quantumvault.detection.approvals import ApprovalRegistry
from quantumvault.detection.clock import ClockNormalizer, correct_timestamp, parse_iso_timestamp
from quantumvault.detection.engine import DetectionEngine
from quantumvault.detection.evaluator import DetectionEvaluator
from quantumvault.detection.ingestion import (
    load_approvals_from_json,
    load_events_from_csv,
    load_labels_from_csv,
)
from quantumvault.detection.models import ApprovalChange, SecurityEvent
from quantumvault.detection.service_graph import ServiceGraph
from quantumvault.storage.db import get_connection, init_db


class TestTelemetryAndClock(unittest.TestCase):
    def test_tel01_csv_ingestion(self):
        try:
            evts = load_events_from_csv("data/practice/events.csv")
        except FileNotFoundError as e:
            raise unittest.SkipTest(f"Practice dataset missing: {e}")
        self.assertEqual(len(evts), 22)
        self.assertEqual(evts[0].event_id, "evt-001")
        self.assertEqual(evts[0].actor, "user-alex")
        self.assertEqual(evts[0].source_service, "portal")
        self.assertEqual(evts[0].target_service, "identity")

    def test_tel02_labels_ingestion(self):
        try:
            labels = load_labels_from_csv("data/practice/labels.csv")
        except FileNotFoundError as e:
            raise unittest.SkipTest(f"Practice dataset missing: {e}")
        self.assertEqual(len(labels), 22)
        self.assertEqual(labels["evt-001"]["label"], "routine")
        self.assertEqual(labels["evt-008"]["label"], "unexpected_role_change")
        self.assertEqual(labels["evt-010"]["label"], "lateral_movement_candidate")

    def test_tel03_approvals_ingestion(self):
        try:
            apprs = load_approvals_from_json("data/practice/approvals.json")
        except FileNotFoundError as e:
            raise unittest.SkipTest(f"Practice dataset missing: {e}")
        c100 = apprs.get("change-100")
        self.assertIsNotNone(c100)
        self.assertEqual(c100.subject, "user-alex")
        self.assertEqual(c100.role, "report-reader")
        self.assertEqual(c100.scope, ["reports", "reports-node-a", "reports-node-b"])

    def test_clk01_offset_correction(self):
        # evt-015 has source_clock_offset_ms = 2000
        event_time = "2026-01-15T09:06:03.000Z"
        corrected = correct_timestamp(event_time, 2000)
        self.assertEqual(corrected, "2026-01-15T09:06:01.000Z")

    def test_clk02_zero_offset(self):
        event_time = "2026-01-15T09:00:00.000Z"
        corrected = correct_timestamp(event_time, 0)
        self.assertEqual(corrected, "2026-01-15T09:00:00.000Z")

    def test_clk03_out_of_order_arrival_detection(self):
        normalizer = ClockNormalizer()
        e14 = SecurityEvent(
            event_id="evt-014",
            event_time_utc="2026-01-15T09:05:02.000Z",
            received_time_utc="2026-01-15T09:05:02.200Z",
            source_clock_offset_ms=0,
            actor="user-alex",
            source_service="portal",
            target_service="reports",
            action="read",
            role_before="report-reader",
            role_after="report-reader",
            outcome="allow"
        )
        e13 = SecurityEvent(
            event_id="evt-013",
            event_time_utc="2026-01-15T09:05:01.000Z",
            received_time_utc="2026-01-15T09:05:04.200Z",  # Arrived later than e14!
            source_clock_offset_ms=0,
            actor="user-alex",
            source_service="portal",
            target_service="catalog",
            action="read",
            role_before="report-reader",
            role_after="report-reader",
            outcome="allow"
        )
        normalizer.normalize_event(e14)
        a14 = normalizer.detect_anomalies(e14)
        self.assertFalse(a14["is_out_of_order"])

        normalizer.normalize_event(e13)
        a13 = normalizer.detect_anomalies(e13)
        self.assertTrue(a13["is_out_of_order"])


class TestThreatDetectionEngine(unittest.TestCase):
    def setUp(self):
        try:
            self.events = load_events_from_csv("data/practice/events.csv")
            self.labels = load_labels_from_csv("data/practice/labels.csv")
            self.approvals = load_approvals_from_json("data/practice/approvals.json")
        except FileNotFoundError as e:
            raise unittest.SkipTest(f"Practice dataset missing: {e}")
        self.engine = DetectionEngine(approval_registry=self.approvals)

    def test_det01_practice_dataset_100_percent_accuracy(self):
        results = self.engine.evaluate_events(self.events)
        evaluator = DetectionEvaluator(self.labels)
        metrics = evaluator.evaluate(results)
        self.assertEqual(metrics.exact_matches, 22)
        self.assertEqual(metrics.exact_accuracy, 1.0)
        self.assertEqual(metrics.precision, 1.0)
        self.assertEqual(metrics.recall, 1.0)
        self.assertEqual(metrics.f1_score, 1.0)

    def test_det02_unexpected_role_change_incident(self):
        results = self.engine.evaluate_events(self.events)
        res_008 = next(r for r in results if r.event_id == "evt-008")
        self.assertEqual(res_008.label, "unexpected_role_change")
        self.assertTrue(res_008.is_suspicious)
        self.assertIsNotNone(res_008.incident_id)

        incidents = self.engine.get_incidents()
        inc = next(i for i in incidents if i.incident_id == res_008.incident_id)
        self.assertEqual(inc.incident_type, "unexpected_role_change")
        self.assertEqual(inc.actor_id, "user-blair")

    def test_det03_review_after_role_change(self):
        results = self.engine.evaluate_events(self.events)
        res_009 = next(r for r in results if r.event_id == "evt-009")
        self.assertEqual(res_009.label, "review_after_role_change")
        self.assertTrue(res_009.is_suspicious)
        self.assertIn("evt-008", res_009.evidence_event_ids)

    def test_lat01_candidate_lateral_movement_sequence(self):
        results = self.engine.evaluate_events(self.events)
        r10 = next(r for r in results if r.event_id == "evt-010")
        r11 = next(r for r in results if r.event_id == "evt-011")
        r12 = next(r for r in results if r.event_id == "evt-012")
        self.assertEqual(r10.label, "lateral_movement_candidate")
        self.assertEqual(r11.label, "lateral_movement_candidate")
        self.assertEqual(r12.label, "lateral_movement_candidate")
        self.assertEqual(r10.incident_id, r11.incident_id)
        self.assertEqual(r11.incident_id, r12.incident_id)

    def test_lat02_isolated_denial_distinction(self):
        results = self.engine.evaluate_events(self.events)
        r20 = next(r for r in results if r.event_id == "evt-020")
        self.assertEqual(r20.label, "isolated_denial")
        self.assertFalse(r20.is_suspicious)

    def test_lat03_routine_denial_after_revocation(self):
        results = self.engine.evaluate_events(self.events)
        r17 = next(r for r in results if r.event_id == "evt-017")
        r18 = next(r for r in results if r.event_id == "evt-018")
        self.assertEqual(r17.label, "routine_denial")
        self.assertEqual(r18.label, "routine_denial")

    def test_met01_confusion_matrix_structure(self):
        results = self.engine.evaluate_events(self.events)
        evaluator = DetectionEvaluator(self.labels)
        metrics = evaluator.evaluate(results)
        self.assertIn("routine", metrics.confusion_matrix)
        self.assertIn("lateral_movement_candidate", metrics.confusion_matrix)
        self.assertEqual(metrics.confusion_matrix["routine"]["routine"], 9)
        self.assertEqual(metrics.confusion_matrix["lateral_movement_candidate"]["lateral_movement_candidate"], 3)


class TestServiceGraph(unittest.TestCase):
    def test_graph01_expected_edges(self):
        g = ServiceGraph()
        self.assertTrue(g.is_expected("portal", "identity"))
        self.assertTrue(g.is_expected("portal", "catalog"))
        self.assertTrue(g.is_expected("reports", "catalog"))

    def test_graph02_unexpected_edges(self):
        g = ServiceGraph()
        self.assertFalse(g.is_expected("reports", "billing"))
        self.assertFalse(g.is_expected("billing", "archive"))
        self.assertFalse(g.is_expected("archive", "identity"))


if __name__ == "__main__":
    unittest.main()

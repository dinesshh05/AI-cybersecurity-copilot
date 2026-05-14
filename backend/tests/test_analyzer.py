from __future__ import annotations

import unittest

from app.services.anomaly import score_log_text
from app.services.analyzer import analyze_log_text
from app.services.rag import rebuild_knowledge_base, search_knowledge


class AnalyzerTests(unittest.TestCase):
    def test_detects_high_risk_security_incident(self) -> None:
        log_text = """Failed password for invalid user admin from 185.220.101.1 port 52144 ssh2
powershell.exe -enc SQBFAFgAIAA=
malware beaconing to 203.0.113.42
scanner found CVE-2024-3094 on package xz-utils"""

        result = analyze_log_text(log_text, source_name="unit-test")

        self.assertEqual(result.severity, "critical")
        self.assertGreaterEqual(result.risk_score, 85)
        self.assertTrue(any(item.kind == "cve" for item in result.indicators))
        self.assertTrue(any("patch" in step.lower() for step in result.remediation))

    def test_keeps_benign_log_low_risk(self) -> None:
        result = analyze_log_text("service started successfully\nheartbeat received", source_name="unit-test")

        self.assertEqual(result.severity, "low")
        self.assertLessEqual(result.risk_score, 25)

    def test_rag_retrieval_returns_matches(self) -> None:
        rebuild_knowledge_base()
        items = search_knowledge("PowerShell command execution", limit=3)

        self.assertGreaterEqual(len(items), 1)
        self.assertTrue(any("PowerShell" in item.title for item in items))

    def test_anomaly_scoring_flags_bad_log(self) -> None:
        report = score_log_text(
            """Failed password for invalid user admin from 185.220.101.1
powershell.exe -enc SQBFAFgAIAA=
malware beaconing to 203.0.113.42
scanner found CVE-2024-3094"""
        )

        self.assertGreaterEqual(report.score, 60)
        self.assertIn("Suspicious command execution pattern", report.signals)


if __name__ == "__main__":
    unittest.main()

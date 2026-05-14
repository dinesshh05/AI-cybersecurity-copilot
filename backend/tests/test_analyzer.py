from __future__ import annotations

import unittest

from app.services.analyzer import analyze_log_text


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


if __name__ == "__main__":
    unittest.main()


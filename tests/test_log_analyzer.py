import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from src.log_analyzer import analyze_log


class TestLogAnalyzer(unittest.TestCase):
    def test_detects_repeated_failed_attempts(self):
        with TemporaryDirectory() as temp_dir:
            log = Path(temp_dir) / "auth.log"
            log.write_text(
                "Failed password for admin from 203.0.113.25 port 1 ssh2\n"
                "Failed password for root from 203.0.113.25 port 2 ssh2\n"
                "Failed password for guest from 203.0.113.25 port 3 ssh2\n",
                encoding="utf-8"
            )
            result = analyze_log(log, threshold=3)
            self.assertEqual(len(result["failed_attempts"]), 3)
            self.assertIn("203.0.113.25", result["suspicious_ips"])


if __name__ == "__main__":
    unittest.main()

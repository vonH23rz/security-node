import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "scripts" / "generate-example-scanner-results.py"
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"
EXAMPLE_CONFIG = ROOT / "examples" / "config.example.yaml"
PLACEHOLDER = "REPLACE_WITH_CURRENT_ISO8601_TIMESTAMP"


class ExampleScannerResultsGeneratorTests(unittest.TestCase):
    def test_generator_writes_fresh_renderable_example_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_results = Path(tmpdir) / "scanner-results.yaml"
            dashboard = Path(tmpdir) / "dashboard.html"

            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    "--output",
                    str(scanner_results),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(scanner_results.exists())
            self.assertIn("Security Node example scanner evidence generator", result.stdout)
            self.assertIn(f"output={scanner_results}", result.stdout)
            self.assertNotIn(PLACEHOLDER, scanner_results.read_text(encoding="utf-8"))

            data = yaml.safe_load(scanner_results.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 2)
            self.assertIsInstance(data[0]["checked_at"], str)
            self.assertIsInstance(data[1]["checked_at"], str)

            render_result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results),
                    "--output",
                    str(dashboard),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(render_result.returncode, 0, render_result.stdout + render_result.stderr)
            rendered = dashboard.read_text(encoding="utf-8")

            self.assertIn("Security Confidence: MEDIUM", rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 0", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 4)
            self.assertNotIn("No scanner results collected yet.", rendered)

    def test_generator_accepts_explicit_timestamp(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_results = Path(tmpdir) / "scanner-results.yaml"
            timestamp = "2026-01-01T00:00:00+00:00"

            result = subprocess.run(
                [
                    sys.executable,
                    str(GENERATOR),
                    "--output",
                    str(scanner_results),
                    "--timestamp",
                    timestamp,
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = yaml.safe_load(scanner_results.read_text(encoding="utf-8"))
            self.assertEqual(data[0]["checked_at"], timestamp)
            self.assertEqual(data[1]["checked_at"], timestamp)
            self.assertIn(f"checked_at={timestamp}", result.stdout)


if __name__ == "__main__":
    unittest.main()

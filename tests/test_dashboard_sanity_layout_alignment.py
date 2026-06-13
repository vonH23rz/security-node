import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"
GENERATOR = ROOT / "scripts" / "generate-example-scanner-results.py"
EXAMPLE_CONFIG = ROOT / "examples" / "config.example.yaml"


class DashboardSanityLayoutAlignmentTests(unittest.TestCase):
    def test_dashboard_uses_wide_header_status_and_top_information_layout(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_results = Path(tmpdir) / "scanner-results.yaml"
            dashboard = Path(tmpdir) / "dashboard.html"

            generate_result = subprocess.run(
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
            self.assertEqual(generate_result.returncode, 0, generate_result.stdout + generate_result.stderr)

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

            self.assertIn("max-width: 118rem", rendered)
            self.assertIn('class="page-header-meta"', rendered)
            self.assertIn('class="security-status-strip status-strip-confidence-medium"', rendered)
            self.assertIn('class="top-information-grid"', rendered)
            self.assertIn("Security Confidence: MEDIUM", rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 0", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn("Config schema validation passed before rendering.", rendered)
            self.assertNotIn('class="page-status-panel"', rendered)


if __name__ == "__main__":
    unittest.main()

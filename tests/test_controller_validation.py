import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"
EXAMPLE_CONFIG = ROOT / "examples" / "config.example.yaml"


class ControllerValidationTests(unittest.TestCase):
    def test_controller_renders_when_config_is_valid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(output.exists())
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("Security Node", rendered)
            self.assertIn("Site: Example Homelab", rendered)
            self.assertIn("Security Confidence: UNKNOWN", rendered)
            self.assertIn("Verification Level: Controller only", rendered)
            self.assertIn("Config schema validation passed before rendering.", rendered)
            self.assertIn("Controller ID", rendered)
            self.assertIn("controller", rendered)
            self.assertIn("Controller Display Name", rendered)
            self.assertIn("Security Node Controller", rendered)
            self.assertIn("Controller Network", rendered)
            self.assertIn("lan", rendered)
            self.assertIn("Controller Capabilities", rendered)
            self.assertIn("reachability, nmap", rendered)
            self.assertIn("Networks: 1", rendered)
            self.assertIn("Hosts: 1", rendered)
            self.assertIn("Probes: 0", rendered)
            self.assertIn("Accepted Risks: 0", rendered)
            self.assertIn("External Exposure Expectations: 0", rendered)
            self.assertIn("Expected Verification Surface Items: 2", rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 0", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn("Expected Verification Surface", rendered)
            self.assertIn("Configured host ports that should be checked by future scanner logic.", rendered)
            self.assertIn("Observed Scanner Results", rendered)
            self.assertIn("Scanner result model is prepared, but live scanner logic is not implemented yet.", rendered)
            self.assertIn("No scanner results collected yet.", rendered)
            self.assertIn("<th>Observed State</th>", rendered)
            self.assertIn("<th>Source</th>", rendered)
            self.assertIn("<th>Checked At</th>", rendered)
            self.assertIn("Router", rendered)
            self.assertIn("192.168.1.1", rendered)
            self.assertIn("TCP", rendered)
            self.assertIn("<td>80</td>", rendered)
            self.assertIn("<td>443</td>", rendered)
            self.assertIn("<th>Status</th>", rendered)
            self.assertEqual(rendered.count('class="status status-not-verified">NOT VERIFIED</span>'), 2)
            self.assertIn(".status-not-verified", rendered)
            self.assertIn(".status-verified", rendered)
            self.assertIn(".status-unexpected", rendered)
            self.assertIn(".status-accepted", rendered)
            self.assertIn(".status-unknown", rendered)
            self.assertNotIn(">OK</span>", rendered)
            self.assertIn("summary: 0 error(s), 0 warning(s)", result.stdout)
            self.assertIn("Wrote dashboard from validated state model", result.stdout)

    def test_controller_renders_optional_scanner_results_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    """
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "2026-06-12T10:00:00+00:00"
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("Expected Surface NOT VERIFIED: 1", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn("imported-test-evidence", rendered)
            self.assertIn("2026-06-12T10:00:00+00:00", rendered)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 2)
            self.assertEqual(rendered.count('class="status status-not-verified">NOT VERIFIED</span>'), 1)
            self.assertNotIn(">OK</span>", rendered)

    def test_controller_does_not_verify_expected_surface_from_nonmatching_evidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    """
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 22
                      observed_state: VERIFIED
                      source: imported-nonmatching-test-evidence
                      checked_at: "2026-06-12T10:00:00+00:00"
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 1", rendered)
            self.assertIn("imported-nonmatching-test-evidence", rendered)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 1)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 0)
            self.assertEqual(rendered.count('class="status status-not-verified">NOT VERIFIED</span>'), 2)
            self.assertNotIn(">OK</span>", rendered)

    def test_controller_keeps_matching_verified_evidence_verified(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    """
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-matching-test-evidence
                      checked_at: "2026-06-12T10:00:00+00:00"
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("Expected Surface NOT VERIFIED: 1", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn("imported-matching-test-evidence", rendered)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 2)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 0)
            self.assertEqual(rendered.count('class="status status-not-verified">NOT VERIFIED</span>'), 1)
            self.assertNotIn(">OK</span>", rendered)

    def test_controller_refuses_invalid_scanner_results_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    """
                    host_id: router
                    host_address: 192.168.1.1
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn("scanner results file must contain a YAML list", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_unknown_scanner_result_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    """
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: OPEN
                      source: imported-test-evidence
                      checked_at: "2026-06-12T10:00:00+00:00"
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn(
                "scanner result #1: observed_state must be one of: ACCEPTED, UNEXPECTED, UNKNOWN, VERIFIED",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_unknown_scanner_result_protocol(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    """
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: icmp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "2026-06-12T10:00:00+00:00"
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn(
                "scanner result #1: protocol must be one of: tcp, udp",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_to_render_when_config_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "invalid.yaml"
            output = Path(tmpdir) / "index.html"

            config.write_text(
                textwrap.dedent(
                    """
                    site:
                      name: Broken
                    controller:
                      id: controller
                      network: missing_network
                      capabilities: [reachability]
                    networks: []
                    hosts: []
                    probes: []
                    accepted_risks: []
                    external_exposure:
                      expected: []
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(config),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertIn("FAILED: refusing to render dashboard from invalid config", result.stdout)
            self.assertIn("networks: must contain at least one network", result.stdout)
            self.assertIn("controller.network: references unknown network", result.stdout)


if __name__ == "__main__":
    unittest.main()

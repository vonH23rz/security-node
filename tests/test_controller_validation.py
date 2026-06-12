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
            self.assertIn('class="page-body"', rendered)
            self.assertIn('class="page-main"', rendered)
            self.assertIn('class="page-header"', rendered)
            self.assertIn('class="page-title">Security Node</h1>', rendered)
            self.assertIn('class="page-meta site-name">Site: Example Homelab</p>', rendered)
            self.assertIn('class="page-meta page-security-confidence"', rendered)
            self.assertIn('class="security-confidence confidence-unknown"', rendered)
            self.assertIn('aria-label="Security Confidence: UNKNOWN"', rendered)
            self.assertIn('class="confidence-label">Security Confidence:</span>', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn(".security-confidence", rendered)
            self.assertIn(".confidence-label", rendered)
            self.assertIn(".confidence-badge", rendered)
            self.assertIn(".page-body", rendered)
            self.assertIn(".page-main", rendered)
            self.assertIn(".page-header", rendered)
            self.assertIn(".page-title", rendered)
            self.assertIn(".page-meta", rendered)
            self.assertIn(".site-name", rendered)
            self.assertIn(".verification-level", rendered)
            self.assertIn(".validation-notice", rendered)
            self.assertIn(".page-footer", rendered)
            self.assertIn(".scanner-implementation-notice", rendered)
            self.assertIn(".generated-timestamp", rendered)
            self.assertIn(".confidence-unknown", rendered)
            self.assertIn(".confidence-low", rendered)
            self.assertIn(".confidence-medium", rendered)
            self.assertIn("Verification Level: Controller only", rendered)
            self.assertIn('class="page-meta verification-level">Verification Level: Controller only</p>', rendered)
            self.assertIn("Config schema validation passed before rendering.", rendered)
            self.assertIn('class="page-meta validation-notice">Config schema validation passed before rendering.</p>', rendered)
            self.assertIn('class="page-footer"', rendered)
            self.assertIn('class="scanner-implementation-notice">Scanner logic is not implemented yet.</p>', rendered)
            self.assertIn('class="generated-timestamp">Generated: ', rendered)
            self.assertIn("Controller ID", rendered)
            self.assertIn("controller", rendered)
            self.assertIn("Controller Display Name", rendered)
            self.assertIn("Security Node Controller", rendered)
            self.assertIn("Controller Network", rendered)
            self.assertIn("lan", rendered)
            self.assertIn("Controller Capabilities", rendered)
            self.assertIn("reachability, nmap", rendered)
            self.assertIn('class="controller-state-section"', rendered)
            self.assertIn('class="controller-state-heading"', rendered)
            self.assertIn('class="controller-state-list"', rendered)
            self.assertIn('class="controller-state-term controller-state-controller-id-label"', rendered)
            self.assertIn('class="controller-state-value controller-state-controller-id">controller</dd>', rendered)
            self.assertIn('class="controller-state-term controller-state-display-name-label"', rendered)
            self.assertIn('class="controller-state-value controller-state-display-name">Security Node Controller</dd>', rendered)
            self.assertIn('class="controller-state-term controller-state-network-label"', rendered)
            self.assertIn('class="controller-state-value controller-state-network">lan</dd>', rendered)
            self.assertIn('class="controller-state-term controller-state-capabilities-label"', rendered)
            self.assertIn('class="controller-state-value controller-state-capabilities">reachability, nmap</dd>', rendered)
            self.assertIn(".controller-state-section", rendered)
            self.assertIn(".controller-state-heading", rendered)
            self.assertIn(".controller-state-list", rendered)
            self.assertIn(".controller-state-term", rendered)
            self.assertIn(".controller-state-value", rendered)
            self.assertIn("Networks: 1", rendered)
            self.assertIn("Hosts: 1", rendered)
            self.assertIn("Probes: 0", rendered)
            self.assertIn("Accepted Risks: 0", rendered)
            self.assertIn("External Exposure Expectations: 0", rendered)
            self.assertIn("Expected Verification Surface Items: 2", rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 0", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn('class="configuration-summary-section" aria-labelledby="configuration-summary"', rendered)
            self.assertIn('id="configuration-summary" class="configuration-summary-heading">Configuration Summary</h2>', rendered)
            self.assertIn(".configuration-summary-section", rendered)
            self.assertIn(".configuration-summary-heading", rendered)
            self.assertIn('class="posture-summary configuration-summary-list"', rendered)
            self.assertIn('class="summary-metric summary-metric-networks configuration-summary-metric configuration-summary-metric-networks"', rendered)
            self.assertIn('class="summary-metric summary-metric-hosts configuration-summary-metric configuration-summary-metric-hosts"', rendered)
            self.assertIn('class="summary-metric summary-metric-probes configuration-summary-metric configuration-summary-metric-probes"', rendered)
            self.assertIn('class="summary-metric summary-metric-accepted-risks configuration-summary-metric configuration-summary-metric-accepted-risks"', rendered)
            self.assertIn('class="summary-metric summary-metric-external-exposure configuration-summary-metric configuration-summary-metric-external-exposure"', rendered)
            self.assertIn('class="summary-metric summary-metric-expected-surface configuration-summary-metric configuration-summary-metric-expected-surface"', rendered)
            self.assertIn('class="summary-metric summary-metric-expected-not-verified configuration-summary-metric configuration-summary-metric-expected-not-verified"', rendered)
            self.assertIn('class="summary-metric summary-metric-observed-results configuration-summary-metric configuration-summary-metric-observed-results"', rendered)
            self.assertIn('class="summary-metric summary-metric-unexpected configuration-summary-metric configuration-summary-metric-unexpected"', rendered)
            self.assertIn(".posture-summary", rendered)
            self.assertIn(".configuration-summary-list", rendered)
            self.assertIn(".summary-metric", rendered)
            self.assertIn(".configuration-summary-metric", rendered)
            self.assertIn(".summary-metric-unexpected", rendered)
            self.assertIn(".configuration-summary-metric-unexpected", rendered)
            self.assertIn("Expected Verification Surface", rendered)
            self.assertIn("Configured host ports that should be checked by future scanner logic.", rendered)
            self.assertIn('class="expected-surface-section" aria-labelledby="expected-verification-surface"', rendered)
            self.assertIn('id="expected-verification-surface" class="expected-surface-heading">Expected Verification Surface</h2>', rendered)
            self.assertIn('class="expected-surface-description">Configured host ports that should be checked by future scanner logic.</p>', rendered)
            self.assertIn(".expected-surface-section", rendered)
            self.assertIn(".expected-surface-heading", rendered)
            self.assertIn(".expected-surface-description", rendered)
            self.assertIn('class="expected-surface-table"', rendered)
            self.assertIn('class="expected-surface-header-row"', rendered)
            self.assertIn('class="expected-surface-header-cell expected-surface-header-host">Host</th>', rendered)
            self.assertIn('class="expected-surface-header-cell expected-surface-header-address">Address</th>', rendered)
            self.assertIn('class="expected-surface-header-cell expected-surface-header-network">Network</th>', rendered)
            self.assertIn('class="expected-surface-header-cell expected-surface-header-protocol">Protocol</th>', rendered)
            self.assertIn('class="expected-surface-header-cell expected-surface-header-port">Port</th>', rendered)
            self.assertIn('class="expected-surface-header-cell expected-surface-header-status">Status</th>', rendered)
            self.assertEqual(rendered.count('class="expected-surface-row"'), 2)
            self.assertIn('class="expected-surface-cell expected-surface-host">Router</td>', rendered)
            self.assertIn('class="expected-surface-cell expected-surface-address">192.168.1.1</td>', rendered)
            self.assertIn('class="expected-surface-cell expected-surface-network">lan</td>', rendered)
            self.assertIn('class="expected-surface-cell expected-surface-protocol">TCP</td>', rendered)
            self.assertIn('class="expected-surface-cell expected-surface-port">80</td>', rendered)
            self.assertIn('class="expected-surface-cell expected-surface-status"><span class="status status-not-verified">NOT VERIFIED</span></td>', rendered)
            self.assertIn(".expected-surface-table", rendered)
            self.assertIn(".expected-surface-header-cell", rendered)
            self.assertIn(".expected-surface-cell", rendered)
            self.assertIn("Observed Scanner Results", rendered)
            self.assertIn("Scanner result model is prepared, but live scanner logic is not implemented yet.", rendered)
            self.assertIn("No scanner results collected yet.", rendered)
            self.assertIn('class="observed-results-section" aria-labelledby="observed-scanner-results"', rendered)
            self.assertIn('id="observed-scanner-results" class="observed-results-heading">Observed Scanner Results</h2>', rendered)
            self.assertIn('class="observed-results-description">Scanner result model is prepared, but live scanner logic is not implemented yet.</p>', rendered)
            self.assertIn(".observed-results-section", rendered)
            self.assertIn(".observed-results-heading", rendered)
            self.assertIn(".observed-results-description", rendered)
            self.assertIn('class="observed-results-table"', rendered)
            self.assertIn('class="observed-results-header-row"', rendered)
            self.assertIn('class="observed-results-header-cell observed-results-header-host-id">Host ID</th>', rendered)
            self.assertIn('class="observed-results-header-cell observed-results-header-address">Address</th>', rendered)
            self.assertIn('class="observed-results-header-cell observed-results-header-protocol">Protocol</th>', rendered)
            self.assertIn('class="observed-results-header-cell observed-results-header-port">Port</th>', rendered)
            self.assertIn('class="observed-results-header-cell observed-results-header-state">Observed State</th>', rendered)
            self.assertIn('class="observed-results-header-cell observed-results-header-source">Source</th>', rendered)
            self.assertIn('class="observed-results-header-cell observed-results-header-checked-at">Checked At</th>', rendered)
            self.assertIn('class="observed-result-row observed-result-empty"', rendered)
            self.assertIn('class="observed-result-cell observed-result-empty-cell" colspan="7">No scanner results collected yet.</td>', rendered)
            self.assertIn(".observed-results-table", rendered)
            self.assertIn(".observed-results-header-cell", rendered)
            self.assertIn(".observed-result-cell", rendered)
            self.assertIn("Router", rendered)
            self.assertIn("192.168.1.1", rendered)
            self.assertIn("TCP", rendered)
            self.assertIn('class="expected-surface-cell expected-surface-port">80</td>', rendered)
            self.assertIn('class="expected-surface-cell expected-surface-port">443</td>', rendered)
            self.assertIn('class="expected-surface-header-cell expected-surface-header-status">Status</th>', rendered)
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
            self.assertIn('class="summary-metric summary-metric-expected-not-verified configuration-summary-metric configuration-summary-metric-expected-not-verified"', rendered)
            self.assertIn('class="summary-metric summary-metric-observed-results configuration-summary-metric configuration-summary-metric-observed-results"', rendered)
            self.assertIn('class="summary-metric summary-metric-unexpected configuration-summary-metric configuration-summary-metric-unexpected"', rendered)
            self.assertIn("Security Confidence: UNKNOWN", rendered)
            self.assertIn('class="security-confidence confidence-unknown"', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn("imported-test-evidence", rendered)
            self.assertIn("2026-06-12T10:00:00+00:00", rendered)
            self.assertIn('class="observed-results-table"', rendered)
            self.assertEqual(rendered.count('class="observed-result-row"'), 1)
            self.assertIn('class="observed-result-cell observed-result-host-id">router</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-address">192.168.1.1</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-protocol">TCP</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-port">443</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-verified">VERIFIED</span></td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-source">imported-test-evidence</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-checked-at">2026-06-12T10:00:00+00:00</td>', rendered)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 2)
            self.assertEqual(rendered.count('class="status status-not-verified">NOT VERIFIED</span>'), 1)
            self.assertEqual(rendered.count('class="expected-surface-row"'), 2)
            self.assertIn('class="expected-surface-cell expected-surface-status"><span class="status status-verified">VERIFIED</span></td>', rendered)
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
            self.assertIn('class="summary-metric summary-metric-expected-not-verified configuration-summary-metric configuration-summary-metric-expected-not-verified"', rendered)
            self.assertIn('class="summary-metric summary-metric-observed-results configuration-summary-metric configuration-summary-metric-observed-results"', rendered)
            self.assertIn('class="summary-metric summary-metric-unexpected configuration-summary-metric configuration-summary-metric-unexpected"', rendered)
            self.assertIn("Security Confidence: LOW", rendered)
            self.assertIn('class="security-confidence confidence-low"', rendered)
            self.assertIn('class="confidence-badge confidence-low">LOW</span>', rendered)
            self.assertIn("imported-nonmatching-test-evidence", rendered)
            self.assertEqual(rendered.count('class="observed-result-row"'), 1)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-unexpected">UNEXPECTED</span></td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-source">imported-nonmatching-test-evidence</td>', rendered)
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
            self.assertIn("Security Confidence: UNKNOWN", rendered)
            self.assertIn('class="security-confidence confidence-unknown"', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn("imported-matching-test-evidence", rendered)
            self.assertEqual(rendered.count('class="observed-result-row"'), 1)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-verified">VERIFIED</span></td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-source">imported-matching-test-evidence</td>', rendered)
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

    def test_controller_sets_medium_confidence_for_fully_verified_expected_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            scanner_results = Path(tmpdir) / "scanner-results.yaml"
            output = Path(tmpdir) / "dashboard.html"

            scanner_results.write_text(
                """\
- host_id: router
  host_address: 192.168.1.1
  protocol: tcp
  port: 80
  observed_state: VERIFIED
  source: imported-full-surface-test-evidence
  checked_at: "2026-06-12T10:00:00+00:00"
- host_id: router
  host_address: 192.168.1.1
  protocol: tcp
  port: 443
  observed_state: VERIFIED
  source: imported-full-surface-test-evidence
  checked_at: "2026-06-12T10:00:00+00:00"
""",
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

            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("Expected Surface NOT VERIFIED: 0", rendered)
            self.assertIn("Observed Scanner Results: 2", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn('class="summary-metric summary-metric-expected-not-verified configuration-summary-metric configuration-summary-metric-expected-not-verified"', rendered)
            self.assertIn('class="summary-metric summary-metric-observed-results configuration-summary-metric configuration-summary-metric-observed-results"', rendered)
            self.assertIn('class="summary-metric summary-metric-unexpected configuration-summary-metric configuration-summary-metric-unexpected"', rendered)
            self.assertIn("Security Confidence: MEDIUM", rendered)
            self.assertIn('class="security-confidence confidence-medium"', rendered)
            self.assertIn('class="confidence-badge confidence-medium">MEDIUM</span>', rendered)
            self.assertIn("imported-full-surface-test-evidence", rendered)
            self.assertEqual(rendered.count('class="observed-result-row"'), 2)
            self.assertIn('class="observed-result-cell observed-result-port">80</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-port">443</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-verified">VERIFIED</span></td>', rendered)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 4)
            self.assertEqual(rendered.count('class="expected-surface-row"'), 2)
            self.assertIn('class="expected-surface-cell expected-surface-status"><span class="status status-verified">VERIFIED</span></td>', rendered)
            self.assertNotIn('class="status status-not-verified">NOT VERIFIED</span>', rendered)
            self.assertNotIn('class="status status-unexpected">UNEXPECTED</span>', rendered)
            self.assertNotIn(">OK</span>", rendered)



if __name__ == "__main__":
    unittest.main()

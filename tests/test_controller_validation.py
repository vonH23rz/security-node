import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts" / "security-node-controller.py"
EXAMPLE_CONFIG = ROOT / "examples" / "config.example.yaml"


class ControllerValidationTests(unittest.TestCase):
    @staticmethod
    def fresh_checked_at(minutes: int = 0) -> str:
        return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()

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
            self.assertIn('class="page-body"', rendered)
            self.assertIn('class="page-main"', rendered)
            self.assertIn('class="page-header"', rendered)
            self.assertIn('rel="icon" type="image/png" href="data:image/png;base64,', rendered)
            self.assertIn('class="page-logo" src="data:image/png;base64,', rendered)
            self.assertIn('alt="" aria-hidden="true"', rendered)

            self.assertIn('class="page-title">Security Node</h1>', rendered)
            self.assertIn('class="page-subtitle">Security posture dashboard</p>', rendered)
            self.assertIn('class="page-header-meta" aria-label="Security Node metadata"', rendered)
            self.assertIn('class="page-header-meta-label">Site:</div><div>Example Homelab</div>', rendered)
            self.assertIn('class="page-header-meta-label">Controller:</div><div>Security Node Controller</div>', rendered)

            self.assertIn('class="security-status-strip status-strip-confidence-unknown" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: UNKNOWN"', rendered)
            self.assertIn('aria-label="Security Confidence: UNKNOWN"', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn("<span>Verification Level: Controller only</span>", rendered)
            self.assertIn("<span>Expected Surface NOT VERIFIED: 2</span>", rendered)
            self.assertIn("<span>Observed Scanner Results UNEXPECTED: 0</span>", rendered)
            self.assertIn("<span>Config schema validation passed before rendering.</span>", rendered)

            self.assertIn('class="top-information-grid"', rendered)
            self.assertIn('class="controller-state-section"', rendered)
            self.assertIn('class="configuration-summary-section"', rendered)
            self.assertIn("Controller ID", rendered)
            self.assertIn("controller", rendered)
            self.assertIn("Controller Display Name", rendered)
            self.assertIn("Security Node Controller", rendered)
            self.assertIn("Controller Network", rendered)
            self.assertIn("lan", rendered)
            self.assertIn("Controller Capabilities", rendered)
            self.assertIn("reachability, nmap", rendered)
            self.assertIn("Scanner Evidence Max Age", rendered)
            self.assertIn("1440 minutes", rendered)

            self.assertIn("Networks: 1", rendered)
            self.assertIn("Hosts: 1", rendered)
            self.assertIn("Probes: 0", rendered)
            self.assertIn("Accepted Risks: 0", rendered)
            self.assertIn("External Exposure Expectations: 0", rendered)
            self.assertIn("Expected Verification Surface Items: 2", rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 0", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)

            self.assertIn('class="expected-surface-section"', rendered)
            self.assertIn("Expected Verification Surface", rendered)
            self.assertIn("Router", rendered)
            self.assertIn("192.168.1.1", rendered)
            self.assertIn("TCP", rendered)
            self.assertIn("80", rendered)
            self.assertIn("443", rendered)
            self.assertIn('class="status status-not-verified">NOT VERIFIED</span>', rendered)

            self.assertIn('class="observed-results-section"', rendered)
            self.assertIn("Observed Scanner Results", rendered)
            self.assertIn("No scanner results collected yet.", rendered)
            self.assertIn('class="observed-result-row observed-result-empty"', rendered)

            self.assertIn('class="page-footer"', rendered)
            self.assertIn('class="scanner-implementation-notice">Scanner logic is not implemented yet.</p>', rendered)
            self.assertIn('class="generated-timestamp">Generated: ', rendered)

            self.assertIn("font-family: system-ui,", rendered)
            self.assertIn("background: #f3f5f7;", rendered)
            self.assertIn("color: #53585f;", rendered)
            self.assertIn("max-width: 118rem;", rendered)
            self.assertIn(".security-status-strip", rendered)
            self.assertIn(".status-strip-meta", rendered)
            self.assertIn(".top-information-grid", rendered)
            self.assertIn("grid-template-columns: minmax(24rem, 0.8fr) minmax(36rem, 1.2fr);", rendered)
            self.assertIn("grid-template-columns: repeat(2, minmax(0, 1fr));", rendered)
            self.assertIn("grid-template-columns: repeat(3, minmax(0, 1fr));", rendered)
            self.assertIn("@media (max-width: 72rem)", rendered)
            self.assertIn("@media (max-width: 56rem)", rendered)
            self.assertIn("@media (max-width: 48rem)", rendered)

            self.assertIn(".confidence-unknown", rendered)
            self.assertIn("background: #b3b6b6;", rendered)
            self.assertIn(".confidence-low", rendered)
            self.assertIn("background: #ff4539;", rendered)
            self.assertIn(".confidence-medium", rendered)
            self.assertIn("background: #9cc9ff;", rendered)

            self.assertNotIn('class="page-status-panel"', rendered)
            self.assertNotIn("max-width: 72rem;", rendered)
            self.assertNotIn("grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr));", rendered)


    def test_controller_renders_optional_scanner_results_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn('class="security-status-strip status-strip-confidence-unknown" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: UNKNOWN"', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn("imported-test-evidence", rendered)
            self.assertIn('class="observed-result-cell observed-result-checked-at">', rendered)
            self.assertIn('class="observed-results-table"', rendered)
            self.assertEqual(rendered.count('class="observed-result-row"'), 1)
            self.assertIn('class="observed-result-cell observed-result-host-id">router</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-address">192.168.1.1</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-protocol">TCP</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-port">443</td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-verified">VERIFIED</span></td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-source">imported-test-evidence</td>', rendered)
            self.assertRegex(
                rendered,
                r'class="observed-result-cell observed-result-checked-at">[^<]+\+00:00</td>',
            )
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
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 22
                      observed_state: VERIFIED
                      source: imported-nonmatching-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn('class="security-status-strip status-strip-confidence-low" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: LOW"', rendered)
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
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-matching-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn('class="security-status-strip status-strip-confidence-unknown" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: UNKNOWN"', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn("imported-matching-test-evidence", rendered)
            self.assertEqual(rendered.count('class="observed-result-row"'), 1)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-verified">VERIFIED</span></td>', rendered)
            self.assertIn('class="observed-result-cell observed-result-source">imported-matching-test-evidence</td>', rendered)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 2)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 0)
            self.assertEqual(rendered.count('class="status status-not-verified">NOT VERIFIED</span>'), 1)
            self.assertNotIn(">OK</span>", rendered)


    def test_controller_keeps_accepted_scanner_result_for_configured_surface(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: ACCEPTED
                      source: accepted-classification-test
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertTrue(output.exists())

            rendered = output.read_text(encoding="utf-8")

            self.assertIn('class="security-status-strip status-strip-confidence-unknown" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: UNKNOWN"', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-accepted">ACCEPTED</span></td>', rendered)
            self.assertEqual(rendered.count('class="status status-accepted">ACCEPTED</span>'), 1)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 0)
            self.assertNotIn(">OK</span>", rendered)

    def test_controller_classifies_accepted_unconfigured_port_as_unexpected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 22
                      observed_state: ACCEPTED
                      source: accepted-classification-test
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertTrue(output.exists())

            rendered = output.read_text(encoding="utf-8")

            self.assertIn('class="security-status-strip status-strip-confidence-low" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: LOW"', rendered)
            self.assertIn('class="confidence-badge confidence-low">LOW</span>', rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 1", rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-unexpected">UNEXPECTED</span></td>', rendered)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 1)
            self.assertEqual(rendered.count('class="status status-accepted">ACCEPTED</span>'), 0)
            self.assertNotIn(">OK</span>", rendered)

    def test_controller_classifies_accepted_unknown_host_as_unexpected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: unknown-host
                      host_address: 192.168.250.250
                      protocol: tcp
                      port: 443
                      observed_state: ACCEPTED
                      source: accepted-classification-test
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertTrue(output.exists())

            rendered = output.read_text(encoding="utf-8")

            self.assertIn('class="security-status-strip status-strip-confidence-low" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: LOW"', rendered)
            self.assertIn('class="confidence-badge confidence-low">LOW</span>', rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 1", rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-unexpected">UNEXPECTED</span></td>', rendered)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 1)
            self.assertEqual(rendered.count('class="status status-accepted">ACCEPTED</span>'), 0)
            self.assertNotIn(">OK</span>", rendered)




    def test_controller_keeps_unknown_scanner_result_for_configured_surface(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: UNKNOWN
                      source: unknown-classification-test
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertTrue(output.exists())

            rendered = output.read_text(encoding="utf-8")

            self.assertIn('class="security-status-strip status-strip-confidence-unknown" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: UNKNOWN"', rendered)
            self.assertIn('class="confidence-badge confidence-unknown">UNKNOWN</span>', rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-unknown">UNKNOWN</span></td>', rendered)
            self.assertEqual(rendered.count('class="status status-unknown">UNKNOWN</span>'), 1)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 0)
            self.assertNotIn(">OK</span>", rendered)

    def test_controller_classifies_unknown_unconfigured_port_as_unexpected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 22
                      observed_state: UNKNOWN
                      source: unknown-classification-test
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertTrue(output.exists())

            rendered = output.read_text(encoding="utf-8")

            self.assertIn('class="security-status-strip status-strip-confidence-low" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: LOW"', rendered)
            self.assertIn('class="confidence-badge confidence-low">LOW</span>', rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 1", rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-unexpected">UNEXPECTED</span></td>', rendered)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 1)
            self.assertEqual(rendered.count('class="status status-unknown">UNKNOWN</span>'), 0)
            self.assertNotIn(">OK</span>", rendered)

    def test_controller_classifies_unknown_unknown_host_as_unexpected(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: unknown-host
                      host_address: 192.168.250.250
                      protocol: tcp
                      port: 443
                      observed_state: UNKNOWN
                      source: unknown-classification-test
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertTrue(output.exists())

            rendered = output.read_text(encoding="utf-8")

            self.assertIn('class="security-status-strip status-strip-confidence-low" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: LOW"', rendered)
            self.assertIn('class="confidence-badge confidence-low">LOW</span>', rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 2", rendered)
            self.assertIn("Observed Scanner Results: 1", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 1", rendered)
            self.assertIn('class="observed-result-cell observed-result-state"><span class="status status-unexpected">UNEXPECTED</span></td>', rendered)
            self.assertEqual(rendered.count('class="status status-unexpected">UNEXPECTED</span>'), 1)
            self.assertEqual(rendered.count('class="status status-unknown">UNKNOWN</span>'), 0)
            self.assertNotIn(">OK</span>", rendered)


    def test_controller_refuses_duplicate_identical_scanner_result_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: duplicate-key-test
                      checked_at: "{self.fresh_checked_at()}"
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: duplicate-key-test
                      checked_at: "{self.fresh_checked_at()}"
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
                "scanner result #2: duplicate scanner result for router 192.168.1.1 tcp/443",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_duplicate_conflicting_scanner_result_key(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: duplicate-key-test-a
                      checked_at: "{self.fresh_checked_at()}"
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: UNKNOWN
                      source: duplicate-key-test-b
                      checked_at: "{self.fresh_checked_at(minutes=1)}"
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
                "scanner result #2: duplicate scanner result for router 192.168.1.1 tcp/443",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )



    def test_controller_refuses_stale_scanner_result_checked_at(self):
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
                      source: stale-evidence-test
                      checked_at: "1999-01-01T00:00:00+00:00"
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
                "scanner result #1: checked_at is older than scanner evidence max age of 1440 minutes",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_future_scanner_result_checked_at(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: future-evidence-test
                      checked_at: "{self.fresh_checked_at(minutes=10)}"
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
                "scanner result #1: checked_at must not be more than 5 minutes in the future",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_applies_configured_scanner_evidence_max_age_minutes(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "config.yaml"
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            config_text = EXAMPLE_CONFIG.read_text(encoding="utf-8")
            config.write_text(
                config_text.replace(
                    "scanner_evidence_max_age_minutes: 1440",
                    "scanner_evidence_max_age_minutes: 30",
                ),
                encoding="utf-8",
            )

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: configured-freshness-test
                      checked_at: "{self.fresh_checked_at(minutes=-60)}"
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
                "scanner result #1: checked_at is older than scanner evidence max age of 30 minutes",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_invalid_scanner_evidence_max_age_step(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "config.yaml"
            output = Path(tmpdir) / "index.html"

            config_text = EXAMPLE_CONFIG.read_text(encoding="utf-8")
            config.write_text(
                config_text.replace(
                    "scanner_evidence_max_age_minutes: 1440",
                    "scanner_evidence_max_age_minutes: 45",
                ),
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
            self.assertIn(
                "controller.scanner_evidence_max_age_minutes: must be in 30-minute steps",
                result.stdout,
            )

    def test_controller_refuses_too_large_scanner_evidence_max_age(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "config.yaml"
            output = Path(tmpdir) / "index.html"

            config_text = EXAMPLE_CONFIG.read_text(encoding="utf-8")
            config.write_text(
                config_text.replace(
                    "scanner_evidence_max_age_minutes: 1440",
                    "scanner_evidence_max_age_minutes: 1500",
                ),
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
            self.assertIn(
                "controller.scanner_evidence_max_age_minutes: must be between 30 and 1440 minutes",
                result.stdout,
            )


    def test_controller_refuses_invalid_scanner_results_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
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
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: OPEN
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: icmp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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

    def test_controller_refuses_blank_scanner_result_host_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: ''
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn("scanner result #1: host_id must be a non-empty string", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_boolean_scanner_result_host_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: true
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn("scanner result #1: host_id must be a non-empty string", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_null_scanner_result_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source:
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn("scanner result #1: source must be a non-empty string", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_blank_scanner_result_checked_at(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: ''
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
            self.assertIn("scanner result #1: checked_at must be a non-empty string", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_non_timestamp_scanner_result_checked_at(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: not-a-timestamp
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
                "scanner result #1: checked_at must be an ISO-8601 timestamp with timezone offset",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_timezone_less_scanner_result_checked_at(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "2026-06-12T10:00:00"
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
                "scanner result #1: checked_at must be an ISO-8601 timestamp with timezone offset",
                result.stdout,
            )
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_boolean_scanner_result_protocol(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: true
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn("scanner result #1: protocol must be a non-empty string", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_blank_scanner_result_protocol(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: ''
                      port: 443
                      observed_state: VERIFIED
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn("scanner result #1: protocol must be a non-empty string", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_boolean_scanner_result_observed_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: true
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn("scanner result #1: observed_state must be a non-empty string", result.stdout)
            self.assertIn(
                "FAILED: refusing to render dashboard from invalid scanner results",
                result.stdout,
            )

    def test_controller_refuses_blank_scanner_result_observed_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "index.html"
            scanner_results = Path(tmpdir) / "scanner-results.yaml"

            scanner_results.write_text(
                textwrap.dedent(
                    f"""
                    - host_id: router
                      host_address: 192.168.1.1
                      protocol: tcp
                      port: 443
                      observed_state: ''
                      source: imported-test-evidence
                      checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn("scanner result #1: observed_state must be a non-empty string", result.stdout)
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
                    f"""
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
                f"""\
- host_id: router
  host_address: 192.168.1.1
  protocol: tcp
  port: 80
  observed_state: VERIFIED
  source: imported-full-surface-test-evidence
  checked_at: "{self.fresh_checked_at()}"
- host_id: router
  host_address: 192.168.1.1
  protocol: tcp
  port: 443
  observed_state: VERIFIED
  source: imported-full-surface-test-evidence
  checked_at: "{self.fresh_checked_at()}"
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
            self.assertIn('class="security-status-strip status-strip-confidence-medium" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: MEDIUM"', rendered)
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

class ScannerEvidenceExampleTemplateTest(unittest.TestCase):
    def test_example_scanner_results_template_renders_after_timestamp_substitution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            template_path = ROOT / "examples" / "scanner-results.example.yaml"
            scanner_results_path = Path(tmpdir) / "scanner-results.yaml"
            output_path = Path(tmpdir) / "dashboard.html"

            fresh_checked_at = datetime.now(timezone.utc).isoformat()
            scanner_results_path.write_text(
                template_path.read_text(encoding="utf-8").replace(
                    "REPLACE_WITH_CURRENT_ISO8601_TIMESTAMP",
                    fresh_checked_at,
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(CONTROLLER),
                    "--config",
                    str(EXAMPLE_CONFIG),
                    "--scanner-results",
                    str(scanner_results_path),
                    "--output",
                    str(output_path),
                ],
                cwd=ROOT,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rendered = output_path.read_text(encoding="utf-8")

            self.assertIn("Security Confidence: MEDIUM", rendered)
            self.assertIn('class="security-status-strip status-strip-confidence-medium" aria-label="Security Node status summary"', rendered)
            self.assertIn('class="security-confidence" aria-label="Security Confidence: MEDIUM"', rendered)
            self.assertIn('class="confidence-badge confidence-medium">MEDIUM</span>', rendered)
            self.assertIn("Expected Surface NOT VERIFIED: 0", rendered)
            self.assertIn("Observed Scanner Results UNEXPECTED: 0", rendered)
            self.assertEqual(rendered.count('class="status status-verified">VERIFIED</span>'), 4)
            self.assertNotIn("No scanner results collected yet.", rendered)


if __name__ == "__main__":
    unittest.main()

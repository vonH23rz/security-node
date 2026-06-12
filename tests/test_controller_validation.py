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
            self.assertIn("Expected Verification Surface", rendered)
            self.assertIn("Configured host ports that should be checked by future scanner logic.", rendered)
            self.assertIn("Router", rendered)
            self.assertIn("192.168.1.1", rendered)
            self.assertIn("TCP", rendered)
            self.assertIn("<td>80</td>", rendered)
            self.assertIn("<td>443</td>", rendered)
            self.assertIn("summary: 0 error(s), 0 warning(s)", result.stdout)
            self.assertIn("Wrote dashboard from validated state model", result.stdout)

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

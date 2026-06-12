import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate-config.py"
EXAMPLE_CONFIG = ROOT / "examples" / "config.example.yaml"


class ConfigValidationTests(unittest.TestCase):
    def run_validator(self, config_text: str | None = None) -> subprocess.CompletedProcess[str]:
        if config_text is None:
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(EXAMPLE_CONFIG)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.yaml"
            path.write_text(textwrap.dedent(config_text).strip() + "\n", encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(path)],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_example_config_is_valid(self):
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK: config schema is valid", result.stdout)
        self.assertIn("summary: 0 error(s), 0 warning(s)", result.stdout)

    def test_missing_required_top_level_key_fails(self):
        result = self.run_validator(
            """
            site:
              name: Broken
            controller:
              id: controller
              network: lan
              capabilities: [reachability]
            hosts: []
            probes: []
            accepted_risks: []
            external_exposure:
              expected: []
            """
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required top-level key 'networks'", result.stdout)

    def test_host_outside_declared_network_fails(self):
        result = self.run_validator(
            """
            site:
              name: Broken
            controller:
              id: controller
              network: lan
              capabilities: [reachability]
            networks:
              - id: lan
                subnet: 192.168.1.0/24
            hosts:
              - id: wrong_host
                address: 10.10.10.10
                network: lan
                expected_ports: [22]
            probes: []
            accepted_risks: []
            external_exposure:
              expected: []
            """
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is not inside referenced network 'lan'", result.stdout)

    def test_invalid_port_fails(self):
        result = self.run_validator(
            """
            site:
              name: Broken
            controller:
              id: controller
              network: lan
              capabilities: [reachability]
            networks:
              - id: lan
                subnet: 192.168.1.0/24
            hosts:
              - id: router
                address: 192.168.1.1
                network: lan
                expected_ports: [0, 443]
            probes: []
            accepted_risks: []
            external_exposure:
              expected: []
            """
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be between 1 and 65535", result.stdout)


if __name__ == "__main__":
    unittest.main()

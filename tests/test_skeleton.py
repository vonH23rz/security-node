import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class SkeletonTests(unittest.TestCase):
    def test_expected_project_files_exist(self):
        expected = [
            "README.md",
            "LICENSE",
            ".gitignore",
            "Dockerfile",
            "docker-compose.yml",
            "requirements.txt",
            "examples/config.example.yaml",
            "scripts/security-node-controller.py",
            "scripts/validate-config.py",
            "tests/test_config_validation.py",
            "tests/test_controller_validation.py",
            "tests/test_skeleton.py",
        ]

        for relative in expected:
            with self.subTest(relative=relative):
                self.assertTrue((ROOT / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()

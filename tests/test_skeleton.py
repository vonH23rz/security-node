from pathlib import Path


def test_expected_project_files_exist():
    root = Path(__file__).resolve().parents[1]
    expected = [
        "README.md",
        "LICENSE",
        ".gitignore",
        "Dockerfile",
        "docker-compose.yml",
        "examples/config.example.yaml",
        "scripts/security-node-controller.py",
        "scripts/validate-config.py",
    ]
    for relative in expected:
        assert (root / relative).exists()

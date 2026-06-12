#!/usr/bin/env python3
"""Security Node Controller.

The Controller validates configuration before rendering any dashboard output.
Real scanner logic is not implemented yet.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
from pathlib import Path
from types import ModuleType


def load_validator_module() -> ModuleType:
    """Load the validator script despite its CLI-friendly hyphenated filename."""

    validator_path = Path(__file__).with_name("validate-config.py")
    spec = importlib.util.spec_from_file_location("security_node_config_validator", validator_path)

    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load validator module from {validator_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def print_validation_report(config: Path, report: object) -> None:
    """Print validator output in the same clear style as the standalone validator."""

    errors = getattr(report, "errors", [])
    warnings = getattr(report, "warnings", [])

    print("Security Node Controller")
    print(f"config={config}")

    for warning in warnings:
        print(f"WARNING: {warning}")

    for error in errors:
        print(f"ERROR: {error}")

    print(f"summary: {len(errors)} error(s), {len(warnings)} warning(s)")


def render_placeholder(output: Path) -> None:
    now = _dt.datetime.now(_dt.timezone.utc).isoformat()
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Node</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
  <main>
    <h1>Security Node</h1>
    <p>Security Confidence: UNKNOWN</p>
    <p>Controller skeleton is installed. Scanner logic is not implemented yet.</p>
    <p>Config schema validation passed before rendering.</p>
    <p>Generated: {now}</p>
  </main>
</body>
</html>
"""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Node Controller")
    parser.add_argument("--config", default="examples/config.example.yaml")
    parser.add_argument("--output", default="html/index.html")
    args = parser.parse_args()

    config = Path(args.config)
    output = Path(args.output)

    validator = load_validator_module()
    report = validator.validate_config(config)

    if not report.ok:
        print_validation_report(config, report)
        print("FAILED: refusing to render dashboard from invalid config")
        return 1

    print_validation_report(config, report)
    render_placeholder(output)
    print(f"Wrote placeholder dashboard: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

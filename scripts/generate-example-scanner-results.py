#!/usr/bin/env python3
"""Generate fresh example scanner evidence from the public template."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path


PLACEHOLDER = "REPLACE_WITH_CURRENT_ISO8601_TIMESTAMP"
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE = ROOT / "examples" / "scanner-results.example.yaml"
DEFAULT_OUTPUT = ROOT / "data" / "scanner-results.example.generated.yaml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate a fresh example scanner evidence YAML file from "
            "examples/scanner-results.example.yaml."
        )
    )
    parser.add_argument(
        "--template",
        default=str(DEFAULT_TEMPLATE),
        help="Template YAML file containing timestamp placeholders.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Output YAML file to write. Defaults to data/scanner-results.example.generated.yaml.",
    )
    parser.add_argument(
        "--timestamp",
        default=None,
        help="Optional ISO-8601 timestamp override. Defaults to current UTC time.",
    )
    return parser


def generate_example_scanner_results(template_path: Path, output_path: Path, timestamp: str | None) -> str:
    checked_at = timestamp or datetime.now(timezone.utc).isoformat()

    template = template_path.read_text(encoding="utf-8")
    if PLACEHOLDER not in template:
        raise ValueError(f"template does not contain required placeholder: {PLACEHOLDER}")

    output = template.replace(PLACEHOLDER, checked_at)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output, encoding="utf-8")

    return checked_at


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    template_path = Path(args.template)
    output_path = Path(args.output)

    try:
        checked_at = generate_example_scanner_results(
            template_path=template_path,
            output_path=output_path,
            timestamp=args.timestamp,
        )
    except (OSError, ValueError) as error:
        parser.exit(1, f"ERROR: {error}\n")

    print("Security Node example scanner evidence generator")
    print(f"template={template_path}")
    print(f"output={output_path}")
    print(f"checked_at={checked_at}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

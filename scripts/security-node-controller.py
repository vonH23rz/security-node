#!/usr/bin/env python3
"""Security Node Controller placeholder.

This is intentionally minimal. Real scanner logic is not implemented yet.
"""

from __future__ import annotations

import argparse
import datetime as _dt
from pathlib import Path


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

    if not config.exists():
        raise SystemExit(f"Config file not found: {config}")

    render_placeholder(output)
    print(f"Wrote placeholder dashboard: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

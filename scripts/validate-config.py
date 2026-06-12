#!/usr/bin/env python3
"""Security Node config validator placeholder.

This validates only that the config file exists and is non-empty.
Real schema validation will be added in a later slice.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Security Node config")
    parser.add_argument("config", nargs="?", default="examples/config.example.yaml")
    args = parser.parse_args()

    config = Path(args.config)
    if not config.exists():
        print(f"ERROR: config not found: {config}")
        return 1

    if not config.read_text(encoding="utf-8").strip():
        print(f"ERROR: config is empty: {config}")
        return 1

    print(f"OK: config exists and is not empty: {config}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

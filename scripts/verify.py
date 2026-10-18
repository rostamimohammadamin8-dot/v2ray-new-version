#!/usr/bin/env python3
"""Verify the integrity of published subscription data."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scripts.integrity import verify_outputs  # noqa: E402


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify data/manifest.json, feeds, snapshot and checksums")
    parser.add_argument("--data-dir", type=Path, default=Path("data"))
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    errors = verify_outputs(args.data_dir)
    if errors:
        for error in errors:
            print(f"ERROR {error}", file=sys.stderr)
        print(f"integrity check failed ({len(errors)} error(s))", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"integrity check passed: {args.data_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

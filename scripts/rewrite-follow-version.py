#!/usr/bin/env python3
"""Rewrite Plus-agent version files after following a Lite-agent tag."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import follow_overlay  # noqa: E402


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: rewrite-follow-version.py <plus-version> <lite-agent-tag>")
    follow_overlay.rewrite_versions(follow_overlay.ROOT, sys.argv[1], sys.argv[2])


if __name__ == "__main__":
    main()

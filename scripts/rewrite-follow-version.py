#!/usr/bin/env python3
"""Rewrite Plus-agent version files after following a Lite-agent tag."""

import json
import pathlib
import re
import sys


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: rewrite-follow-version.py <plus-version> <lite-agent-tag>")
    new, tag = sys.argv[1], sys.argv[2]
    root = pathlib.Path(__file__).resolve().parent.parent

    go = root / "update" / "update.go"
    text = go.read_text(encoding="utf-8")
    text, n = re.subn(r'CurrentVersion string = "[^"]*"', f'CurrentVersion string = "{new}"', text, count=1)
    if n != 1:
        raise SystemExit("did not find CurrentVersion assignment in update/update.go")
    text, n = re.subn(r'Repo string = "[^"]*"', 'Repo string = "nuomiiiii/Lite-Plus-agent"', text, count=1)
    if n != 1:
        raise SystemExit("did not find Repo assignment in update/update.go")
    go.write_text(text, encoding="utf-8")

    test = root / "update" / "update_test.go"
    t = test.read_text(encoding="utf-8")
    t, n = re.subn(r'CurrentVersion != "[^"]+"', f'CurrentVersion != "{new}"', t, count=1)
    if n != 1:
        raise SystemExit("did not find CurrentVersion assertion in update/update_test.go")
    t, n = re.subn(r'CurrentVersion = %q, want [^"]+"', f'CurrentVersion = %q, want {new}"', t, count=1)
    if n != 1:
        raise SystemExit("did not find CurrentVersion fatals in update/update_test.go")
    test.write_text(t, encoding="utf-8")

    (root / "plus-baseline.json").write_text(
        json.dumps({"lite_plus_agent": new, "lite_agent": tag}, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

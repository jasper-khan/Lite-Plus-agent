"""Plus overlay helpers for follow-lite-agent merges."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

OURS_ONLY = (
    "update/update.go",
    "plus-baseline.json",
)

NEED_UPDATE_ROW = re.compile(
    r'^\t\t\{"[^"]+", "[^"]+", (?:true|false)\},',
    re.M,
)
CHANGELOG_ROW = re.compile(r"^\| `[^`]+` \| .* \|$", re.M)
NEED_UPDATE_END = "\n\t}\n\n\tfor _, tt := range tests"
CHANGELOG_END = "\n完整发布记录"


def _function_span(text: str, name: str) -> tuple[int, int]:
    start = text.find(f"func {name}")
    if start < 0:
        raise SystemExit(f"{name} not found")
    nxt = text.find("\nfunc ", start + 1)
    if nxt < 0:
        nxt = len(text)
    return start, nxt


def _need_update_span(text: str) -> tuple[int, int]:
    if "func TestNeedUpdate" in text:
        return _function_span(text, "TestNeedUpdate")
    return 0, len(text)


def merge_need_update_rows(ours: str, theirs: str) -> str:
    os, oe = _need_update_span(ours)
    ts, te = _need_update_span(theirs)
    ours_fn = ours[os:oe]
    theirs_fn = theirs[ts:te]
    existing = set(NEED_UPDATE_ROW.findall(ours_fn))
    extra = [row for row in NEED_UPDATE_ROW.findall(theirs_fn) if row not in existing]
    if not extra:
        return ours
    idx = ours_fn.find(NEED_UPDATE_END)
    if idx < 0:
        raise SystemExit("needUpdate table end not found")
    return ours[:os] + ours_fn[:idx] + "\n" + "\n".join(extra) + ours_fn[idx:] + ours[oe:]


def merge_changelog_rows(ours: str, theirs: str) -> str:
    existing = set(CHANGELOG_ROW.findall(ours))
    extra = [row for row in CHANGELOG_ROW.findall(theirs) if row not in existing]
    if not extra:
        return ours
    idx = ours.find(CHANGELOG_END)
    if idx < 0:
        raise SystemExit("readme changelog end not found")
    return ours[:idx] + "\n" + "\n".join(extra) + ours[idx:]


def ensure_need_update_case(text: str, current: str, latest: str, want: bool) -> str:
    row = f'\t\t{{"{current}", "{latest}", {"true" if want else "false"}}},'
    start, end = _need_update_span(text)
    section = text[start:end]
    if row in section:
        return text
    idx = section.find(NEED_UPDATE_END)
    if idx < 0:
        raise SystemExit("needUpdate table end not found")
    return text[:start] + section[:idx] + "\n" + row + section[idx:] + text[end:]


def rewrite_versions(root: pathlib.Path, new: str, tag: str) -> None:
    go = root / "update" / "update.go"
    text = go.read_text(encoding="utf-8")
    old_match = re.search(r'CurrentVersion string = "([^"]*)"', text)
    if not old_match:
        raise SystemExit("did not find CurrentVersion assignment in update/update.go")
    old = old_match.group(1)
    text, n = re.subn(r'CurrentVersion string = "[^"]*"', f'CurrentVersion string = "{new}"', text, count=1)
    if n != 1:
        raise SystemExit("did not replace CurrentVersion assignment in update/update.go")
    text, n = re.subn(r'Repo string = "[^"]*"', 'Repo string = "nuomiiiii/Lite-Plus-agent"', text, count=1)
    if n != 1:
        raise SystemExit("did not find Repo assignment in update/update.go")
    go.write_text(text, encoding="utf-8")

    baseline_path = root / "plus-baseline.json"
    old_lite = json.loads(baseline_path.read_text(encoding="utf-8")).get("lite_agent", "")

    test = root / "update" / "update_test.go"
    t = test.read_text(encoding="utf-8")
    t, n = re.subn(r'CurrentVersion != "[^"]+"', f'CurrentVersion != "{new}"', t, count=1)
    if n != 1:
        raise SystemExit("did not find CurrentVersion assertion in update/update_test.go")
    t, n = re.subn(r'CurrentVersion = %q, want [^"]+"', f'CurrentVersion = %q, want {new}"', t, count=1)
    if n != 1:
        raise SystemExit("did not find CurrentVersion fatals in update/update_test.go")
    if old and old != new:
        t = ensure_need_update_case(t, old, new, True)
        t = ensure_need_update_case(t, f"{old}+abc1234", new, True)
        t = ensure_need_update_case(t, f"{old}+abc1234", old, False)
    t = ensure_need_update_case(t, f"{new}+abc1234", new, False)
    if old_lite and old_lite != tag:
        t = ensure_need_update_case(t, old_lite, tag, True)
    t = ensure_need_update_case(t, f"{tag}+abc1234", tag, False)
    test.write_text(t, encoding="utf-8")

    readme = root / "readme.md"
    r = readme.read_text(encoding="utf-8")
    r, n = re.subn(r"当前稳定版本：`[^`]+`", f"当前稳定版本：`{new}`", r, count=1)
    if n != 1:
        raise SystemExit("did not find current version in readme.md")
    r, n = re.subn(
        r"docker pull ghcr.io/nuomiiiii/lite-plus-agent:\d+\.\d+\.\d+\.\d+",
        f"docker pull ghcr.io/nuomiiiii/lite-plus-agent:{new}",
        r,
        count=1,
    )
    if n != 1:
        raise SystemExit("did not find versioned docker pull in readme.md")
    readme.write_text(r, encoding="utf-8")

    baseline_path.write_text(
        json.dumps({"lite_plus_agent": new, "lite_agent": tag}, indent=2) + "\n",
        encoding="utf-8",
    )


def _git_output(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True)


def _git_stage(path: str, stage: int) -> str:
    try:
        return _git_output("show", f":{stage}:{path}")
    except subprocess.CalledProcessError:
        return ""


def resolve_unmerged() -> list[str]:
    unmerged = [p for p in _git_output("diff", "--name-only", "--diff-filter=U").splitlines() if p]
    leftover: list[str] = []
    for path in unmerged:
        ours = _git_stage(path, 2)
        theirs = _git_stage(path, 3)
        if path in OURS_ONLY:
            resolved = ours
        elif path == "update/update_test.go":
            resolved = merge_need_update_rows(ours, theirs)
        elif path == "readme.md":
            resolved = merge_changelog_rows(ours, theirs)
        else:
            leftover.append(path)
            continue
        if resolved == "":
            leftover.append(path)
            continue
        (ROOT / path).write_text(resolved, encoding="utf-8")
        subprocess.check_call(["git", "add", "--", path], cwd=ROOT)
    return leftover


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: follow_overlay.py resolve | rewrite <plus-version> <lite-agent-tag>")
    cmd = sys.argv[1]
    if cmd == "resolve":
        leftover = resolve_unmerged()
        if leftover:
            sys.stderr.write("unresolved follow conflicts:\n" + "\n".join(leftover) + "\n")
            raise SystemExit(2)
        return
    if cmd == "rewrite":
        if len(sys.argv) != 4:
            raise SystemExit("usage: follow_overlay.py rewrite <plus-version> <lite-agent-tag>")
        rewrite_versions(ROOT, sys.argv[2], sys.argv[3])
        return
    raise SystemExit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()

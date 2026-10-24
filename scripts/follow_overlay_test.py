#!/usr/bin/env python3

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import follow_overlay  # noqa: E402


OURS_TEST = """\t\t{"2.3.10.0+abc1234", "2.3.10.0", false},
\t\t{"0.0.0.5", "0.0.0.6", true},
\t\t{"0.0.0.6+abc1234", "0.0.0.6", false},
\t}

\tfor _, tt := range tests {
"""

THEIRS_TEST = """\t\t{"2.3.10.0+abc1234", "2.3.10.0", false},
\t\t{"2.3.10.0", "2.3.10.1", true},
\t\t{"2.3.10.1+abc1234", "2.3.10.1", false},
\t}

\tfor _, tt := range tests {
"""

OURS_README = """当前稳定版本：`0.0.0.6`

```bash
docker pull ghcr.io/nuomiiiii/lite-plus-agent:0.0.0.6
```

| `0.0.0.6` | Plus only. |
| `2.3.10.0` | 修复 CVE-2026-111943。当前 Agent 不受该问题影响，此次一并跟进。 |

完整发布记录和升级说明请查看 [GitHub Releases](https://github.com/nuomiiiii/Lite-Plus-agent/releases)。
"""

THEIRS_README = """当前稳定版本：`2.3.10.1`

```bash
docker pull ghcr.io/nuomiiiii/lite-agent:2.3.10.1
```

| `2.3.10.0` | 修复 CVE-2026-111943。当前 Agent 不受该问题影响，此次一并跟进。 |
| `2.3.10.1` | 修复远程终端执行输出很多、耗时较长的命令后，过几分钟无法输入的 bug。 |

完整发布记录和升级说明请查看 [GitHub Releases](https://github.com/nuomiiiii/Lite-agent/releases)。
"""


class FollowOverlayTest(unittest.TestCase):
    def test_keeps_plus_need_update_cases_and_adds_lite_rows(self) -> None:
        got = follow_overlay.merge_need_update_rows(OURS_TEST, THEIRS_TEST)
        self.assertIn('{"0.0.0.5", "0.0.0.6", true}', got)
        self.assertIn('{"2.3.10.0", "2.3.10.1", true}', got)
        self.assertIn('{"2.3.10.1+abc1234", "2.3.10.1", false}', got)
        self.assertNotIn("lite-agent", got)

    def test_keeps_plus_readme_and_adds_lite_changelog(self) -> None:
        got = follow_overlay.merge_changelog_rows(OURS_README, THEIRS_README)
        self.assertIn("当前稳定版本：`0.0.0.6`", got)
        self.assertIn("lite-plus-agent:0.0.0.6", got)
        self.assertNotIn("lite-agent:2.3.10.1", got)
        self.assertIn("| `2.3.10.1` | 修复远程终端执行输出很多、耗时较长的命令后，过几分钟无法输入的 bug。 |", got)

    def test_rewrite_bumps_plus_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "update").mkdir()
            (root / "update" / "update.go").write_text(
                'var (\n\tCurrentVersion string = "0.0.0.6"\n\tRepo string = "nuomiiiii/Lite-Plus-agent"\n)\n',
                encoding="utf-8",
            )
            (root / "update" / "update_test.go").write_text(
                'func TestDefaultUpdateRepo(t *testing.T) {\n\tif CurrentVersion != "0.0.0.6" {\n\t\tt.Fatalf("CurrentVersion = %q, want 0.0.0.6", CurrentVersion)\n\t}\n}\n'
                + OURS_TEST,
                encoding="utf-8",
            )
            (root / "readme.md").write_text(OURS_README, encoding="utf-8")
            (root / "plus-baseline.json").write_text(
                json.dumps({"lite_plus_agent": "0.0.0.6", "lite_agent": "2.3.10.0"}, indent=2) + "\n",
                encoding="utf-8",
            )
            follow_overlay.rewrite_versions(root, "0.0.0.7", "2.3.10.1")
            go = (root / "update" / "update.go").read_text(encoding="utf-8")
            self.assertIn('CurrentVersion string = "0.0.0.7"', go)
            self.assertIn('Repo string = "nuomiiiii/Lite-Plus-agent"', go)
            test = (root / "update" / "update_test.go").read_text(encoding="utf-8")
            self.assertIn('CurrentVersion != "0.0.0.7"', test)
            self.assertIn('{"0.0.0.6", "0.0.0.7", true}', test)
            self.assertIn('{"2.3.10.0", "2.3.10.1", true}', test)
            readme = (root / "readme.md").read_text(encoding="utf-8")
            self.assertIn("当前稳定版本：`0.0.0.7`", readme)
            self.assertIn("lite-plus-agent:0.0.0.7", readme)
            baseline = json.loads((root / "plus-baseline.json").read_text(encoding="utf-8"))
            self.assertEqual(baseline, {"lite_plus_agent": "0.0.0.7", "lite_agent": "2.3.10.1"})


if __name__ == "__main__":
    unittest.main()

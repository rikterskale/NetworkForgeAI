"""Portable smoke checks for supported developer platforms."""

import platform
import subprocess
import sys
from pathlib import Path

from networkforgeai.cli import build_parser


def test_cli_parser_and_paths_are_platform_neutral(tmp_path: Path):
    args = build_parser().parse_args(["--list-tools"])
    assert args.list_tools is True
    nested = tmp_path / "scan" / "report.md"
    nested.parent.mkdir()
    nested.write_text("ok", encoding="utf-8")
    assert nested.read_text(encoding="utf-8") == "ok"


def test_python_subprocess_uses_argument_vectors():
    result = subprocess.run(
        [sys.executable, "-c", "print('platform-ok')"],
        capture_output=True,
        text=True,
        shell=False,
        check=True,
    )
    assert result.stdout.strip() == "platform-ok"
    assert platform.system()

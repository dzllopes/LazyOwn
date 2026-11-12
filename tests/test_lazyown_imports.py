"""Contract: names the shell module uses at runtime are bound at import time."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lazyown  # noqa: E402


def test_strip_ansi_is_bound_for_the_ai_output_path() -> None:
    """``LazyOwnShell`` cleans AI-bound output with ``strip_ansi``; it must resolve."""
    assert lazyown.strip_ansi("\x1b[31mred\x1b[0m") == "red"


def test_sys_is_the_standard_module() -> None:
    """``sys`` must come from the standard library import, not a re-export."""
    assert lazyown.sys is sys

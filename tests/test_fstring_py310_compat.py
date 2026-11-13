"""Contract: no f-string reuses its outer quote inside a replacement field.

That form only parses on Python 3.12 and later, while ``pyproject.toml``
declares ``requires-python >= 3.10``. One such line makes the whole module
fail to import on 3.10 and 3.11.
"""

from __future__ import annotations

import ast
import io
import subprocess
import sys
import tokenize
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PEP_701_VERSION = (3, 12)


def _tracked_python_files() -> list[Path]:
    """Return every Python file tracked by git."""
    listing = subprocess.run(
        ["git", "ls-files", "*.py"], cwd=REPO_ROOT, capture_output=True, text=True, check=True, timeout=60
    )
    return [REPO_ROOT / line for line in listing.stdout.splitlines() if line]


def _reused_quote_lines(source: str) -> list[int]:
    """Return the line numbers of f-strings that reuse the outer quote in a field."""
    hits: list[int] = []
    open_quotes: list[str] = []
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.FSTRING_START:
            open_quotes.append(token.string.lstrip("rbfRBF"))
        elif token.type == tokenize.FSTRING_END:
            open_quotes.pop()
        elif token.type == tokenize.STRING and open_quotes:
            outer = open_quotes[-1]
            if len(outer) == 1 and token.string.endswith(outer) and not token.string.endswith(outer * 3):
                hits.append(token.start[0])
    return hits


def test_detector_flags_the_312_only_form() -> None:
    if sys.version_info < PEP_701_VERSION:
        pytest.skip("the tokenizer only exposes f-string tokens on 3.12+; older interpreters fail at import instead")
    assert _reused_quote_lines("x = f'a {d['k']} b'\n") == [1]
    assert _reused_quote_lines("x = f\"a {d['k']} b\"\n") == []


def test_no_tracked_file_uses_the_312_only_form() -> None:
    offenders: list[str] = []
    for path in _tracked_python_files():
        try:
            source = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        if sys.version_info < PEP_701_VERSION:
            try:
                ast.parse(source)
            except SyntaxError as error:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{error.lineno}")
            continue
        try:
            lines = _reused_quote_lines(source)
        except (tokenize.TokenError, SyntaxError):
            continue
        offenders.extend(f"{path.relative_to(REPO_ROOT)}:{line}" for line in lines)
    assert offenders == []

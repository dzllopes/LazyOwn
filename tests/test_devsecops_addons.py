"""BDD contract for the recon and DevSecOps lazyaddons.

Scenarios:
  - Given each addon YAML, when loaded, it exposes the mandatory fields and a
    name usable as a cmd2 verb.
  - Given an addon that wraps a system binary, it declares no clone step and
    writes its artefacts under ``sessions/``.
  - Given an addon definition, it carries no hardcoded address or secret.
  - Given a parameter with a default that is absent from ``payload.json``,
    when the addon runs, the default fills the command placeholder.
  - Given a payload value for that parameter, it wins over the default.
  - Given a required parameter missing from the payload, the addon refuses
    to build a command.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ADDONS_DIR = REPO_ROOT / "lazyaddons"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import lazyown  # noqa: E402
from cli.exploration import ALLOWED_OS_VALUES  # noqa: E402

EXPECTED_BINARY = {
    "subfinder": "subfinder",
    "httpx": "httpx-toolkit",
    "semgrep": "semgrep",
    "osv_scanner": "osv-scanner",
    "codeql": "codeql",
    "aflpp": "afl-fuzz",
}
REQUIRED_FIELDS = ("name", "description", "enabled", "tool", "category", "os", "trigger")
IPV4_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
SECRET_PATTERN = re.compile(r"(password|passwd|api[_-]?key|token)\s*[:=]\s*\S+", re.IGNORECASE)
VERB_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
PLACEHOLDER_PATTERN = re.compile(r"\{([a-z_]+)\}")


def _load(name: str) -> dict:
    """Return the parsed YAML document of one addon."""
    with (ADDONS_DIR / f"{name}.yaml").open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _text(name: str) -> str:
    """Return the raw YAML text of one addon."""
    return (ADDONS_DIR / f"{name}.yaml").read_text(encoding="utf-8")


def _run(addon: dict, params: dict, line: str = "") -> tuple[list[str], list[str]]:
    """Register an addon on a stub shell, invoke it and return commands and warnings."""
    commands: list[str] = []
    warnings: list[str] = []
    shell = SimpleNamespace(
        params=params,
        cmd=commands.append,
        onecmd=commands.append,
        display_toastr=lambda message, type="info": warnings.append(message),
    )
    lazyown.LazyOwnShell.register_yaml_plugin(shell, addon)
    getattr(shell, f"do_{addon['name']}")(line)
    return commands, warnings


@pytest.mark.parametrize("name", sorted(EXPECTED_BINARY))
class TestAddonContract:
    """Static contract shared by the six addons."""

    def test_required_fields_present(self, name: str) -> None:
        addon = _load(name)
        for field in REQUIRED_FIELDS:
            assert field in addon, f"{name} is missing {field}"
        assert addon["enabled"] is True
        assert len(addon["description"]) > 40

    def test_name_matches_file_and_is_a_valid_verb(self, name: str) -> None:
        addon = _load(name)
        assert addon["name"] == name
        assert VERB_PATTERN.match(name)

    def test_name_does_not_shadow_a_builtin_command(self, name: str) -> None:
        assert not hasattr(lazyown.LazyOwnShell, f"do_{name}")

    def test_os_and_trigger_are_valid(self, name: str) -> None:
        addon = _load(name)
        assert addon["os"] in ALLOWED_OS_VALUES
        assert isinstance(addon["trigger"], list)

    def test_wraps_the_system_binary_without_clone_step(self, name: str) -> None:
        tool = _load(name)["tool"]
        assert "install_path" not in tool
        assert "repo_url" not in tool
        assert tool["execute_command"].split()[0] == EXPECTED_BINARY[name]
        assert tool["install_command"].strip()

    def test_artefacts_land_in_sessions(self, name: str) -> None:
        assert "sessions/" in _load(name)["tool"]["execute_command"]

    def test_every_placeholder_is_a_declared_param(self, name: str) -> None:
        addon = _load(name)
        declared = {param["name"] for param in addon.get("params") or []}
        used = set(PLACEHOLDER_PATTERN.findall(addon["tool"]["execute_command"]))
        assert used <= declared

    def test_params_are_documented(self, name: str) -> None:
        for param in _load(name).get("params") or []:
            assert param["description"].strip()
            assert param["required"] or "default" in param

    def test_no_hardcoded_address_or_secret(self, name: str) -> None:
        text = _text(name)
        assert not IPV4_PATTERN.search(text)
        assert not SECRET_PATTERN.search(text)


class TestAddonExecution:
    """Behaviour of the generated shell command."""

    def test_default_fills_placeholder_when_payload_lacks_the_key(self) -> None:
        commands, warnings = _run(_load("osv_scanner"), {})
        assert warnings == []
        assert commands == ["osv-scanner scan source -r --format json --output-file sessions/osv_scanner_output.json ."]

    def test_payload_value_overrides_the_default(self) -> None:
        commands, _ = _run(_load("osv_scanner"), {"osv_target": "external/project"})
        assert commands[0].endswith(" external/project")

    def test_codeql_resolves_both_defaults_in_every_step(self) -> None:
        commands, _ = _run(_load("codeql"), {})
        assert "{" not in commands[0]
        assert "--language=python --source-root=." in commands[0]
        assert "codeql/python-queries" in commands[0]
        assert commands[0].endswith("--output=sessions/codeql_python.sarif")

    def test_codeql_language_from_payload_is_used_everywhere(self) -> None:
        commands, _ = _run(_load("codeql"), {"codeql_language": "go"})
        assert "python" not in commands[0]
        assert commands[0].count("codeql_db_go") == 2
        assert "codeql/go-queries" in commands[0]

    def test_extra_arguments_are_appended(self) -> None:
        commands, _ = _run(_load("aflpp"), {}, "./target @@")
        assert commands == ["afl-fuzz -i sessions/afl_input -o sessions/afl_output -V 60 -- ./target @@"]

    def test_semgrep_scans_the_given_path(self) -> None:
        commands, _ = _run(_load("semgrep"), {}, "modules")
        assert commands == ["semgrep scan --config auto --json --output sessions/semgrep_output.json modules"]

    @pytest.mark.parametrize("name", ["subfinder", "httpx"])
    def test_domain_comes_from_the_payload(self, name: str) -> None:
        commands, warnings = _run(_load(name), {"domain": "example.com"})
        assert warnings == []
        assert f"sessions/{name}_example.com.txt" in commands[0]
        assert "{domain}" not in commands[0]

    @pytest.mark.parametrize("name", ["subfinder", "httpx"])
    def test_missing_required_domain_runs_nothing(self, name: str) -> None:
        commands, warnings = _run(_load(name), {})
        assert commands == []
        assert len(warnings) == 1 and "domain" in warnings[0]

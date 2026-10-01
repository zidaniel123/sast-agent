"""Phase 0 Semgrep pre-scan: parsing, rendering, invocation modes, opt-out.

No network, no API key, and no Semgrep binary required: subprocess and PATH
lookups are mocked everywhere, so these run in CI on a bare machine.
"""

from __future__ import annotations

import json
import subprocess

import pytest

import semgrep_scan
from semgrep_scan import (
    MAX_CANDIDATES,
    Candidate,
    ScanOutcome,
    SemgrepConfig,
    SemgrepUnavailableError,
    parse_results,
    render_candidates_block,
    resolve_command,
    run_scan,
)

SEMGREP_ENV_VARS = (
    "SAST_NO_SEMGREP",
    "SEMGREP_CONFIG",
    "SEMGREP_TIMEOUT",
    "SEMGREP_IMAGE",
)


@pytest.fixture
def clean_env(monkeypatch):
    """Remove every Semgrep variable so tests do not read the developer's .env."""
    for name in SEMGREP_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


SAMPLE_PAYLOAD = {
    "version": "1.95.0",
    "results": [
        {
            "check_id": "python.lang.security.audit.exec-detected.exec-detected",
            "path": "/src/app/handler.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 30},
            "extra": {
                "message": "Detected the use of exec().",
                "severity": "ERROR",
                "lines": "    exec(user_input)",
                "metadata": {
                    "cwe": [
                        "CWE-95: Improper Neutralization of Directives in "
                        "Dynamically Evaluated Code ('Eval Injection')"
                    ],
                    "owasp": ["A03:2021 - Injection"],
                },
            },
        },
        {
            "check_id": "python.lang.security.audit.md5-used-as-password",
            "path": "/src/app/auth.py",
            "start": {"line": 7, "col": 12},
            "extra": {
                "message": "MD5 used as a password hash.",
                "severity": "WARNING",
                "lines": "    h = hashlib.md5(password)",
                "metadata": {"cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"},
            },
        },
        {
            "check_id": "generic.toml.security.detected-secret",
            "path": "/src/config/settings.toml",
            "start": {"line": 3},
            "extra": {
                "message": "Possible hardcoded secret.",
                "severity": "INFO",
                "lines": "api_key = \"deadbeef\"",
                "metadata": {},
            },
        },
    ],
    "errors": [],
}


class TestConfigFromEnv:
    def test_defaults(self, clean_env):
        config = SemgrepConfig.from_env()
        assert not config.disabled
        assert config.config == "auto"
        assert config.timeout == 600
        assert config.image == "semgrep/semgrep:latest"

    def test_env_vars_are_read(self, clean_env):
        clean_env.setenv("SEMGREP_CONFIG", "p/python")
        clean_env.setenv("SEMGREP_TIMEOUT", "120")
        clean_env.setenv("SEMGREP_IMAGE", "semgrep/semgrep:1.95.0")
        config = SemgrepConfig.from_env()
        assert config.config == "p/python"
        assert config.timeout == 120
        assert config.image == "semgrep/semgrep:1.95.0"

    def test_sast_no_semgrep_disables(self, clean_env):
        clean_env.setenv("SAST_NO_SEMGREP", "1")
        assert SemgrepConfig.from_env().disabled

    @pytest.mark.parametrize("value", ["true", "YES", "on"])
    def test_other_truthy_values_disable(self, clean_env, value):
        clean_env.setenv("SAST_NO_SEMGREP", value)
        assert SemgrepConfig.from_env().disabled

    def test_cli_flag_disables(self, clean_env):
        assert SemgrepConfig.from_env(disabled=True).disabled

    def test_empty_config_falls_back_to_auto(self, clean_env):
        clean_env.setenv("SEMGREP_CONFIG", "  ")
        assert SemgrepConfig.from_env().config == "auto"


class TestResolveCommand:
    def test_local_binary_wins(self, monkeypatch):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
        )
        assert resolve_command(SemgrepConfig(disabled=False)) == ["/usr/local/bin/semgrep"]

    def test_docker_is_the_fallback(self, monkeypatch):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/docker" if name == "docker" else None,
        )
        prefix = resolve_command(SemgrepConfig(disabled=False))
        assert prefix == ["/usr/local/bin/docker", "run", "--rm"]

    def test_neither_returns_none(self, monkeypatch):
        monkeypatch.setattr(semgrep_scan.shutil, "which", lambda name: None)
        assert resolve_command(SemgrepConfig(disabled=False)) is None


class TestParseResults:
    def test_candidates_carry_rule_severity_location_snippet_cwe(self):
        candidates = parse_results(SAMPLE_PAYLOAD, "/src/")
        by_rule = {c.rule_id: c for c in candidates}
        exec_hit = by_rule["python.lang.security.audit.exec-detected.exec-detected"]
        assert exec_hit.severity == "error"
        assert exec_hit.path == "app/handler.py"
        assert exec_hit.line == 42
        assert exec_hit.snippet == "exec(user_input)"
        assert exec_hit.cwe == "CWE-95"
        assert "exec()" in exec_hit.message

    def test_string_shaped_cwe_metadata_is_accepted(self):
        candidates = parse_results(SAMPLE_PAYLOAD, "/src/")
        md5 = next(c for c in candidates if "md5" in c.rule_id)
        assert md5.cwe == "CWE-327"

    def test_missing_cwe_metadata_means_empty_cwe(self):
        candidates = parse_results(SAMPLE_PAYLOAD, "/src/")
        secret = next(c for c in candidates if "secret" in c.rule_id)
        assert secret.cwe == ""

    def test_sorted_by_severity_then_path(self):
        candidates = parse_results(SAMPLE_PAYLOAD, "/src/")
        assert [c.severity for c in candidates] == ["error", "warning", "info"]

    def test_docker_src_prefix_is_stripped(self):
        candidates = parse_results(SAMPLE_PAYLOAD, "/src/")
        assert all(not c.path.startswith("/src/") for c in candidates)

    def test_local_mode_leaves_relative_paths_alone(self):
        payload = json.loads(json.dumps(SAMPLE_PAYLOAD).replace("/src/", ""))
        candidates = parse_results(payload, "")
        assert candidates[0].path == "app/handler.py"

    def test_malformed_entries_are_skipped_not_fatal(self):
        payload = {"results": [{"check_id": "ok"}, "junk", None]}
        candidates = parse_results(payload)
        assert [c.rule_id for c in candidates] == ["ok"]

    def test_missing_results_key_means_no_candidates(self):
        assert parse_results({"version": "1.0"}) == []


class TestRunScan:
    def _completed(self, payload, returncode=0, stderr=""):
        return subprocess.CompletedProcess(
            args=[], returncode=returncode, stdout=json.dumps(payload), stderr=stderr
        )

    def test_disabled_short_circuits_without_touching_the_subprocess(self, monkeypatch):
        def _explode(*args, **kwargs):
            raise AssertionError("subprocess must not run when Phase 0 is disabled")

        monkeypatch.setattr(semgrep_scan.subprocess, "run", _explode)
        outcome = run_scan("/tmp/code", SemgrepConfig(disabled=True))
        assert outcome.status == "disabled"

    def test_missing_scanner_is_a_startup_error(self, monkeypatch):
        monkeypatch.setattr(semgrep_scan.shutil, "which", lambda name: None)
        with pytest.raises(SemgrepUnavailableError, match="SAST_NO_SEMGREP"):
            run_scan("/tmp/code", SemgrepConfig(disabled=False))

    def test_local_binary_invocation_and_parsing(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
        )
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs
            return self._completed(SAMPLE_PAYLOAD)

        monkeypatch.setattr(semgrep_scan.subprocess, "run", fake_run)
        outcome = run_scan(str(tmp_path), SemgrepConfig(disabled=False, timeout=120))
        assert outcome.status == "ok"
        assert outcome.version == "1.95.0"
        assert len(outcome.candidates) == 3
        argv = seen["argv"]
        assert argv[:1] == ["/usr/local/bin/semgrep"]
        assert "scan" in argv and "--json" in argv and "--metrics=off" in argv
        assert seen["kwargs"]["cwd"] == str(tmp_path)
        assert seen["kwargs"]["timeout"] == 120

    def test_docker_invocation_mounts_the_codebase_read_only(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/bin/docker" if name == "docker" else None,
        )
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            return self._completed(SAMPLE_PAYLOAD)

        monkeypatch.setattr(semgrep_scan.subprocess, "run", fake_run)
        config = SemgrepConfig(disabled=False, image="semgrep/semgrep:1.95.0")
        outcome = run_scan(str(tmp_path), config)
        argv = seen["argv"]
        assert argv[:3] == ["/usr/bin/docker", "run", "--rm"]
        assert f"{tmp_path}:/src:ro" in argv, "untrusted code must mount read-only"
        assert "semgrep/semgrep:1.95.0" in argv
        assert outcome.status == "ok"
        # /src/ prefixes from inside the container must not leak downstream.
        assert all(not c.path.startswith("/src/") for c in outcome.candidates)

    def test_zero_findings_is_empty_not_ok(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
        )
        payload = {"version": "1.95.0", "results": [], "errors": []}
        monkeypatch.setattr(
            semgrep_scan.subprocess, "run", lambda *a, **k: self._completed(payload)
        )
        outcome = run_scan(str(tmp_path), SemgrepConfig(disabled=False))
        assert outcome.status == "empty"
        assert outcome.candidates == ()

    def test_timeout_degrades_to_failed_with_detail(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
        )

        def fake_run(*a, **k):
            raise subprocess.TimeoutExpired(cmd="semgrep", timeout=120)

        monkeypatch.setattr(semgrep_scan.subprocess, "run", fake_run)
        outcome = run_scan(str(tmp_path), SemgrepConfig(disabled=False, timeout=120))
        assert outcome.status == "failed"
        assert "120" in outcome.detail

    def test_nonzero_exit_degrades_to_failed_with_stderr(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
        )
        monkeypatch.setattr(
            semgrep_scan.subprocess, "run",
            lambda *a, **k: self._completed({}, returncode=2, stderr="invalid config"),
        )
        outcome = run_scan(str(tmp_path), SemgrepConfig(disabled=False))
        assert outcome.status == "failed"
        assert "invalid config" in outcome.detail

    def test_unparseable_stdout_degrades_to_failed(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
        )
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="not json", stderr="")
        monkeypatch.setattr(semgrep_scan.subprocess, "run", lambda *a, **k: completed)
        outcome = run_scan(str(tmp_path), SemgrepConfig(disabled=False))
        assert outcome.status == "failed"

    def test_candidates_are_capped_and_marked_truncated(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            semgrep_scan.shutil, "which",
            lambda name: "/usr/local/bin/semgrep" if name == "semgrep" else None,
        )
        results = [
            {
                "check_id": f"rule.{i}",
                "path": f"f{i}.py",
                "start": {"line": 1},
                "extra": {"message": "m", "severity": "WARNING", "lines": "x"},
            }
            for i in range(MAX_CANDIDATES + 10)
        ]
        monkeypatch.setattr(
            semgrep_scan.subprocess, "run",
            lambda *a, **k: self._completed({"version": "1.0", "results": results}),
        )
        outcome = run_scan(str(tmp_path), SemgrepConfig(disabled=False))
        assert len(outcome.candidates) == MAX_CANDIDATES
        assert outcome.truncated


class TestRenderBlock:
    def _ok_outcome(self) -> ScanOutcome:
        return ScanOutcome(
            status="ok",
            candidates=(Candidate(
                rule_id="python.lang.security.audit.exec-detected",
                severity="error", path="app.py", line=42,
                message="exec()", snippet="exec(x)", cwe="CWE-95",
            ),),
            version="1.95.0",
            config="auto",
        )

    def test_ok_block_lists_candidates_as_json(self):
        block = render_candidates_block(self._ok_outcome())
        assert "1.95.0" in block
        assert "```json" in block
        assert "exec-detected" in block
        assert "CWE-95" in block
        assert "NOT the finding's severity" in block

    def test_truncation_is_stated(self):
        outcome = ScanOutcome(
            status="ok", candidates=self._ok_outcome().candidates,
            version="1.95.0", config="auto", truncated=True,
        )
        assert "TRUNCATED" in render_candidates_block(outcome)

    def test_empty_block_says_zero_and_not_evidence_of_safety(self):
        block = render_candidates_block(ScanOutcome(status="empty", version="1.95.0"))
        assert "ZERO findings" in block
        assert "not evidence of safety" in block

    def test_disabled_block_says_so_loudly(self):
        block = render_candidates_block(ScanOutcome(status="disabled", detail="disabled by operator"))
        assert "DISABLED" in block
        assert "no deterministic scanner leads" in block

    def test_failed_block_says_so_loudly(self):
        block = render_candidates_block(ScanOutcome(status="failed", detail="timed out"))
        assert "FAILED" in block
        assert "timed out" in block
        assert "no deterministic scanner leads" in block


class TestMetadata:
    def test_metadata_is_recorded_deterministically(self):
        outcome = ScanOutcome(
            status="ok",
            candidates=(
                Candidate("rule.a", "error", "a.py", 1, "m", "s"),
                Candidate("rule.a", "error", "a.py", 2, "m", "s"),
                Candidate("rule.b", "warning", "b.py", 3, "m", "s"),
            ),
            version="1.95.0",
            config="auto",
        )
        meta = outcome.metadata()
        assert meta["status"] == "ok"
        assert meta["version"] == "1.95.0"
        assert meta["candidate_count"] == 3
        # Same rule firing twice counts once: this is rules-triggered, not hits.
        assert meta["rules_triggered"] == 2

    def test_disabled_metadata_marks_the_report_as_ungrounded(self):
        meta = ScanOutcome(status="disabled", detail="disabled by operator").metadata()
        assert meta["status"] == "disabled"
        assert meta["candidate_count"] == 0


class TestCliFlag:
    def test_no_semgrep_flag_parses(self, monkeypatch):
        from main import _parse_args

        monkeypatch.setattr("sys.argv", ["main.py", "--path", "/tmp/x", "--no-semgrep"])
        assert _parse_args().no_semgrep is True

    def test_no_semgrep_flag_defaults_off(self, monkeypatch):
        from main import _parse_args

        monkeypatch.setattr("sys.argv", ["main.py", "--path", "/tmp/x"])
        assert _parse_args().no_semgrep is False

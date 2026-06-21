"""CLI (auditai.cli) 테스트."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditai.cli import _EXIT, _HARD_FAIL, _exit_code, build_parser, main
from auditai.contracts import (
    GateFailureCode, GateId, GateResult, GateStatus, Reliability, RunReport, RunStatus, TargetType,
)


def test_exit_code_map():
    assert _exit_code(RunStatus.NO_VULN_FOUND) == 0
    assert _exit_code(RunStatus.FINDINGS_PRESENT) == 1
    assert _exit_code(RunStatus.ANALYSIS_ERROR) == 2  # hard fail
    assert _exit_code(RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN) == 2
    assert _exit_code(RunStatus.COMPLETED_DEGRADED) == 3
    assert _exit_code(RunStatus.OUT_OF_MVP_SCOPE) == 4


def test_exit_code_exhaustive():
    """codex Q3-1: 모든 RunStatus 가 명시 분류돼야 한다(새 멤버 silent exit 2 방지)."""
    assert set(RunStatus) == set(_EXIT) | _HARD_FAIL
    for st in RunStatus:
        _exit_code(st)  # 미분류면 RuntimeError


def _fake_report(status=RunStatus.DIFF_SCOPE_MISSING):
    """monkeypatch 용 최소 유효 RunReport (G1 fail → DIFF_SCOPE_MISSING)."""
    g1f = GateResult(gate=GateId.G1, status=GateStatus.FAIL, code=GateFailureCode.G1_DIFF)
    return RunReport(run_id="x", target_type=TargetType.SYNTHETIC, run_status=status,
                     reliability=Reliability.UNRELIABLE, s2_completed=False, gate_results=[g1f])


def test_cli_codeql_validation_branch_wiring(monkeypatch, tmp_path: Path):
    """codex Q3-3: --codeql-validation 명시경로 > --run-codeql 기본 > None 분기가 run_pipeline 에 정확 전달."""
    captured = {}

    def rec(*a, **k):
        captured.update(k)
        return _fake_report()

    monkeypatch.setattr("auditai.cli.run_pipeline", rec)
    vfile = tmp_path / "v.json"
    vfile.write_text(json.dumps({"status": "run", "codeql_version": "9.9.9",
                                 "results": {"a": {"framework": "fastapi", "detected": True}}}),
                     encoding="utf-8")
    base = ["scan", "--repo", "r", "--base", "b", "--head", "h", "--run-id", "x",
            "--target-type", "synthetic", "--eval-target", "owasp_sourced", "--runs-dir", str(tmp_path)]
    # 명시 경로 우선
    main(base + ["--codeql-validation", str(vfile)])
    assert captured["validation_matrix"] == {"fastapi": True}
    assert captured["validation_codeql_version"] == "9.9.9"
    assert captured["track_a_required"] is False  # --run-codeql 없음
    # --run-codeql 기본 매트릭스 + 기본 버전 전달(codex Q3r2: version assert 보강)
    captured.clear()
    main(base + ["--run-codeql"])
    assert captured["validation_matrix"] == {"fastapi": True, "starlette": False, "strawberry": False}
    assert captured["validation_codeql_version"] == "2.25.6"  # 동봉 매트릭스 버전
    assert captured["track_a_required"] is True
    # 둘 다 없음 → None
    captured.clear()
    main(base)
    assert captured["validation_matrix"] is None and captured["validation_codeql_version"] is None


def test_cli_framework_append_passed_as_set(monkeypatch, tmp_path: Path):
    captured = {}
    monkeypatch.setattr("auditai.cli.run_pipeline", lambda *a, **k: captured.update(k) or _fake_report())
    main(["scan", "--repo", "r", "--base", "b", "--head", "h", "--run-id", "x",
          "--target-type", "synthetic", "--eval-target", "owasp_sourced", "--runs-dir", str(tmp_path),
          "--framework", "fastapi", "--framework", "starlette"])
    assert captured["frameworks"] == {"fastapi", "starlette"}


def _degraded_report():
    """유효한 COMPLETED_DEGRADED 리포트 (smoke + G2 degraded + s2 완료 + G3/G4 pass + finding0)."""
    return RunReport(
        run_id="x", target_type=TargetType.SMOKE, run_status=RunStatus.COMPLETED_DEGRADED,
        reliability=Reliability.UNRELIABLE, s2_completed=True,
        gate_results=[
            GateResult(gate=GateId.G1, status=GateStatus.PASS),
            GateResult(gate=GateId.G2, status=GateStatus.DEGRADED, code=GateFailureCode.G2_SOURCE_NOT_RUN),
            GateResult(gate=GateId.G3, status=GateStatus.PASS),
            GateResult(gate=GateId.G4, status=GateStatus.PASS),
        ])


def test_cli_exit3_degraded_wiring(monkeypatch, tmp_path: Path):
    """codex Q3-6: main() 이 COMPLETED_DEGRADED → exit 3 을 반환(CLI wiring)."""
    monkeypatch.setattr("auditai.cli.run_pipeline", lambda *a, **k: _degraded_report())
    code = main(["scan", "--repo", "r", "--base", "b", "--head", "h", "--run-id", "x",
                 "--target-type", "smoke", "--eval-target", "owasp_sourced", "--runs-dir", str(tmp_path)])
    assert code == 3


@pytest.mark.parametrize("exc", [OSError("disk full"),
                                 __import__("auditai.scope", fromlist=["GitError"]).GitError("git boom")])
def test_cli_operational_exception_clean_error(monkeypatch, tmp_path: Path, capsys, exc):
    """codex Q3-2: run_pipeline 의 OSError(artifact write)/GitError(detector) 도 traceback 누출 없이
    'auditai: error:' + exit 2 로 정규화."""
    def boom(*a, **k):
        raise exc

    monkeypatch.setattr("auditai.cli.run_pipeline", boom)
    code = main(["scan", "--repo", "r", "--base", "b", "--head", "h", "--run-id", "x",
                 "--target-type", "synthetic", "--eval-target", "owasp_sourced", "--runs-dir", str(tmp_path)])
    assert code == 2
    assert "auditai: error:" in capsys.readouterr().err


def test_cli_parser_invalid_target_type():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "--repo", "r", "--base", "b", "--head", "h",
                                   "--run-id", "x", "--target-type", "BOGUS", "--runs-dir", "d"])


def test_cli_parser_missing_required():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["scan", "--repo", "r"])  # base/head/run-id/target-type/runs-dir 누락


def test_parser_requires_subcommand():
    import pytest

    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_cli_track_b_only_findings(diff_repo: Path, tmp_path: Path):
    """codex Q2 R2-2: --run-codeql 없음(Track-B-only) + 삭제 가드 inventory → FINDINGS_PRESENT(exit 1)."""
    code = main([
        "scan", "--repo", str(diff_repo), "--base", "HEAD~1", "--head", "HEAD",
        "--run-id", "cli1", "--target-type", "synthetic",
        "--eval-target", "owasp_sourced", "--runs-dir", str(tmp_path),
    ])
    assert code == 1  # Track B inventory 가 findings 로 노출
    assert (tmp_path / "cli1" / "run_report.json").exists()


def test_cli_framework_no_matrix_hard_fail(fastapi_pr_repo: Path, tmp_path: Path):
    """framework 코드 + 검증 매트릭스 없음 → G2 NOT_RUN → exit 2 (빈 결과 오독 금지 가시화)."""
    code = main([
        "scan", "--repo", str(fastapi_pr_repo), "--base", "HEAD~1", "--head", "HEAD",
        "--run-id", "cli2", "--target-type", "synthetic",
        "--eval-target", "owasp_sourced", "--runs-dir", str(tmp_path),
    ])
    assert code == 2
    assert (tmp_path / "cli2" / "run_report.json").exists()


def test_cli_invalid_validation_file_not_run(fastapi_pr_repo: Path, tmp_path: Path, capsys):
    """codex Q3-4: status!=run 검증파일 → None → G2 NOT_RUN → exit 2 + stderr (framework 코드)."""
    vfile = tmp_path / "bad.json"
    vfile.write_text(json.dumps({"status": "skipped", "results": {}}), encoding="utf-8")
    code = main(["scan", "--repo", str(fastapi_pr_repo), "--base", "HEAD~1", "--head", "HEAD",
                 "--run-id", "badv", "--target-type", "synthetic", "--eval-target", "owasp_sourced",
                 "--runs-dir", str(tmp_path), "--codeql-validation", str(vfile)])
    assert code == 2
    assert "NOT RUN" in capsys.readouterr().err


def test_cli_gate_fail_visible_in_stderr(fastapi_pr_repo: Path, tmp_path: Path, capsys):
    """codex Q3-5: 게이트 실패가 stderr 로 가시화(빈 결과 오독 금지는 exit code 만으로 부족)."""
    code = main(["scan", "--repo", str(fastapi_pr_repo), "--base", "HEAD~1", "--head", "HEAD",
                 "--run-id", "gfv", "--target-type", "synthetic", "--eval-target", "owasp_sourced",
                 "--runs-dir", str(tmp_path)])
    assert code == 2
    err = capsys.readouterr().err
    assert "[G2" in err and "NOT RUN" in err


def test_cli_invalid_run_id_clean_error(diff_repo: Path, tmp_path: Path, capsys):
    """잘못된 run_id → traceback 아니라 깨끗한 에러 + exit 2."""
    code = main([
        "scan", "--repo", str(diff_repo), "--base", "HEAD~1", "--head", "HEAD",
        "--run-id", "../escape", "--target-type", "synthetic",
        "--eval-target", "owasp_sourced", "--runs-dir", str(tmp_path),
    ])
    assert code == 2
    assert "error:" in capsys.readouterr().err


def test_cli_run_codeql_flag_parses():
    args = build_parser().parse_args([
        "scan", "--repo", "r", "--base", "b", "--head", "h", "--run-id", "x",
        "--target-type", "synthetic", "--runs-dir", "d", "--run-codeql",
    ])
    assert args.run_codeql is True

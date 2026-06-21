"""AuditAI CLI — end-to-end 파이프라인 실행 진입점.

사용: python -m auditai scan --repo . --base origin/main --head HEAD --run-id r1 \
        --target-type synthetic --eval-target synthetic_python --runs-dir runs

종료코드(RunStatus → CI exit bucket; 5개 버킷으로 그룹화):
  0  NO_VULN_FOUND (clean — Track A taint 실행+0 finding)
  1  FINDINGS_PRESENT (Track A finding, 또는 --run-codeql 없는 Track-B-only 실행의 inventory)
  2  hard fail (DIFF_SCOPE_MISSING / FRAMEWORK_SOURCE_*  / ANALYSIS_ERROR / EVAL_* / AUTHZ_*)
  3  COMPLETED_DEGRADED (smoke, 신뢰불가)
  4  OUT_OF_MVP_SCOPE

NOTE(codex Q2 R2-2): `--run-codeql` 없으면 Track-B-only 모드(track_a_required=False) — Track B
inventory 가 있으면 FINDINGS_PRESENT(exit 1, unreliable), 없으면 ANALYSIS_ERROR(taint 미실행이라
clean 주장 금지). `--run-codeql` 면 full-scan(track_a_required=True) — taint 미완료 시 ANALYSIS_ERROR.
"""

from __future__ import annotations

import argparse
import sys

from .contracts import RunStatus, TargetType
from .run import run_pipeline
from .scope import GitError

_EXIT = {
    RunStatus.NO_VULN_FOUND: 0,
    RunStatus.FINDINGS_PRESENT: 1,
    RunStatus.COMPLETED_DEGRADED: 3,
    RunStatus.OUT_OF_MVP_SCOPE: 4,
}
# 나머지는 전부 hard-fail(exit 2). codex Q3-1: 새 RunStatus 가 추가되면 조용히 2 로 떨어지지
# 않도록 명시 분류한다 — 모든 enum 멤버가 _EXIT ∪ _HARD_FAIL 에 있어야 함(test_exit_code_exhaustive).
_HARD_FAIL = {
    RunStatus.DIFF_SCOPE_MISSING,
    RunStatus.FRAMEWORK_SOURCE_VALIDATION_NOT_RUN,
    RunStatus.FRAMEWORK_SOURCE_MODEL_MISSING,
    RunStatus.EVAL_TARGET_INSUFFICIENT,
    RunStatus.AUTHZ_SCOPE_UNDECLARED,
    RunStatus.ANALYSIS_ERROR,
    RunStatus.SEMANTIC_JUDGE_NOT_RUN,  # codex MVP r2 M5: S3 미완 = hard fail(exit 2)
}


def _exit_code(status: RunStatus) -> int:
    if status in _EXIT:
        return _EXIT[status]
    if status in _HARD_FAIL:
        return 2
    # 미분류 RunStatus → 조용히 2 로 떨어뜨리지 않고 실패시켜 강제 분류(새 "clean"류 오분류 방지).
    raise RuntimeError(f"unclassified RunStatus for CLI exit code: {status!r}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditai", description="AI-authored code SAST triage")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="PR diff 를 분석해 RunReport 산출")
    s.add_argument("--repo", required=True)
    s.add_argument("--base", required=True, help="base ref (merge-base 계산용)")
    s.add_argument("--head", required=True, help="head ref")
    s.add_argument("--run-id", required=True)
    s.add_argument("--target-type", required=True, choices=[t.value for t in TargetType])
    s.add_argument("--eval-target", action="append", default=[], dest="eval_targets",
                   help="반복 지정. 효과입증 타겟(synthetic/known_cve) 없이 phoenix 단독이면 G3 실패")
    s.add_argument("--runs-dir", required=True)
    s.add_argument("--framework", action="append", default=None, dest="frameworks",
                   help="명시 프레임워크(없으면 diff+repo-wide 탐지)")
    s.add_argument("--run-codeql", action="store_true",
                   help="CodeQL CLI 가 있으면 Track A taint 를 실제로 실행(P0-3b)")
    s.add_argument("--codeql-validation", default=None, dest="codeql_validation",
                   help="framework source 검증 매트릭스 JSON 경로(G2). 미지정+--run-codeql 이면 "
                        "동봉 기본 매트릭스 사용. 프레임워크 코드인데 둘 다 없으면 G2 NOT_RUN(hard fail)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "scan":
        # G2 검증 매트릭스(+ 검증된 CodeQL 버전): 명시 경로 우선, 없고 --run-codeql 이면 동봉 기본값
        from .codeql import (
            default_validation_codeql_version,
            default_validation_matrix,
            load_source_validation_matrix,
            source_validation_codeql_version,
        )
        if args.codeql_validation:
            validation_matrix = load_source_validation_matrix(args.codeql_validation)
            validation_codeql_version = source_validation_codeql_version(args.codeql_validation)
        elif args.run_codeql:
            validation_matrix = default_validation_matrix()
            validation_codeql_version = default_validation_codeql_version()
        else:
            validation_matrix = None
            validation_codeql_version = None
        try:
            report = run_pipeline(
                args.repo, args.base, args.head,
                run_id=args.run_id,
                target_type=TargetType(args.target_type),
                eval_targets=args.eval_targets,
                runs_dir=args.runs_dir,
                validation_matrix=validation_matrix,
                validation_codeql_version=validation_codeql_version,
                frameworks=set(args.frameworks) if args.frameworks else None,
                run_codeql=args.run_codeql,
                # --run-codeql 없으면 Track-B-only(taint 미요구) — inventory 를 FINDINGS 로 노출
                track_a_required=args.run_codeql,
            )
        except (ValueError, FileExistsError, OSError, GitError) as e:
            # 운영 예외(잘못된 run_id/충돌/계약위반/파일 IO/git) → traceback 누출 없이 깨끗한 에러 +
            # hard-fail 종료코드(빈 결과 오독 금지). codex Q3-2: OSError(artifact write)·GitError
            # (Track B detector)도 정규화.
            print(f"auditai: error: {e}", file=sys.stderr)
            return 2
        rel = report.reliability.value
        print(f"run_status={report.run_status.value} reliability={rel} "
              f"findings={len(report.findings)} risk_inventory={len(report.risk_inventory)}")
        # 게이트 실패는 표준에러로(빈 결과 오독 금지를 가시화)
        for g in report.gate_results:
            if g.status.value in ("fail", "degraded"):
                print(f"  [{g.gate.value} {g.status.value}] {g.message}", file=sys.stderr)
        return _exit_code(report.run_status)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

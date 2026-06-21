"""AuditAI — AI(Claude)-authored code 우선 SAST triage (MVP / Slice 1).

설계 단일 진실원: docs/03-blueprint.md (codex sign-off 96/100).
이 패키지는 청사진 §7 데이터 계약과 S0~S4 파이프라인을 구현한다.
현재 구현 범위(Slice 1 기반): 데이터 계약(contracts) + S0 귀속(attribution) + Security KB.
"""

__version__ = "0.1.0"

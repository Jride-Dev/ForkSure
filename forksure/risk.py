from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol


class RepoRiskInput(Protocol):
    pushed_at: datetime | None
    stargazers_count: int
    default_branch: str


@dataclass(frozen=True)
class RiskSignal:
    name: str
    points: int
    detail: str


@dataclass(frozen=True)
class RiskScore:
    score: int
    level: str
    signals: tuple[RiskSignal, ...]


def score_repo(
    repo: RepoRiskInput,
    *,
    upstream_default_branch: str | None = None,
    now: datetime | None = None,
) -> RiskScore:
    current_time = _as_aware_utc(now or datetime.now(UTC))
    signals: list[RiskSignal] = []

    if repo.pushed_at is None:
        signals.append(RiskSignal("never_pushed", 35, "Repository has no pushed_at timestamp."))
    else:
        pushed_at = _as_aware_utc(repo.pushed_at)
        if pushed_at < current_time - timedelta(days=365):
            signals.append(RiskSignal("stale", 25, "Repository has not been pushed in over a year."))

    if repo.stargazers_count == 0:
        signals.append(RiskSignal("no_stars", 5, "Repository has no stars."))

    if upstream_default_branch and repo.default_branch != upstream_default_branch:
        signals.append(
            RiskSignal(
                "branch_drift",
                10,
                f"Default branch differs from upstream ({upstream_default_branch}).",
            )
        )

    score = min(100, sum(signal.points for signal in signals))
    return RiskScore(score=score, level=_level_for(score), signals=tuple(signals))


def _level_for(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)

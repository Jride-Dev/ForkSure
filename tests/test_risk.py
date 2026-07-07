from dataclasses import dataclass
from datetime import UTC, datetime

from forksure.risk import score_repo


@dataclass
class Repo:
    pushed_at: datetime | None
    stargazers_count: int
    default_branch: str


def test_score_repo_stale_fork_is_medium_risk() -> None:
    repo = Repo(
        pushed_at=datetime(2024, 1, 1, tzinfo=UTC),
        stargazers_count=0,
        default_branch="master",
    )

    score = score_repo(
        repo,
        upstream_default_branch="main",
        now=datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert score.score == 40
    assert score.level == "medium"
    assert {signal.name for signal in score.signals} == {"stale", "no_stars", "branch_drift"}


def test_score_repo_active_popular_fork_is_low_risk() -> None:
    repo = Repo(
        pushed_at=datetime(2026, 1, 1, tzinfo=UTC),
        stargazers_count=5,
        default_branch="main",
    )

    score = score_repo(
        repo,
        upstream_default_branch="main",
        now=datetime(2026, 6, 1, tzinfo=UTC),
    )

    assert score.score == 0
    assert score.level == "low"
    assert score.signals == ()

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from forksure.json_reports import dumps_json_report, to_jsonable, write_json_report


@dataclass(frozen=True)
class Example:
    path: Path
    created_at: datetime


def test_to_jsonable_handles_paths_dataclasses_and_datetimes() -> None:
    value = Example(Path("reports/example.json"), datetime(2026, 1, 1, tzinfo=UTC))

    result = to_jsonable(value)

    assert result == {
        "path": "reports\\example.json" if "\\" in str(Path("reports/example.json")) else "reports/example.json",
        "created_at": "2026-01-01T00:00:00+00:00",
    }


def test_write_json_report_writes_pretty_json(tmp_path) -> None:
    output_path = tmp_path / "report.json"

    result = write_json_report({"risk": "INFO"}, output_path)

    assert result == output_path
    assert output_path.read_text(encoding="utf-8") == '{\n  "risk": "INFO"\n}\n'


def test_dumps_json_report_preserves_readable_key_order() -> None:
    output = dumps_json_report({"source_repo": "a/b", "candidate_repo": "c/d"})

    assert output.splitlines()[1].strip() == '"source_repo": "a/b",'

from pathlib import Path

from forksure import similarity_scanner
from forksure.similarity_scanner import MAX_FILE_SIZE_BYTES, scan_repository_similarity


def test_similarity_scanner_finds_exact_same_files(monkeypatch, tmp_path) -> None:
    source = tmp_path / "source"
    candidate = tmp_path / "candidate"
    _write(source / "README.md", "same text\n")
    _write(candidate / "README.md", "same text\n")

    _mock_clones(monkeypatch, {"source/repo": source, "candidate/repo": candidate})

    result = scan_repository_similarity("source/repo", "candidate/repo")

    assert result["source_file_count"] == 1
    assert result["candidate_file_count"] == 1
    assert result["shared_path_count"] == 1
    assert result["exact_hash_match_count"] == 1
    assert result["overall_similarity_score"] == 100
    assert result["top_matches"][0]["source_path"] == "README.md"


def test_similarity_scanner_ignores_generated_and_cache_paths(monkeypatch, tmp_path) -> None:
    source = tmp_path / "source"
    candidate = tmp_path / "candidate"
    _write(source / "src" / "app.py", "print('same')\n")
    _write(candidate / "src" / "app.py", "print('same')\n")
    for ignored in [".git", "node_modules", ".forksure-cache", "reports"]:
        _write(source / ignored / "ignored.py", "print('ignored')\n")
        _write(candidate / ignored / "ignored.py", "print('ignored')\n")

    _mock_clones(monkeypatch, {"source/repo": source, "candidate/repo": candidate})

    result = scan_repository_similarity("source/repo", "candidate/repo")

    assert result["source_file_count"] == 1
    assert result["candidate_file_count"] == 1
    assert result["exact_hash_match_count"] == 1
    assert result["ignored_paths_summary"]["ignored_directories"] >= 8


def test_similarity_scanner_skips_large_files(monkeypatch, tmp_path) -> None:
    source = tmp_path / "source"
    candidate = tmp_path / "candidate"
    _write(source / "large.py", "a" * (MAX_FILE_SIZE_BYTES + 1))
    _write(candidate / "large.py", "a" * (MAX_FILE_SIZE_BYTES + 1))

    _mock_clones(monkeypatch, {"source/repo": source, "candidate/repo": candidate})

    result = scan_repository_similarity("source/repo", "candidate/repo")

    assert result["source_file_count"] == 0
    assert result["candidate_file_count"] == 0
    assert result["overall_similarity_score"] == 0
    assert result["ignored_paths_summary"]["skipped_large_files"] == 2


def test_similarity_score_is_zero_for_unrelated_files(monkeypatch, tmp_path) -> None:
    source = tmp_path / "source"
    candidate = tmp_path / "candidate"
    _write(source / "src" / "source.py", "print('source')\n")
    _write(candidate / "docs" / "candidate.md", "# Candidate\n")

    _mock_clones(monkeypatch, {"source/repo": source, "candidate/repo": candidate})

    result = scan_repository_similarity("source/repo", "candidate/repo")

    assert result["source_file_count"] == 1
    assert result["candidate_file_count"] == 1
    assert result["shared_path_count"] == 0
    assert result["exact_hash_match_count"] == 0
    assert result["overall_similarity_score"] == 0


def _mock_clones(monkeypatch, paths: dict[str, Path]) -> None:
    monkeypatch.setattr(similarity_scanner, "_ensure_repo_clone", lambda owner_repo: paths[owner_repo])


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

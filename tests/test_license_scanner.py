from forksure.license_scanner import compare_licenses


def test_license_comparison_same_is_info() -> None:
    source = {"found": True, "key": "mit", "spdx_id": "MIT", "name": "MIT License"}
    fork = {"found": True, "key": "mit", "spdx_id": "MIT", "name": "MIT License"}

    result = compare_licenses(source, fork)

    assert result["status"] == "same"
    assert result["severity"] == "info"


def test_license_comparison_missing_fork_license_is_medium() -> None:
    source = {"found": True, "key": "mit", "spdx_id": "MIT", "name": "MIT License"}
    fork = {"found": False, "key": None, "spdx_id": None, "name": None}

    result = compare_licenses(source, fork)

    assert result["status"] == "missing"
    assert result["severity"] == "medium"


def test_license_comparison_changed_fork_license_is_high() -> None:
    source = {"found": True, "key": "mit", "spdx_id": "MIT", "name": "MIT License"}
    fork = {"found": True, "key": "apache-2.0", "spdx_id": "Apache-2.0", "name": "Apache License 2.0"}

    result = compare_licenses(source, fork)

    assert result["status"] == "changed"
    assert result["severity"] == "high"


def test_license_comparison_unknown_license_is_handled_gracefully() -> None:
    source = {"found": False, "key": None, "spdx_id": None, "name": None}
    fork = {"found": True, "key": "mit", "spdx_id": "MIT", "name": "MIT License"}

    result = compare_licenses(source, fork)

    assert result["status"] == "unknown"
    assert result["severity"] == "low"

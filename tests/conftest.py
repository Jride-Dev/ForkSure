from __future__ import annotations

import re
import shutil
import uuid
from pathlib import Path

import pytest


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
TEST_TMP_ROOT = WORKSPACE_ROOT / ".cbh-test-tmp"


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest) -> Path:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", request.node.name)[:60]
    path = TEST_TMP_ROOT / f"{safe_name}-{uuid.uuid4().hex}"
    path.mkdir(parents=True, exist_ok=False)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
        try:
            TEST_TMP_ROOT.rmdir()
        except OSError:
            pass

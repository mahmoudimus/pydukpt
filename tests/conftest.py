from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

FIXTURE = Path(__file__).parent / "fixtures" / "vectors.json"


def load_vectors() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text())


VECTORS = load_vectors()


def h(s: str) -> bytes:
    return bytes.fromhex(s)


@pytest.fixture(scope="session")
def vectors() -> dict[str, Any]:
    return VECTORS

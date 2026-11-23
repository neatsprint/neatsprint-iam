from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from neatsprint_lib.db import get_session

from neatsprint_iam.main import app

PAYLOAD = {
    "tenant_id": "018f0a00-0000-7000-8000-000000000001",
    "user_ids": ["018f0a00-0000-7000-8000-000000000002"],
}


class _FakeScalars:
    def __iter__(self) -> Any:
        return iter([])


class _FakeResult:
    def scalars(self) -> _FakeScalars:
        return _FakeScalars()


class _FakeSession:
    async def execute(self, statement: object) -> _FakeResult:
        return _FakeResult()


async def _fake_session() -> AsyncIterator[_FakeSession]:
    yield _FakeSession()


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app.state.settings, "bootstrap_token", "test-token")
    app.dependency_overrides[get_session] = _fake_session
    yield
    app.dependency_overrides.clear()


def test_lookup_rejects_missing_or_wrong_token() -> None:
    client = TestClient(app)
    assert client.post("/internal/users/lookup", json=PAYLOAD).status_code == 403
    assert (
        client.post(
            "/internal/users/lookup", json=PAYLOAD, headers={"X-Bootstrap-Token": "wrong"}
        ).status_code
        == 403
    )


def test_lookup_returns_envelope() -> None:
    response = TestClient(app).post(
        "/internal/users/lookup", json=PAYLOAD, headers={"X-Bootstrap-Token": "test-token"}
    )
    assert response.status_code == 200
    assert response.json()["data"] == []

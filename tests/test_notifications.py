from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from neatsprint_iam.services import event_consumer
from neatsprint_iam.services.assignment_email import (
    AssignmentNotice,
    render_assignment_digest,
)

TENANT_ID: UUID = uuid4()
ASSIGNEE_ID: UUID = uuid4()
PROJECT_ID: UUID = uuid4()


class _FakeResult:
    def first(self) -> None:
        return None


class _FakeSession:
    def __init__(self, user: object | None = None) -> None:
        self.user = user
        self.added: list[object] = []
        self.committed = False

    async def execute(self, statement: object) -> _FakeResult:
        return _FakeResult()

    async def get(self, model: object, key: object) -> object | None:
        return self.user

    def add(self, instance: object) -> None:
        self.added.append(instance)

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        return None


def _assignment_fields(**overrides: str) -> dict[str, str]:
    values = {
        "event_type": "item.assigned",
        "event_id": str(uuid4()),
        "tenant_id": str(TENANT_ID),
        "actor_id": str(uuid4()),
        "data": json.dumps(
            {
                "item_id": str(uuid4()),
                "project_id": str(PROJECT_ID),
                "key": "AUTH-1",
                "title": "Device-bound sessions",
                "assignee_id": str(ASSIGNEE_ID),
            }
        ),
    }
    values.update(overrides)
    return values


async def test_assignment_event_creates_notification() -> None:
    session = _FakeSession(SimpleNamespace(tenant_id=TENANT_ID, deleted_at=None))

    created = await event_consumer.handle_event(session, _assignment_fields())

    assert created is True
    assert session.committed is True
    assert len(session.added) == 1
    notification = session.added[0]
    assert notification.user_id == ASSIGNEE_ID
    assert "AUTH-1" in notification.title


async def test_self_assignment_is_ignored() -> None:
    actor = uuid4()
    fields = _assignment_fields(actor_id=str(actor))
    payload = json.loads(fields["data"])
    payload["assignee_id"] = str(actor)
    fields["data"] = json.dumps(payload)
    session = _FakeSession(SimpleNamespace(tenant_id=TENANT_ID, deleted_at=None))

    assert await event_consumer.handle_event(session, fields) is False
    assert session.added == []


async def test_unknown_assignee_is_ignored() -> None:
    session = _FakeSession(None)

    assert await event_consumer.handle_event(session, _assignment_fields()) is False
    assert session.added == []


async def test_other_events_are_ignored() -> None:
    session = _FakeSession(SimpleNamespace(tenant_id=TENANT_ID, deleted_at=None))

    assert (
        await event_consumer.handle_event(
            session, _assignment_fields(event_type="item.created")
        )
        is False
    )
    assert session.added == []


def _notice(key: str = "AUTH-1") -> AssignmentNotice:
    return AssignmentNotice(
        item_key=key,
        item_title="Device-bound sessions",
        project_name="Authentication",
        link="https://app.neatsprint.test/projects/1/backlog",
    )


def test_assignment_email_handles_a_single_item() -> None:
    content = render_assignment_digest(
        recipient_name="Mia Member",
        actor_name="Olivia Owner",
        notices=[_notice()],
        settings_url="https://app.neatsprint.test/settings",
    )

    assert content.subject == "1 item assigned to you"
    assert "AUTH-1 Device-bound sessions" in content.text
    assert "https://app.neatsprint.test/projects/1/backlog" in content.text


def test_assignment_email_batches_and_escapes() -> None:
    notice = AssignmentNotice(
        item_key="AUTH-2",
        item_title="<script>alert(1)</script>",
        project_name="Authentication & Access",
        link="https://app.neatsprint.test/projects/1/backlog",
    )
    content = render_assignment_digest(
        recipient_name="Mia Member",
        actor_name="Olivia Owner",
        notices=[_notice(), notice],
        settings_url="https://app.neatsprint.test/settings",
    )

    assert content.subject == "2 items assigned to you"
    assert "&lt;script&gt;" in content.html
    assert "<script>" not in content.html


def test_assignment_email_requires_absolute_links() -> None:
    bad = AssignmentNotice(
        item_key="AUTH-3",
        item_title="Relative",
        project_name="Authentication",
        link="/projects/1/backlog",
    )
    with pytest.raises(ValueError):
        render_assignment_digest(
            recipient_name="Mia",
            actor_name="Olivia",
            notices=[bad],
            settings_url="https://app.neatsprint.test/settings",
        )
    with pytest.raises(ValueError):
        render_assignment_digest(
            recipient_name="Mia",
            actor_name="Olivia",
            notices=[],
            settings_url="https://app.neatsprint.test/settings",
        )

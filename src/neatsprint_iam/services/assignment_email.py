"""Digest-safe assignment email rendering.

Pure functions with no I/O, no tracking pixels and no per-recipient tokens, so the same
message can be batched into a daily digest. A single assignment is a digest of one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from html import escape


@dataclass(frozen=True, slots=True)
class AssignmentNotice:
    item_key: str
    item_title: str
    project_name: str
    link: str


@dataclass(frozen=True, slots=True)
class EmailContent:
    subject: str
    text: str
    html: str


def render_assignment_digest(
    *,
    recipient_name: str,
    actor_name: str,
    notices: Sequence[AssignmentNotice],
    settings_url: str,
) -> EmailContent:
    if not notices:
        raise ValueError("at least one assignment is required")
    for notice in notices:
        if not notice.link.startswith(("http://", "https://")):
            raise ValueError("assignment links must be absolute")

    count = len(notices)
    item_word = "item" if count == 1 else "items"
    subject = f"{count} {item_word} assigned to you"

    text_lines = [
        f"Hi {recipient_name},",
        "",
        f"{actor_name} assigned {count} {item_word} to you:",
        "",
    ]
    for notice in notices:
        text_lines.append(
            f"- {notice.item_key} {notice.item_title} ({notice.project_name})"
        )
        text_lines.append(f"  {notice.link}")
    text_lines.extend(
        [
            "",
            f"Manage notification settings: {settings_url}",
            "You receive this because items were assigned to you in NeatSprint.",
        ]
    )

    rows = "".join(
        (
            "<li>"
            f"<strong>{escape(notice.item_key)}</strong> {escape(notice.item_title)} "
            f"<span>({escape(notice.project_name)})</span><br />"
            f'<a href="{escape(notice.link, quote=True)}">{escape(notice.link)}</a>'
            "</li>"
        )
        for notice in notices
    )
    html = (
        '<div style="font-family:Arial,sans-serif;line-height:1.5;color:#0f172a">'
        f"<p>Hi {escape(recipient_name)},</p>"
        f"<p>{escape(actor_name)} assigned {count} {item_word} to you:</p>"
        f"<ul>{rows}</ul>"
        f'<p><a href="{escape(settings_url, quote=True)}">Manage notification settings</a></p>'
        '<p style="color:#64748b;font-size:12px">'
        "You receive this because items were assigned to you in NeatSprint."
        "</p>"
        "</div>"
    )
    return EmailContent(subject=subject, text="\n".join(text_lines), html=html)

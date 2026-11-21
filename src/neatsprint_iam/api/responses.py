from __future__ import annotations

from typing import Any

from fastapi import Request


def envelope(request: Request, data: Any, **meta: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "data": data,
        "meta": {"request_id": getattr(request.state, "request_id", None)},
    }
    payload["meta"].update(meta)
    return payload

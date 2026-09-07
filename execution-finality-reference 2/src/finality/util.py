from __future__ import annotations

import base64


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64d(value: str, maximum: int = 16384) -> bytes:
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise ValueError("invalid base64url input")
    if any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value):
        raise ValueError("non-base64url character")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) > maximum:
        raise ValueError("decoded input exceeds limit")
    return raw


"""Strict deterministic CBOR subset used by the experimental profile.

Supported types are integers, bytes, UTF-8 strings, arrays, maps, booleans,
and null. Indefinite-length values, floats, tags, duplicate map keys, and
non-minimal integer encodings are rejected. Map keys use RFC 8949 core
deterministic ordering: encoded-key length followed by bytewise order.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class CBORError(ValueError):
    pass


def _head(major: int, value: int) -> bytes:
    if value < 0:
        raise CBORError("negative CBOR argument")
    prefix = major << 5
    if value < 24:
        return bytes([prefix | value])
    if value <= 0xFF:
        return bytes([prefix | 24, value])
    if value <= 0xFFFF:
        return bytes([prefix | 25]) + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + value.to_bytes(4, "big")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + value.to_bytes(8, "big")
    raise CBORError("integer outside uint64 range")


def dumps(value: Any) -> bytes:
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(dumps(item) for item in value)
    if isinstance(value, dict):
        encoded: list[tuple[bytes, bytes]] = []
        for key, item in value.items():
            ek = dumps(key)
            encoded.append((ek, dumps(item)))
        encoded.sort(key=lambda pair: (len(pair[0]), pair[0]))
        return _head(5, len(encoded)) + b"".join(k + v for k, v in encoded)
    raise CBORError(f"unsupported type: {type(value).__name__}")


@dataclass
class _Decoder:
    data: bytes
    pos: int = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise CBORError("truncated CBOR")
        out = self.data[self.pos:end]
        self.pos = end
        return out

    def argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        sizes = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in sizes:
            raise CBORError("indefinite or reserved encoding rejected")
        size = sizes[additional]
        raw = self.take(size)
        value = int.from_bytes(raw, "big")
        minimum = {1: 24, 2: 256, 4: 65536, 8: 4294967296}[size]
        if value < minimum:
            raise CBORError("non-minimal integer encoding")
        return value

    def item(self) -> Any:
        initial = self.take(1)[0]
        major, additional = initial >> 5, initial & 31
        if major == 7:
            if additional == 20:
                return False
            if additional == 21:
                return True
            if additional == 22:
                return None
            raise CBORError("unsupported simple value")
        arg = self.argument(additional)
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return self.take(arg)
        if major == 3:
            try:
                return self.take(arg).decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise CBORError("invalid UTF-8") from exc
        if major == 4:
            return [self.item() for _ in range(arg)]
        if major == 5:
            out: dict[Any, Any] = {}
            previous: tuple[int, bytes] | None = None
            for _ in range(arg):
                start = self.pos
                key = self.item()
                encoded_key = self.data[start:self.pos]
                order = (len(encoded_key), encoded_key)
                if previous is not None and order <= previous:
                    raise CBORError("map keys are duplicate or not deterministic")
                previous = order
                try:
                    if key in out:
                        raise CBORError("duplicate map key")
                    out[key] = self.item()
                except TypeError as exc:
                    raise CBORError("unhashable map key") from exc
            return out
        raise CBORError(f"unsupported major type {major}")


def loads(data: bytes) -> Any:
    decoder = _Decoder(data)
    value = decoder.item()
    if decoder.pos != len(data):
        raise CBORError("trailing data")
    if dumps(value) != data:
        raise CBORError("input is not deterministically encoded")
    return value


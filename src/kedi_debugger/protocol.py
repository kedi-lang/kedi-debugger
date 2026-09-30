"""Bounded DAP framing shared by the editor transport and private worker pipes."""

from __future__ import annotations

import json
import math
from typing import Any, BinaryIO

MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 8 * 1024

__all__ = ["MAX_MESSAGE_BYTES", "ProtocolError", "read_message", "write_message"]


class ProtocolError(ValueError):
    """Malformed, truncated, or oversized protocol input; never includes raw data."""


def _invalid_constant(value: str) -> None:
    raise ProtocolError("Non-finite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ProtocolError("Non-finite JSON number")
    return number


def _validate_unicode(value: Any) -> None:
    if isinstance(value, str):
        value.encode("utf-8")
    elif isinstance(value, dict):
        for key, item in value.items():
            key.encode("utf-8")
            _validate_unicode(item)
    elif isinstance(value, list):
        for item in value:
            _validate_unicode(item)


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    """Read one UTF-8 JSON object, returning None only for clean between-frame EOF."""
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        byte = stream.read(1)
        if not byte:
            if not header:
                return None
            raise ProtocolError("Truncated message header")
        header.extend(byte)
        if len(header) > MAX_HEADER_BYTES:
            raise ProtocolError("Message header exceeds 8 KiB")

    length: int | None = None
    for line in header[:-4].split(b"\r\n"):
        name, separator, value = line.partition(b":")
        if not separator or not name or any(byte < 33 or byte > 126 for byte in name):
            raise ProtocolError("Malformed message header")
        if any(byte < 32 and byte != 9 or byte > 126 for byte in value):
            raise ProtocolError("Message headers must be ASCII")
        if name.lower() == b"content-length":
            value = value.strip()
            if length is not None or not value.isdigit() or len(value) > 10:
                raise ProtocolError("Invalid or duplicate Content-Length")
            length = int(value)
    if length is None or not 0 < length <= MAX_MESSAGE_BYTES:
        raise ProtocolError("Content-Length must be between 1 and 4 MiB")

    body = bytearray()
    while len(body) < length:
        chunk = stream.read(length - len(body))
        if not chunk:
            raise ProtocolError("Truncated message body")
        body.extend(chunk)
    try:
        message = json.loads(
            body.decode("utf-8"), parse_constant=_invalid_constant, parse_float=_finite_float
        )
        _validate_unicode(message)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("Message must contain valid UTF-8 JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("Message must be a JSON object")
    return message


def write_message(stream: BinaryIO, message: dict[str, Any]) -> None:
    """Write a complete frame; callers serialize concurrent writes to the stream."""
    if not isinstance(message, dict):
        raise ProtocolError("Message must be a JSON object")
    try:
        body = json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        payload = body.encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("Message must contain valid UTF-8 JSON") from exc
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError("Message body exceeds 4 MiB")
    frame = memoryview(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii") + payload)
    while frame:
        written = stream.write(frame)
        if written is None or written <= 0:
            raise OSError("Protocol stream made no write progress")
        frame = frame[written:]
    stream.flush()

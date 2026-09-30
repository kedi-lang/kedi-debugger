"""Bounded, non-evaluating value capture for the debugger's JSON boundary."""

from __future__ import annotations

import json
import os
import re
from concurrent.futures import Future
from types import MappingProxyType
from typing import Any, Iterator, TypedDict

from pydantic import BaseModel
from typing_extensions import NotRequired

from kedi.lang.compiler.environment import KediEnv, ScopeFrame
from kedi.promise import KediPromise

from .redaction import is_token_metric_name

__all__ = ["Snapshot", "SnapshotLimitError", "SnapshotNode"]


class SnapshotNode(TypedDict):
    name: str
    value: str
    type: str
    children: NotRequired[list[SnapshotNode]]


class SnapshotLimitError(ValueError):
    """No room remains for another root; retain the roots already captured."""


_REDACTED = "<redacted>"
_TRUNCATED = " <truncated>"
_TRUNCATION_RESERVE = len(" <truncated: changed>")
_SOURCE_CHARACTERS = re.compile(r"[^\r\n]")
_MISSING = object()
_TYPE_DICT = type.__dict__["__dict__"]
_TYPE_MRO = type.__dict__["__mro__"]
_TYPE_NAME = type.__dict__["__name__"]
_MODEL_DICT = BaseModel.__dict__["__dict__"]
_PROMISE_FUTURE = KediPromise.__dict__["_future"]
_PROMISE_KEY = KediPromise.__dict__["_key"]
_PROMISE_RESOLVED = KediPromise.__dict__["_resolved"]
_PROMISE_VALUE = KediPromise.__dict__["_value"]
_SECRET_NAME = re.compile(
    r"password|passwd|passphrase|secret|token|credential|authorization|"
    r"apikey|accesskey|privatekey|signingkey|clientkey|cookie|"
    r"connectionstring|databaseurl|dsn"
)
_PRIVATE_FIELDS = {"key", "auth", "headers", "environ", "environment"}


def _namespace(cls: type) -> MappingProxyType:
    # Calling type's descriptors directly also bypasses hostile metaclasses.
    return _TYPE_DICT.__get__(cls)


def _mro(cls: type) -> tuple[type, ...]:
    return _TYPE_MRO.__get__(cls)


def _sensitive(name: str) -> bool:
    if len(name) > 512:
        return True
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    if is_token_metric_name(normalized):
        return False
    return normalized in _PRIVATE_FIELDS or _SECRET_NAME.search(normalized) is not None


def _model_storage(value: Any, bases: tuple[type, ...]) -> dict | None:
    for base in bases:
        descriptor = _namespace(base).get("__dict__", _MISSING)
        if descriptor is not _MISSING:
            if descriptor is not _MODEL_DICT:
                return None
            storage = object.__getattribute__(value, "__dict__")
            return storage if type(storage) is dict else None
    return None


def _promise_snapshot(value: KediPromise) -> tuple[str, Any]:
    try:
        capture_key = _PROMISE_KEY.__get__(value)
        if type(capture_key) is str and _sensitive(capture_key):
            return "redacted", _MISSING
        # resolve() publishes _value before _resolved. Prefer the value the
        # program actually reads, even if the source result was later mutated.
        if _PROMISE_RESOLVED.__get__(value) is True:
            return "complete", _PROMISE_VALUE.__get__(value)
        future = _PROMISE_FUTURE.__get__(value)
    except AttributeError:
        return "unknown", _MISSING
    if type(future) is not Future:
        return "unknown", _MISSING
    storage = object.__getattribute__(future, "__dict__")
    state = None
    exception = None
    result = _MISSING
    # No Future methods, locks, or lookups that could compare a
    # user key. FINISHED is published only after _result/_exception are stored.
    try:
        for index, (key, item) in enumerate(dict.items(storage)):
            if index >= 32:
                return "unknown", _MISSING
            if type(key) is str:
                if key == "_state":
                    state = item
                elif key == "_exception":
                    exception = item
                elif key == "_result":
                    result = item
    except RuntimeError:
        return "unknown", _MISSING
    if type(state) is not str:
        return "unknown", _MISSING
    if state in ("CANCELLED", "CANCELLED_AND_NOTIFIED"):
        return "cancelled", _MISSING
    if state == "FINISHED":
        if exception is not None:
            return "failed", _MISSING
        if capture_key is None:
            return "complete", result
        if type(capture_key) is str and type(result) is dict:
            try:
                for index, (name, item) in enumerate(dict.items(result)):
                    if index >= 4096:
                        break
                    if type(name) is str and name == capture_key:
                        return "complete", item
            except RuntimeError:
                pass
        return "complete", _MISSING
    return ("pending" if state in ("PENDING", "RUNNING") else "unknown"), _MISSING


class Snapshot:
    """Capture detached JSON trees, sharing limits across roots at one stop.

    Depth starts at zero. ``max_items`` counts every node, including roots;
    ``max_string`` bounds each displayed string; ``max_bytes`` bounds the sum
    of default ``json.dumps`` encodings of returned roots (ASCII escaping).
    A new root that cannot fit raises ``SnapshotLimitError``. Truncated trees
    mark the containing node instead of allocating an unbudgeted marker child.

    Returned dictionaries belong to the caller. They are immutable with respect
    to live program changes, not Python read-only containers. This object keeps
    only limits, counters, and bounded environment secret strings, never values
    or returned nodes. Create one instance per stop, on the capturing thread.
    Arbitrary undiscovered sensitive text cannot be detected automatically.
    """

    def __init__(
        self,
        *,
        max_depth: int = 4,
        max_items: int = 100,
        max_string: int = 1024,
        max_bytes: int = 65536,
    ) -> None:
        for name, value, minimum, maximum in (
            ("max_depth", max_depth, 0, 32),
            ("max_items", max_items, 1, 10000),
            ("max_string", max_string, 32, 16384),
            ("max_bytes", max_bytes, 128, 4194304),
        ):
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
        self._max_depth = max_depth
        self._max_string = max_string
        self._items_left = max_items
        self._bytes_left = max_bytes
        self._hide_text = False
        secrets = self._read_secrets()
        self._lookahead = max((len(secret) for secret in secrets), default=0)
        self._secret_pattern = (
            re.compile("(?=(" + "|".join(re.escape(secret) for secret in secrets) + "))")
            if secrets
            else None
        )

    def _read_secrets(self) -> tuple[str, ...]:
        secrets: set[str] = set()
        size = 0
        # The process environment is trusted infrastructure, not an inspected
        # Mapping. A replaced environment is not traversed.
        if type(os.environ) is not os._Environ:
            self._hide_text = True
            return ()
        storage = object.__getattribute__(os.environ, "_data")
        if type(storage) is not dict:
            self._hide_text = True
            return ()
        # _Environ.items() snapshots every key before yielding; raw storage keeps
        # this scan bounded too. Decode only bounded, exact builtin strings.
        try:
            for index, (key, value) in enumerate(dict.items(storage)):
                if index >= 4096 or not (type(key) is str or type(key) is bytes):
                    self._hide_text = True
                    break
                name = os.fsdecode(key) if len(key) <= 512 else "secret"
                if not _sensitive(name):
                    continue
                if not (type(value) is str or type(value) is bytes) or len(value) > 32768:
                    self._hide_text = True
                    break
                secret = os.fsdecode(value)
                if not secret:
                    continue
                size += len(secret)
                if len(secret) > 8192 or size > 65536 or len(secrets) >= 256:
                    self._hide_text = True
                    break
                secrets.add(secret)
        except RuntimeError:
            self._hide_text = True
        return tuple(sorted(secrets, key=len, reverse=True))

    def _secret_spans(
        self, text: str, *, merge_adjacent: bool = False
    ) -> Iterator[tuple[int, int]]:
        if self._secret_pattern is None:
            return
        start = end = 0
        for match in self._secret_pattern.finditer(text):
            position = match.start()
            if position > end or (position == end and not merge_adjacent):
                if end > start:
                    yield start, end
                start = position
            end = max(end, position + len(match[1]))
        if end > start:
            yield start, end

    def _text(self, value: str) -> str:
        if self._hide_text:
            return _REDACTED
        # Look past the visible prefix so truncation cannot expose half a secret.
        text = value[: self._max_string + self._lookahead]
        if self._secret_pattern is not None:
            parts: list[str] = []
            offset = 0
            for start, end in self._secret_spans(text):
                parts.extend((text[offset:start], _REDACTED))
                offset = end
            parts.append(text[offset:])
            text = "".join(parts)
        # Lone surrogates must also survive IPC writers using ensure_ascii=False.
        text = text.encode("utf-8", errors="backslashreplace").decode("utf-8")
        if len(value) > self._max_string or len(text) > self._max_string:
            return text[: self._max_string - len(_TRUNCATED)] + _TRUNCATED
        return text

    def redact_text(self, text: str) -> str:
        """Return a secret-redacted preview bounded by max_string, outside the node budget."""
        if type(text) is not str:
            raise TypeError("Snapshot text must be an exact string")
        return self._text(text)

    def mask_source(self, text: str) -> str:
        """Mask known secrets without changing character positions or CR/LF.

        The source caller must bound input to 2 MiB. This full-source operation
        neither truncates to max_string nor spends the captured-node budget.
        """
        if type(text) is not str:
            raise TypeError("Snapshot source must be an exact string")
        if self._hide_text:
            return _SOURCE_CHARACTERS.sub("*", text)
        if self._secret_pattern is None:
            return text

        # Merge overlapping matches against the original source, so masking one
        # credential cannot conceal another match and leave its suffix exposed.
        parts: list[str] = []
        offset = 0
        for start, end in self._secret_spans(text, merge_adjacent=True):
            parts.extend((text[offset:start], _SOURCE_CHARACTERS.sub("*", text[start:end])))
            offset = end
        parts.append(text[offset:])
        return "".join(parts)

    def _type_name(self, cls: type) -> str:
        name = _TYPE_NAME.__get__(cls)
        return self._text(name) if type(name) is str else "object"

    def _scalar(self, value: Any) -> str:
        cls = type(value)
        if cls is str:
            return self._text(value)
        if cls is bytes or cls is bytearray:
            prefix = value[: (self._max_string + self._lookahead) * 4]
            text = bytes(prefix).decode("utf-8", errors="surrogateescape")
            result = self._text(text)
            if len(value) > len(prefix):
                result = result[: self._max_string - len(_TRUNCATED)] + _TRUNCATED
            return result
        if cls is int:
            bits = int.bit_length(value)
            if bits > min(self._max_string, 640) * 3:
                return self._text(f"<int: {bits} bits; truncated>")
            return self._text(str(value))
        if cls is bool or cls is float or value is None:
            return self._text(repr(value))
        return self._text(f"<opaque {self._type_name(cls)} at 0x{id(value):x}>")

    def _key(self, key: Any) -> tuple[str, bool]:
        cls = type(key)
        if cls is str:
            return self._text(key), _sensitive(key)
        if cls is bytes:
            return self._scalar(key), len(key) > 512 or _sensitive(key.decode("utf-8", "replace"))
        return self._scalar(key), False

    def capture(self, name: str, value: Any) -> SnapshotNode:
        """Read only audited storage; never resolve, evaluate, or serialize value."""
        if type(name) is not str:
            raise TypeError("Snapshot names must be exact strings")
        return self._capture(self._text(name), value, _sensitive(name), 0, set())

    def _node(self, name: str, value: str, kind: str) -> SnapshotNode:
        if self._items_left == 0:
            raise SnapshotLimitError("Snapshot item budget exhausted")
        node: SnapshotNode = {"name": name, "value": value, "type": kind}
        # Reserve both a truncation suffix and children-list punctuation up front.
        # This makes the budget independent of the serializer's Unicode escaping.
        cost = len(json.dumps(node, ensure_ascii=True)) + _TRUNCATION_RESERVE + 18
        if cost > self._bytes_left:
            node = {"name": "", "value": "<truncated: budget>", "type": ""}
            cost = len(json.dumps(node)) + _TRUNCATION_RESERVE + 18
            if cost > self._bytes_left:
                raise SnapshotLimitError("Snapshot byte budget exhausted")
        self._bytes_left -= cost
        self._items_left -= 1
        return node

    def _truncate(self, node: SnapshotNode, reason: str) -> None:
        suffix = f" <truncated: {reason}>"
        node["value"] = node["value"][: self._max_string - len(suffix)] + suffix

    def _capture(
        self, name: str, value: Any, sensitive: bool, depth: int, active: set[int]
    ) -> SnapshotNode:
        cls = type(value)
        kind = self._type_name(cls)
        if sensitive:
            return self._node(name, _REDACTED, kind)
        if id(value) in active:
            return self._node(name, "<cycle>", kind)
        if cls is KediPromise:
            state, result = _promise_snapshot(value)
            if state == "redacted":
                return self._node(name, _REDACTED, kind)
            if result is _MISSING or depth >= self._max_depth:
                return self._node(name, f"<promise: {state}>", kind)
            active.add(id(value))
            try:
                return self._capture(name, result, sensitive, depth + 1, active)
            finally:
                active.remove(id(value))

        storage = None
        size = 0
        iterator: Iterator | None = None
        if cls is dict or cls is ScopeFrame or cls is KediEnv:
            storage = value
        elif any(cls is container for container in (list, tuple, set, frozenset)):
            size = len(value)
            iterator = enumerate(value)
        else:
            bases = _mro(cls)
            if len(bases) <= 64 and any(base is BaseModel for base in bases):
                storage = _model_storage(value, bases)
        if storage is not None:
            size = dict.__len__(storage)
            iterator = iter(dict.items(storage))
        if iterator is None:
            return self._node(name, self._scalar(value), kind)

        node = self._node(name, self._text(f"{kind} ({size} items)"), kind)
        if node["value"] == "<truncated: budget>":
            return node
        if not size:
            node["children"] = []
            return node
        if depth >= self._max_depth:
            self._truncate(node, "depth")
            return node
        children: list[SnapshotNode] = []
        node["children"] = children
        active.add(id(value))
        try:
            for index in range(size):
                if self._items_left == 0:
                    self._truncate(node, "items")
                    break
                try:
                    key, child = next(iterator)
                except (RuntimeError, StopIteration):
                    self._truncate(node, "changed")
                    break
                if storage is not None and type(key) is str and key == "__builtins__":
                    continue
                child_name, child_sensitive = (
                    self._key(key) if storage is not None else (str(index), False)
                )
                # A large earlier value must not consume every later binding's slot.
                reserved_items = min(size - index - 1, max(0, self._items_left - 1))
                reserved_bytes = min(reserved_items * 128, max(0, self._bytes_left - 256))
                self._items_left -= reserved_items
                self._bytes_left -= reserved_bytes
                try:
                    children.append(
                        self._capture(child_name, child, child_sensitive, depth + 1, active)
                    )
                except SnapshotLimitError:
                    self._truncate(node, "budget")
                    break
                finally:
                    self._items_left += reserved_items
                    self._bytes_left += reserved_bytes
        finally:
            active.remove(id(value))
        return node

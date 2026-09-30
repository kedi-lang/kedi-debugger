"""Frozen source snapshots and conservative executable breakpoint locations."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCES = 64


def source_path(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("Source path must be a non-empty string without null bytes")
    if value.startswith("file:"):
        parsed = urlparse(value)
        if parsed.netloc not in ("", "localhost"):
            raise ValueError("Only local file URIs are supported")
        value = unquote(parsed.path)
        if len(value) > 2 and value[0] == "/" and value[2] == ":":
            value = value[1:]
    return str(Path(value).resolve())


class Sources:
    def __init__(self) -> None:
        self.text: dict[str, str] = {}
        self.lines: dict[str, set[int]] = {}

    def load(self, path: str) -> str:
        path = source_path(path)
        if path in self.text:
            self._verify(path)
            return path
        if len(self.text) >= MAX_SOURCES:
            raise ValueError("Debug session source limit reached (64 files)")
        return self.register(path, self._read(path))

    @staticmethod
    def _read(path: str) -> str:
        file = Path(path)
        if file.suffix != ".kedi":
            raise ValueError("Debug sources must be .kedi files no larger than 2 MiB")
        with file.open("rb") as stream:
            data = stream.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            raise ValueError("Debug sources must be .kedi files no larger than 2 MiB")
        # Match Path.read_text's universal newlines used by the runtime compiler.
        return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")

    def register(self, path: str, text: str) -> str:
        """Register the actual compiled document without replacing a frozen source."""
        from kedi.lang import parse_program
        from kedi.lang.ast import (
            ConditionalLoopStmt,
            IfStmt,
            LoopStmt,
            ModuleImport,
            ProcDefStmt,
            ProcedureDef,
            Stmt,
            TaskGroupStmt,
            TypeDef,
        )

        path = source_path(path)
        if type(text) is not str:
            raise TypeError("Debug source text must be an exact string")
        if (
            Path(path).suffix != ".kedi"
            or len(text) > MAX_SOURCE_BYTES
            or len(text.encode("utf-8")) > MAX_SOURCE_BYTES
        ):
            raise ValueError("Debug sources must be .kedi files no larger than 2 MiB")
        if path in self.text:
            if self.text[path] != text:
                raise ValueError("Debug source changed; restart required")
            return path
        if len(self.text) >= MAX_SOURCES:
            raise ValueError("Debug session source limit reached (64 files)")
        program = parse_program(text, source_path=path)
        lines: set[int] = set()
        if program.prelude is not None and program.prelude_loc is not None:
            lines.add(program.prelude_loc.start_line)
        pending: list[Any] = list(program.imports)
        pending.extend(program.ordered_toplevel or program.toplevel_body)
        if program.toplevel_return is not None:
            pending.append(program.toplevel_return)
        # Only descend into blocks reached by the statement executors, not
        # configuration metadata, Python text, or templates nested in tasks.
        while pending:
            node = pending.pop()
            if (
                isinstance(node, (Stmt, ModuleImport, ProcedureDef, TypeDef))
                and node.loc is not None
            ):
                lines.add(node.loc.start_line)
            if isinstance(node, ProcDefStmt):
                if node.proc is not None:
                    pending.append(node.proc)
            elif isinstance(node, ProcedureDef):
                if not node.auto_spec and not node.ai_prompt:
                    pending.extend(node.body)
            elif isinstance(node, IfStmt):
                pending.extend(node.body)
                pending.extend(node.else_body or [])
            elif isinstance(node, (LoopStmt, ConditionalLoopStmt)):
                pending.extend(node.body)
                if isinstance(node, LoopStmt):
                    pending.extend(node.map_body or [])
            elif isinstance(node, TaskGroupStmt):
                for arm in node.arms:
                    pending.extend(arm.body or [])
        self.text[path] = text
        self.lines[path] = lines
        return path

    def _verify(self, path: str) -> None:
        try:
            current = self._read(path)
        except (OSError, ValueError) as exc:
            raise ValueError("Debug source changed or is unavailable; restart required") from exc
        captured = self.text[path].replace("\r\n", "\n").replace("\r", "\n")
        if current != captured:
            raise ValueError("Debug source changed; restart required")

    def verify(self) -> None:
        """Require every registered on-disk document to match its compiled snapshot."""
        for path in self.text:
            self._verify(path)

    def content(self, path: str) -> str:
        from .inspection import Snapshot

        path = source_path(path)
        if path not in self.text:
            raise ValueError("Source was not loaded in this debug session")
        return Snapshot().mask_source(self.text[path])

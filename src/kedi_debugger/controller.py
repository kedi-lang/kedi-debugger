"""Cooperative lane control and detached, read-only DAP inspection."""

from __future__ import annotations

import ast
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kedi.debugging import DebugEvent

from .inspection import Snapshot, SnapshotLimitError
from .sources import Sources, source_path


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer greater than or equal to {minimum}")
    return value


@dataclass
class Lane:
    id: int
    name: str
    paused: bool = False
    pause_requested: bool = False
    step: str | None = None
    depth: int = 0
    frames: list[dict[str, Any]] = field(default_factory=list)
    handles: set[int] = field(default_factory=set)
    cursors: dict[int, Any] = field(default_factory=dict)
    observations: dict[str, dict[str, Any]] = field(default_factory=dict)
    previous: dict[str, Any] | None = None
    exception: dict[str, Any] | None = None
    waiting: str | None = None
    progress_id: str | None = None
    last_span: Any = None


class Controller:
    def __init__(self, config: dict[str, Any], send: Callable[[dict[str, Any]], None]):
        self.config = config
        self.send = send
        client = config.get("__initialize", {})
        self.line_offset = 0 if client.get("linesStartAt1", True) else 1
        self.column_offset = 0 if client.get("columnsStartAt1", True) else 1
        self.uri_paths = client.get("pathFormat") == "uri"
        self.progress_reporting = bool(client.get("supportsProgressReporting", False))
        self._next_progress = 1
        self.sources = Sources()
        self.sources.load(config["program"])
        self.condition = threading.Condition(threading.RLock())
        self.lanes: dict[int, Lane] = {}
        self.breakpoints: dict[str, set[int]] = {}
        self.filters: set[str] = {"exceptions"}
        self.entry = bool(config.get("stopOnEntry", True))
        self.finished = False
        self.terminated = False
        self._next_handle = 1
        self._handles: dict[int, list[dict[str, Any]]] = {}
        self._frames: dict[int, tuple[Lane, list[dict[str, Any]]]] = {}

    def emit(self, event: str, **body: Any) -> None:
        self.send({"type": "event", "event": event, "body": body})

    def _lane(self) -> Lane:
        identity = threading.get_ident()
        if identity not in self.lanes:
            if len(self.lanes) >= 128:
                raise RuntimeError("Debugger lane limit reached (128); restart the session")
            lane = Lane(len(self.lanes) + 1, threading.current_thread().name)
            self.lanes[identity] = lane
            self.emit("thread", reason="started", threadId=lane.id)
        return self.lanes[identity]

    def _thread(self, identifier: Any) -> Lane:
        identifier = _integer(identifier, "threadId", minimum=1)
        for lane in self.lanes.values():
            if lane.id == identifier:
                return lane
        raise ValueError("Unknown execution lane")

    def _source(self, span: Any) -> dict[str, Any] | None:
        if span is None or span.source_path is None:
            return None
        path = source_path(span.source_path)
        return {"name": Path(path).name, "path": Path(path).as_uri() if self.uri_paths else path}

    def __call__(self, event: DebugEvent) -> None:
        with self.condition:
            if self.terminated:
                raise SystemExit("Debugger terminated")
            if event.kind == "source_loaded":
                source_map = event.runtime._source_map
                if source_map is not None:
                    for document in source_map.documents:
                        if document.path is not None:
                            self.sources.register(str(document.path), document.text)
                return
            lane = self._lane()
            if event.kind == "waiting":
                self._end_wait(lane)
                lane.waiting = "Waiting for a capture"
                if self.progress_reporting:
                    lane.progress_id = f"capture-{self._next_progress}"
                    self._next_progress += 1
                    self.emit("progressStart", progressId=lane.progress_id, title=lane.waiting)
                return
            if event.kind == "wait_complete":
                self._end_wait(lane)
                return
            if event.kind == "frame_exit":
                if event.frames:
                    lane.cursors.pop(id(event.frames[-1]), None)
                return
            if event.kind == "execution_complete":
                self._end_wait(lane)
                self._snapshot(lane, event)
                return
            if event.span is not None:
                lane.last_span = event.span
            if event.frames and event.span is not None:
                lane.cursors[id(event.frames[-1])] = event.span
            if event.kind in ("request", "model_input", "model_result", "usage"):
                lane.observations[event.kind] = dict(
                    Snapshot(max_bytes=16384).capture(event.kind, event.payload)
                )
            if not event.safe:
                return
            depth = len(event.frames)
            reason = None
            if event.kind == "statement":
                source = self._source(event.span)
                path = source_path(source["path"]) if source else ""
                if event.span is not None and event.span.start_line in self.breakpoints.get(
                    path, set()
                ):
                    reason = "breakpoint"
                elif self.entry:
                    reason = "entry"
                    self.entry = False
            if lane.pause_requested:
                reason = reason or "pause"
            if lane.step is not None and event.kind == "statement":
                if (
                    lane.step == "stepIn"
                    or (lane.step == "next" and depth <= lane.depth)
                    or (lane.step == "stepOut" and depth < lane.depth)
                ):
                    reason = reason or "step"
            if event.kind == "exception" and "exceptions" in self.filters:
                reason = "exception"
            if event.kind in self.filters:
                reason = reason or "breakpoint"
            if reason is None:
                return
            self.entry = False
            lane.pause_requested = False
            lane.step = None
            lane.depth = depth
            self._snapshot(lane, event)
            lane.paused = True
            self.emit(
                "stopped",
                reason=reason,
                description=event.kind,
                threadId=lane.id,
                allThreadsStopped=False,
            )
            while lane.paused and not self.terminated:
                self.condition.wait()
            if self.terminated:
                raise SystemExit("Debugger terminated")

    def _invalidate(self, lane: Lane) -> None:
        for handle in lane.handles:
            self._handles.pop(handle, None)
            self._frames.pop(handle, None)
        lane.handles.clear()
        lane.frames.clear()

    def _handle(self, lane: Lane, children: list[dict[str, Any]]) -> int:
        handle = self._next_handle
        self._next_handle += 1
        self._handles[handle] = children
        lane.handles.add(handle)
        return handle

    def _variable(self, lane: Lane, node: dict[str, Any]) -> dict[str, Any]:
        children = node.get("children", [])
        result = {key: node[key] for key in ("name", "value", "type")}
        result["variablesReference"] = (
            self._handle(lane, [self._variable(lane, c) for c in children]) if children else 0
        )
        return result

    def _snapshot(self, lane: Lane, event: DebugEvent) -> None:
        self._invalidate(lane)
        remaining_bytes = 65536

        def capture(name: str, value: Any) -> dict[str, Any]:
            nonlocal remaining_bytes
            try:
                if remaining_bytes < 128:
                    raise SnapshotLimitError("Snapshot byte budget exhausted")
                node = dict(Snapshot(max_bytes=min(8192, remaining_bytes)).capture(name, value))
                remaining_bytes -= len(json.dumps(node))
                return node
            except SnapshotLimitError:
                return {"name": name, "value": "<snapshot budget exhausted>", "type": "truncated"}

        frames = list(event.frames)
        if not frames:
            from kedi.debugging import DebugFrame

            frames = [DebugFrame("<program>", event.runtime, event.env, event.span)]
        for index, frame in enumerate(reversed(frames[-32:])):
            span = (
                (event.span or lane.last_span)
                if index == 0
                else lane.cursors.get(id(frame), frame.span)
            )
            env = event.env if index == 0 else frame.env
            local = capture("Locals", env)
            nodes = [local]
            from kedi.lang.compiler.environment import ScopeFrame

            scope = env
            seen = {id(scope)}
            for level in range(8):
                if type(scope) is not ScopeFrame:
                    break
                storage = object.__getattribute__(scope, "__dict__")
                parent = None
                for offset, (key, value) in enumerate(dict.items(storage)):
                    if offset >= 32:
                        break
                    if type(key) is str and key == "parent":
                        parent = value
                        break
                if parent is None or id(parent) in seen or parent is frame.runtime._globals_env:
                    break
                seen.add(id(parent))
                nodes.append(capture(f"Closure {level + 1}", parent))
                scope = parent
            nodes.append(capture("Globals", frame.runtime._globals_env))
            if index == 0:
                nodes.append(capture("Python", frame.runtime._prelude_env))
            if index == 0:
                nodes.extend(lane.observations.values())
                if lane.previous is not None:
                    before = {n["name"]: n for n in lane.previous.get("children", [])}
                    changes = [n for n in local.get("children", []) if before.get(n["name"]) != n]
                    nodes.append(
                        {
                            "name": "Changes",
                            "value": "Captured values only",
                            "type": "snapshot",
                            "children": changes,
                        }
                    )
                lane.previous = local
            scopes = []
            for node in nodes:
                children = node.get("children")
                if children is None:
                    children = [{**node, "name": "value"}]
                elif "<truncated:" in node["value"]:
                    # DAP scopes hide the root value; retain its limit notice.
                    children = [
                        *children,
                        {"name": "<snapshot>", "value": node["value"], "type": "truncated"},
                    ]
                scopes.append(
                    {
                        "name": node["name"],
                        "variablesReference": self._handle(
                            lane, [self._variable(lane, child) for child in children]
                        ),
                        "expensive": False,
                    }
                )
            frame_id = self._handle(lane, [])
            self._frames[frame_id] = (lane, scopes)
            dap_frame: dict[str, Any] = {
                "id": frame_id,
                "name": frame.name,
                "line": max(1, span.start_line if span else 1) - self.line_offset,
                "column": max(1, span.start_col if span else 1) - self.column_offset,
            }
            source = self._source(span)
            if source is not None:
                dap_frame["source"] = source
            lane.frames.append(dap_frame)
        if event.kind != "execution_complete":
            lane.exception = None
        if event.kind == "exception":
            node = capture("arguments", BaseException.__dict__["args"].__get__(event.payload))
            lane.exception = {
                "exceptionId": Snapshot().capture("exception", event.payload)["type"],
                "breakMode": "always",
                "description": node["value"],
            }

    def request(
        self,
        command: str,
        args: dict[str, Any],
        *,
        acknowledge: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        with self.condition:
            if command == "setBreakpoints":
                path = self.sources.load(args["source"]["path"])
                selected: set[int] = set()
                result = []
                for bp in args.get("breakpoints", []):
                    line = (
                        _integer(bp["line"], "line", minimum=1 - self.line_offset)
                        + self.line_offset
                    )
                    valid = line in self.sources.lines[path] and not any(
                        bp.get(k) for k in ("condition", "hitCondition", "logMessage")
                    )
                    if valid:
                        selected.add(line)
                    result.append(
                        {
                            "verified": valid,
                            "line": line - self.line_offset,
                            "message": ""
                            if valid
                            else "No executable Kedi statement here, or unsupported breakpoint condition",
                        }
                    )
                self.breakpoints[path] = selected
                return {"breakpoints": result}
            if command == "setExceptionBreakpoints":
                filters = set(args.get("filters", []))
                if filters - {"exceptions", "model_input", "model_result"}:
                    raise ValueError("Unknown Kedi exception/event filter")
                self.filters = filters
                return {}
            if command == "threads":
                return {
                    "threads": [
                        {"id": lane.id, "name": lane.name}
                        for lane in self.lanes.values()
                        if not self.finished
                    ]
                }
            if command == "stackTrace":
                lane = self._thread(args["threadId"])
                if not lane.paused and not self.finished:
                    raise ValueError("Lane is not stopped")
                start = _integer(args.get("startFrame", 0), "startFrame")
                levels = _integer(args.get("levels", 0), "levels") or len(lane.frames)
                return {
                    "stackFrames": lane.frames[start : start + levels],
                    "totalFrames": len(lane.frames),
                }
            if command == "scopes":
                item = self._frames.get(_integer(args["frameId"], "frameId", minimum=1))
                if item is None:
                    raise ValueError("Expired or unknown frame")
                return {"scopes": item[1]}
            if command == "variables":
                values = self._handles.get(
                    _integer(args["variablesReference"], "variablesReference", minimum=1)
                )
                if values is None:
                    raise ValueError("Expired or unknown variable reference")
                start = _integer(args.get("start", 0), "start")
                count = _integer(args.get("count", 0), "count") or len(values)
                return {"variables": values[start : start + count]}
            if command == "source":
                return {
                    "content": self.sources.content(args["source"]["path"]),
                    "mimeType": "text/x-kedi",
                }
            if command == "evaluate":
                return self._evaluate(args)
            if command == "exceptionInfo":
                lane = self._thread(args["threadId"])
                if lane.exception is None:
                    raise ValueError("No exception at this stop")
                return lane.exception
            if command in ("continue", "next", "stepIn", "stepOut", "pause"):
                if type(args.get("singleThread", False)) is not bool:
                    raise ValueError("singleThread must be a boolean")
                if self.finished:
                    raise ValueError("Execution has finished")
                lane = self._thread(args["threadId"])
                if command == "pause":
                    if acknowledge is not None:
                        acknowledge({})
                    lane.pause_requested = not lane.paused
                    return {}
                if not lane.paused:
                    raise ValueError("Lane is not stopped")
                try:
                    self.sources.verify()
                except ValueError as exc:
                    self.emit("output", category="console", output=f"{exc}\n")
                    raise
                targets = [lane]
                if not args.get("singleThread", False):
                    targets = [other for other in self.lanes.values() if other.paused]
                all_continued = not args.get("singleThread", False)
                body = {"allThreadsContinued": all_continued} if command == "continue" else {}
                # The wire response must precede events from newly runnable lanes.
                if acknowledge is not None:
                    acknowledge(body)
                for target in targets:
                    target.step = command if target is lane and command != "continue" else None
                    target.paused = False
                    self._invalidate(target)
                self.emit("continued", threadId=lane.id, allThreadsContinued=all_continued)
                self.condition.notify_all()
                return body
            raise ValueError(f"Unsupported debugger request: {command}")

    def _evaluate(self, args: dict[str, Any]) -> dict[str, Any]:
        expression = args.get("expression", "")
        if not isinstance(expression, str) or len(expression) > 256:
            raise ValueError("Only short read-only names and paths are supported")
        frame_id = args.get("frameId")
        item = self._frames.get(frame_id) if type(frame_id) is int else None
        if item is None:
            raise ValueError("Select a current stopped frame")
        path: list[str] = []
        node = ast.parse(expression, mode="eval").body
        while isinstance(node, (ast.Attribute, ast.Subscript)):
            if isinstance(node, ast.Attribute):
                path.append(node.attr)
            elif isinstance(node.slice, ast.Constant) and type(node.slice.value) in (str, int):
                path.append(str(node.slice.value))
            else:
                raise ValueError("Only literal indices are supported")
            node = node.value
        if not isinstance(node, ast.Name):
            raise ValueError("Evaluation cannot execute code")
        path.append(node.id)
        scopes = item[1]
        candidates = []
        for scope in scopes:
            if scope["name"] in ("Locals", "Globals", "Python") or scope["name"].startswith(
                "Closure "
            ):
                candidates.extend(self._handles.get(scope["variablesReference"], []))
        selected = None
        for index, name in enumerate(reversed(path)):
            matches = [value for value in candidates if value["name"] == name]
            if index and len(matches) > 1:
                raise ValueError("Ambiguous key in the snapshot; inspect variables directly")
            selected = matches[0] if matches else None
            if selected is None:
                raise ValueError("Value is not present in the bounded snapshot")
            candidates = self._handles.get(selected["variablesReference"], [])
        assert selected is not None
        return {
            "result": selected["value"],
            "type": selected["type"],
            "variablesReference": selected["variablesReference"],
        }

    def _end_wait(self, lane: Lane) -> None:
        lane.waiting = None
        if lane.progress_id is not None:
            self.emit("progressEnd", progressId=lane.progress_id)
            lane.progress_id = None

    def finish(self) -> None:
        with self.condition:
            if self.finished:
                return
            self.finished = True
            for lane in self.lanes.values():
                self._end_wait(lane)
                lane.paused = False
                lane.pause_requested = False
                lane.step = None
                self.emit("thread", reason="exited", threadId=lane.id)
            self.condition.notify_all()

    def close(self) -> None:
        with self.condition:
            self.terminated = True
            self.condition.notify_all()

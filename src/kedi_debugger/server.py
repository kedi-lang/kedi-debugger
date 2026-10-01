"""DAP supervisor; user code executes only in the owned worker process.

Private IPC uses the same framing as DAP, never pickle. The first worker request
is ``__launch`` with the original launch sequence, ``originalCommand: launch``,
and initialize arguments in ``arguments.__initialize``. The worker acknowledges
``__launch``; this supervisor then emits initialized. A configurationDone
response completes the held launch. Only this process assigns outgoing sequence
numbers; terminal events are deduplicated across runtime completion and crashes.
"""

from __future__ import annotations

import codecs
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, BinaryIO

from .environment import launch_environment
from .protocol import ProtocolError, cancel_windows_read, read_message, write_message
from .redaction import is_token_metric_name

__all__ = ["DebugAdapter", "validate_launch"]

CAPABILITIES = {
    "supportsConfigurationDoneRequest": True,
    "supportsTerminateRequest": True,
    "supportsEvaluateForHovers": True,
    "supportsExceptionInfoRequest": True,
    "supportsDelayedStackTraceLoading": True,
    "supportsSingleThreadExecutionRequests": True,
    "exceptionBreakpointFilters": [
        {"filter": "exceptions", "label": "Raised Kedi exception", "default": True},
        {"filter": "model_input", "label": "Model input ready", "default": False},
        {"filter": "model_result", "label": "Model result ready", "default": False},
    ],
}
_FORWARDED = frozenset(
    {
        "configurationDone",
        "setBreakpoints",
        "setExceptionBreakpoints",
        "threads",
        "stackTrace",
        "scopes",
        "variables",
        "source",
        "evaluate",
        "continue",
        "pause",
        "next",
        "stepIn",
        "stepOut",
        "exceptionInfo",
    }
)
_QUEUE_SIZE = 32
_OUTPUT_CHUNK = 4096
_START_TIMEOUT = 30.0
_STOP_TIMEOUT = 0.5


def validate_launch(arguments: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Normalize paths and validate process inputs without importing Kedi."""
    config = dict(arguments)
    for key in ("python", "pythonPath", "interpreter", "pythonExecutable"):
        if key in config:
            raise ValueError("Select the Python interpreter in the editor, not launch arguments")
    program = config.get("program")
    if not isinstance(program, str) or not program or "\0" in program:
        raise ValueError("program must name an existing .kedi file")
    cwd = config.get("cwd")
    if cwd is not None and (not isinstance(cwd, str) or not cwd or "\0" in cwd):
        raise ValueError("cwd must name an existing directory")
    try:
        directory = Path(cwd).expanduser().resolve() if cwd is not None else Path.cwd()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("cwd must name an existing directory") from exc
    if not directory.is_dir():
        raise ValueError("cwd must name an existing directory")
    try:
        path = (directory / Path(program).expanduser()).resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("program must name an existing .kedi file") from exc
    if path.suffix != ".kedi" or not path.is_file():
        raise ValueError("program must name an existing .kedi file")
    args = config.get("args", [])
    if not isinstance(args, list) or any(not isinstance(v, str) or "\0" in v for v in args):
        raise ValueError("args must be an array of strings without NUL characters")
    env = config.get("env", {})
    if not isinstance(env, dict) or any(
        not isinstance(k, str)
        or not k
        or "=" in k
        or "\0" in k
        or (v is not None and (not isinstance(v, str) or "\0" in v))
        for k, v in env.items()
    ):
        raise ValueError("env must map valid environment names to strings or null")
    if "stopOnEntry" in config and type(config["stopOnEntry"]) is not bool:
        raise ValueError("stopOnEntry must be a boolean")
    for key in ("adapter", "model"):
        if key in config and (not isinstance(config[key], str) or not config[key]):
            raise ValueError(f"{key} must be a nonempty string")
    config.update(program=str(path), cwd=str(directory if cwd is not None else path.parent))
    config["args"] = args
    return config, launch_environment(Path(config["cwd"]), env)


class _Redactor:
    """Retain a suffix so a secret split between stderr reads cannot escape."""

    def __init__(self, environments: list[dict[str, str]]) -> None:
        secrets: set[str] = set()
        size = 0
        self._hide_text = False
        for environment in environments:
            for name, value in environment.items():
                normalized = re.sub(r"[^a-z0-9]", "", name.lower())
                if (
                    not value
                    or is_token_metric_name(normalized)
                    or not re.search(
                        r"key|token|secret|password|passwd|passphrase|credential|auth|cookie|"
                        r"connectionstring|databaseurl|dsn",
                        normalized,
                    )
                ):
                    continue
                if value in secrets:
                    continue
                size += len(value)
                if len(value) > 8192 or size > 65536 or len(secrets) >= 256:
                    self._hide_text = True
                    break
                # Match the diagnostic decoder, including non-UTF-8 environment bytes.
                secrets.add(value.encode("utf-8", "surrogateescape").decode("utf-8", "replace"))
            if self._hide_text:
                secrets.clear()
                break
        self._pattern = (
            re.compile(
                "(?=("
                + "|".join(re.escape(value) for value in sorted(secrets, key=len, reverse=True))
                + "))"
            )
            if secrets
            else None
        )
        self._overlap = max((len(value) - 1 for value in secrets), default=0)
        self._prefixes: dict[str, list[str]] = {}
        for value in secrets:
            self._prefixes.setdefault(value[0], []).append(value)
        self._tail = ""
        self._masked = 0

    def feed(self, value: str, *, final: bool = False) -> str:
        if self._hide_text:
            return "[REDACTED]" if value else ""
        text = self._tail + value
        end = len(text)
        if not final:
            for start in range(max(0, end - self._overlap), end):
                candidates = self._prefixes.get(text[start], ())
                if candidates and any(
                    len(secret) > len(text) - start and secret.startswith(text[start:])
                    for secret in candidates
                ):
                    end = start
                    break
        parts: list[str] = []
        offset = self._masked
        if self._pattern:
            for match in self._pattern.finditer(text):
                if match.start() >= end:
                    break
                if match.start() >= offset:
                    parts.extend((text[offset : match.start()], "[REDACTED]"))
                offset = max(offset, match.start() + len(match[1]))
        parts.append(text[offset:end])
        # Retain original text for overlaps; do not emit a masked prefix twice.
        self._masked = max(0, offset - end)
        self._tail = text[end:]
        return "".join(parts)


class DebugAdapter:
    """Single-owner lifecycle state with bounded, independent pipe IO threads."""

    def __init__(self, reader: BinaryIO, writer: BinaryIO) -> None:
        self._reader = reader
        self._writer = writer
        self._events: queue.Queue[tuple[str, Any]] = queue.Queue(_QUEUE_SIZE)
        self._deferred: deque[tuple[str, Any]] = deque()
        self._outgoing: queue.Queue[dict[str, Any] | None] = queue.Queue(_QUEUE_SIZE)
        self._control: queue.Queue[dict[str, Any]] = queue.Queue(_QUEUE_SIZE)
        self._closed = threading.Event()
        self._worker_stopped = threading.Event()
        self._output_failed = threading.Event()
        self._send_lock = threading.Lock()
        self._seq = 0
        self._last_request = -1
        self._client: dict[str, Any] | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._worker_threads: list[threading.Thread] = []
        self._pending: dict[int, str] = {}
        self._ready = False
        self._configured = False
        self._exit_sent = False
        self._termination_sent = False
        self._progress_ids: set[str] = set()
        self._active_threads: set[int] = set()
        self._process_finished = False
        self._launch_seq: int | None = None
        self._launch_deadline = 0.0
        self._disconnect = False

    def _thread(self, target: Any, *args: Any) -> threading.Thread:
        thread = threading.Thread(target=target, args=args, daemon=True)
        thread.start()
        return thread

    def _put_event(self, kind: str, value: Any) -> None:
        while not self._closed.is_set():
            try:
                self._events.put((kind, value), timeout=0.05)
                return
            except queue.Full:
                continue

    def _read_messages(self, stream: BinaryIO, source: str) -> None:
        try:
            while not self._closed.is_set():
                message = read_message(stream)
                if message is None:
                    self._put_event(f"{source}_eof", None)
                    return
                self._put_event(source, message)
        except (OSError, ValueError) as exc:
            # ProtocolError contains only fixed diagnostics, not message contents.
            detail = str(exc) if isinstance(exc, ProtocolError) else "Protocol pipe closed"
            self._put_event(f"{source}_error", detail)

    def _write_client(self) -> None:
        try:
            while True:
                try:
                    message = self._outgoing.get(timeout=0.05)
                except queue.Empty:
                    if self._closed.is_set():
                        return
                    continue
                if message is None:
                    return
                write_message(self._writer, message)
        except (OSError, ValueError):
            self._output_failed.set()

    def _write_worker(self, stream: BinaryIO) -> None:
        try:
            while not self._worker_stopped.is_set():
                try:
                    message = self._control.get(timeout=0.05)
                except queue.Empty:
                    continue
                write_message(stream, message)
        except (OSError, ValueError):
            self._put_event("worker_error", "Worker control pipe closed")

    def _read_stderr(self, stream: BinaryIO, redactor: _Redactor) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        try:
            while chunk := stream.read(_OUTPUT_CHUNK):
                self._stderr_output(redactor.feed(decoder.decode(chunk)))
        except (OSError, ValueError):
            pass  # Closing an owned child also closes its diagnostic pipe.
        finally:
            self._stderr_output(redactor.feed(decoder.decode(b"", final=True), final=True))
            self._put_event("stderr_eof", None)

    def _stderr_output(self, text: str) -> None:
        for offset in range(0, len(text), _OUTPUT_CHUNK):
            self._put_event("stderr", text[offset : offset + _OUTPUT_CHUNK])

    def _send(self, message: dict[str, Any]) -> None:
        with self._send_lock:
            self._seq += 1
            try:
                self._outgoing.put({**message, "seq": self._seq}, timeout=0.05)
            except queue.Full as exc:
                raise OSError("Client is not consuming debugger output") from exc

    def _response(
        self, request: dict[str, Any], *, error: str | None = None, body: Any = None
    ) -> None:
        response = {
            "type": "response",
            "request_seq": request.get("seq", 0),
            "command": request.get("command", ""),
            "success": error is None,
        }
        if error is not None:
            response["message"] = error
        if body is not None:
            response["body"] = body
        self._send(response)

    def _request(self, request: dict[str, Any]) -> None:
        seq, command = request.get("seq"), request.get("command")
        if (
            request.get("type") != "request"
            or type(seq) is not int
            or seq < 0
            or not isinstance(command, str)
            or not command
        ):
            raise ProtocolError("Expected a DAP request with an integer seq and command")
        if seq <= self._last_request:
            self._response(request, error="Request sequence numbers must increase")
            return
        self._last_request = seq
        arguments = request.get("arguments", {})
        if not isinstance(arguments, dict):
            self._response(request, error="arguments must be an object")
            return
        if command == "initialize":
            if self._client is not None:
                self._response(request, error="Adapter is already initialized")
                return
            if arguments.get("pathFormat", "path") not in ("path", "uri"):
                self._response(request, error="pathFormat must be path or uri")
                return
            for key in ("linesStartAt1", "columnsStartAt1"):
                if key in arguments and type(arguments[key]) is not bool:
                    self._response(request, error=f"{key} must be a boolean")
                    return
            self._client = arguments
            self._response(request, body=CAPABILITIES)
        elif command in ("disconnect", "terminate"):
            for key in ("restart", "terminateDebuggee"):
                if key in arguments and type(arguments[key]) is not bool:
                    self._response(request, error=f"{key} must be a boolean")
                    return
            if arguments.get("terminateDebuggee") is False:
                self._response(request, error="Detach is not supported; terminate instead")
                return
            self._stop_worker()
            self._drain_worker()
            self._fail_pending("Debug session terminated")
            self._response(request)
            self._exit_events()
            self._disconnect = command == "disconnect"
        elif self._client is None:
            self._response(request, error="initialize must precede this request")
        elif command == "launch":
            self._launch(request, arguments)
        elif command not in _FORWARDED:
            self._response(request, error=f"Unsupported request: {command[:100]}")
        elif self._process is None or self._process_finished:
            self._response(request, error="No active debug session")
        elif not self._ready:
            self._response(request, error="Wait for the initialized event before configuration")
        elif command == "configurationDone" and (
            self._configured or "configurationDone" in self._pending.values()
        ):
            self._response(request, error="Configuration is already complete or pending")
        else:
            self._forward(request)

    def _launch(self, request: dict[str, Any], arguments: dict[str, Any]) -> None:
        if self._process is not None:
            self._response(request, error="Only one launch is supported per adapter session")
            return
        try:
            config, environment = validate_launch(arguments)
            config["__initialize"] = self._client
        except (OSError, ValueError) as exc:
            self._response(
                request, error=str(exc) if isinstance(exc, ValueError) else "Invalid launch paths"
            )
            return
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "kedi_debugger.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=config["cwd"],
                env=environment,
                bufsize=0,
                start_new_session=os.name != "nt",
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
        except (OSError, ValueError):
            self._response(request, error="Unable to start the selected Python")
            return
        self._process = process
        self._launch_deadline = time.monotonic() + _START_TIMEOUT
        assert (
            process.stdin is not None and process.stdout is not None and process.stderr is not None
        )
        self._worker_threads = [
            self._thread(self._read_messages, process.stdout, "worker"),
            self._thread(
                self._read_stderr, process.stderr, _Redactor([os.environ.copy(), environment])
            ),
            self._thread(self._write_worker, process.stdin),
        ]
        self._pending[request["seq"]] = "launch"
        self._launch_seq = request["seq"]
        self._control.put_nowait(
            {**request, "command": "__launch", "originalCommand": "launch", "arguments": config}
        )

    def _forward(self, request: dict[str, Any]) -> None:
        if len(self._pending) >= _QUEUE_SIZE:
            self._response(request, error="Too many pending worker requests")
            return
        # Queued controls are a subset of the bounded pending requests.
        self._control.put_nowait(request)
        self._pending[request["seq"]] = request["command"]

    def _worker_message(self, message: dict[str, Any]) -> None:
        if message.get("type") == "response":
            seq = message.get("request_seq")
            if type(seq) is not int:
                raise ProtocolError("Worker response must specify an integer request_seq")
            command = self._pending.get(seq)
            if command == "launch":
                if (
                    message.get("command") != "__launch"
                    or self._ready
                    or type(message.get("success")) is not bool
                ):
                    raise ProtocolError("Invalid worker launch acknowledgement")
                if not message["success"]:
                    del self._pending[seq]
                    self._send({**message, "command": "launch"})
                    self._worker_failure("Worker launch failed")
                    return
                self._ready = True
                self._send({"type": "event", "event": "initialized"})
                return
            if command is None or message.get("command") != command:
                raise ProtocolError("Worker response does not match a pending request")
            if type(message.get("success")) is not bool:
                raise ProtocolError("Worker response must specify success")
            del self._pending[seq]
            self._send(message)
            if command == "configurationDone" and message["success"]:
                self._configured = True
                if self._launch_seq in self._pending:
                    del self._pending[self._launch_seq]
                    self._response({"seq": self._launch_seq, "command": "launch"})
        elif message.get("type") == "event" and isinstance(message.get("event"), str):
            event = message["event"]
            if self._termination_sent:
                return
            body = message.get("body", {})
            if not isinstance(body, dict):
                raise ProtocolError("Worker event body must be an object")
            if event == "progressStart" and isinstance(body.get("progressId"), str):
                self._progress_ids.add(body["progressId"])
            elif event == "progressEnd" and isinstance(body.get("progressId"), str):
                self._progress_ids.discard(body.get("progressId"))
            elif event == "thread" and type(body.get("threadId")) is int:
                if body.get("reason") == "started":
                    self._active_threads.add(body["threadId"])
                elif body.get("reason") == "exited":
                    self._active_threads.discard(body["threadId"])
            if event == "exited":
                if self._exit_sent:
                    return
                self._finish_activity()
                self._exit_sent = True
            if event == "terminated":
                if self._termination_sent:
                    return
                self._finish_activity()
                self._termination_sent = True
            if event == "initialized":
                raise ProtocolError("Worker readiness requires a __launch response")
            self._send(message)
        else:
            raise ProtocolError("Worker sent an invalid response or event")

    def _fail_pending(self, message: str) -> None:
        pending, self._pending = self._pending, {}
        for seq, command in pending.items():
            self._response({"seq": seq, "command": command}, error=message)

    def _stop_worker(self) -> None:
        process = self._process
        if process is None or self._worker_stopped.is_set():
            return
        self._worker_stopped.set()
        if os.name == "nt":
            if process.poll() is None:
                try:
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2,
                        check=False,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
        else:
            # start_new_session makes the child's pid its owned process-group id.
            if process.stdin is not None:
                process.stdin.close()
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=_STOP_TIMEOUT)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_STOP_TIMEOUT)

    def _drain_worker(self) -> None:
        deadline = time.monotonic() + _STOP_TIMEOUT
        while time.monotonic() < deadline:
            try:
                kind, value = self._events.get(timeout=0.01)
            except queue.Empty:
                if not any(thread.is_alive() for thread in self._worker_threads):
                    break
                continue
            if kind == "stderr":
                self._send(
                    {
                        "type": "event",
                        "event": "output",
                        "body": {"category": "console", "output": value},
                    }
                )
            elif kind == "worker":
                try:
                    self._worker_message(value)
                except ProtocolError:
                    continue
            elif kind.startswith("client"):
                if len(self._deferred) >= _QUEUE_SIZE:
                    raise ProtocolError("Too many requests during worker shutdown")
                self._deferred.append((kind, value))

    def _finish_activity(self) -> None:
        for progress_id in sorted(self._progress_ids):
            self._send(
                {"type": "event", "event": "progressEnd", "body": {"progressId": progress_id}}
            )
        self._progress_ids.clear()
        for thread_id in sorted(self._active_threads):
            self._send(
                {
                    "type": "event",
                    "event": "thread",
                    "body": {"reason": "exited", "threadId": thread_id},
                }
            )
        self._active_threads.clear()

    def _exit_events(self) -> None:
        if self._process is None or self._process.returncode is None:
            return
        self._process_finished = True
        self._finish_activity()
        if not self._exit_sent:
            self._exit_sent = True
            self._send(
                {"type": "event", "event": "exited", "body": {"exitCode": self._process.returncode}}
            )
        if not self._termination_sent:
            self._termination_sent = True
            self._send({"type": "event", "event": "terminated"})

    def _worker_failure(self, detail: str) -> None:
        if not self._ready:
            detail += (
                f" Selected Python: {sys.executable}. Install a compatible Kedi build exposing "
                "kedi.debugging.observe_execution and DebugEvent in this interpreter; "
                "the Kedi version number alone does not guarantee debugger support. "
                "See the debug console for startup diagnostics."
            )
        self._stop_worker()
        self._drain_worker()
        self._fail_pending(detail)
        self._exit_events()

    def run(self) -> int:
        """Serve until disconnect, client EOF, or malformed client framing."""
        output_thread = self._thread(self._write_client)
        input_thread = self._thread(self._read_messages, self._reader, "client")
        status = 0
        value: Any
        try:
            while not self._disconnect and not self._output_failed.is_set():
                try:
                    kind, value = (
                        self._deferred.popleft()
                        if self._deferred
                        else self._events.get(timeout=0.05)
                    )
                except queue.Empty:
                    kind, value = "tick", ""
                if kind == "client_eof":
                    break
                if kind == "client_error":
                    status = 1
                    break
                if kind == "client":
                    assert isinstance(value, dict)
                    self._request(value)
                elif kind == "worker":
                    assert isinstance(value, dict)
                    try:
                        self._worker_message(value)
                    except ProtocolError as exc:
                        self._worker_failure(str(exc))
                elif kind == "stderr":
                    self._send(
                        {
                            "type": "event",
                            "event": "output",
                            "body": {"category": "console", "output": value},
                        }
                    )
                elif kind in ("worker_error", "worker_eof") and not self._process_finished:
                    self._worker_failure(
                        value or "Worker exited before completing pending requests"
                    )
                process = self._process
                if process is not None and not self._process_finished:
                    if process.poll() is not None:
                        self._worker_failure("Worker exited before completing pending requests")
                    elif not self._ready and time.monotonic() > self._launch_deadline:
                        self._worker_failure("Worker initialization timed out")
        except (OSError, ProtocolError, KeyboardInterrupt):
            status = 1
        finally:
            self._stop_worker()
            self._closed.set()
            if os.name == "nt":
                cancel_windows_read(input_thread, _STOP_TIMEOUT)
            for thread in self._worker_threads:
                thread.join(timeout=0.1)
            if self._process is not None:
                for stream in (self._process.stdin, self._process.stdout, self._process.stderr):
                    if stream is not None:
                        stream.close()
            try:
                self._outgoing.put(None, timeout=_STOP_TIMEOUT)
            except queue.Full:
                pass
            output_thread.join(timeout=_STOP_TIMEOUT)
        return status

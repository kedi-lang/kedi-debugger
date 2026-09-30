"""Owned debuggee: execute Kedi separately from the responsive DAP supervisor."""

from __future__ import annotations

import os
import io
import sys
import threading
from typing import Any

from .protocol import read_message, write_message


def main() -> None:
    # Reserve private protocol handles before importing or executing project code.
    reader = os.fdopen(os.dup(sys.stdin.fileno()), "rb", buffering=0)
    writer = os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0)
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(line_buffering=True, write_through=True)
    with open(os.devnull, "rb") as null:
        os.dup2(null.fileno(), sys.stdin.fileno())
    lock = threading.Lock()
    closing = False

    def send(message: dict[str, Any]) -> None:
        with lock:
            if not closing:
                write_message(writer, message)

    from kedi.debugging import observe_execution

    from .controller import Controller

    controller: Controller | None = None
    execution_thread: threading.Thread | None = None
    started = False

    def run(active: Controller) -> None:
        code = 1
        try:
            from kedi.app import run_program_cli
            from kedi.error_rendering import render_execution_error, render_parse_error
            from kedi.errors import KediExecutionError
            from kedi.lang.parser.diagnostics import KediParseError
            from kedi.utils import parse_args

            try:
                with observe_execution(active):
                    code, output = run_program_cli(
                        active.config["program"],
                        adapter=active.config.get("adapter")
                        or os.getenv("KEDI_ADAPTER", "pydantic"),
                        model=(
                            active.config.get("model")
                            or os.getenv("KEDI_ADAPTER_MODEL")
                            or os.getenv("MODEL_NAME")
                        ),
                        runtime_args=parse_args(active.config.get("args", [])),
                    )
                if output:
                    print(output, flush=True)
            except KediExecutionError as exc:
                print(render_execution_error(exc, use_color=False), file=sys.stderr, flush=True)
            except KediParseError as exc:
                print(render_parse_error(exc, use_color=False), file=sys.stderr, flush=True)
        except SystemExit as exc:
            if active.terminated or exc.code is None:
                code = 0
            elif isinstance(exc.code, int):
                code = int(exc.code)
            else:
                print(exc.code, file=sys.stderr, flush=True)
        except BaseException as exc:
            print(f"Kedi debuggee failed: {type(exc).__name__}", file=sys.stderr, flush=True)
        finally:
            active.finish()
            active.emit("exited", exitCode=code)
            active.emit("terminated")

    try:
        while (request := read_message(reader)) is not None:
            command = request.get("command", "")
            args = request.get("arguments", {})
            response: dict[str, Any] = {
                "type": "response",
                "request_seq": request.get("seq", 0),
                "command": command,
                "success": True,
            }
            start_after_response = False
            responded = False

            def acknowledge(body: dict[str, Any]) -> None:
                nonlocal responded
                send({**response, "body": body})
                responded = True

            try:
                if command == "__launch":
                    if controller is not None:
                        raise ValueError("A debuggee can only launch once")
                    controller = Controller(args, send)
                    body: dict[str, Any] = {}
                elif controller is None:
                    raise ValueError("Launch a program first")
                elif command == "configurationDone":
                    if started:
                        raise ValueError("Execution was already configured")
                    controller.sources.verify()
                    started = True
                    start_after_response = True
                    body = {}
                else:
                    body = controller.request(command, args, acknowledge=acknowledge)
                response["body"] = body
            except (ValueError, KeyError, TypeError, OSError, SyntaxError) as exc:
                response.update(success=False, message=str(exc)[:1024])
            if not responded:
                send(response)
            if start_after_response:
                assert controller is not None
                execution_thread = threading.Thread(
                    target=run, args=(controller,), name="Kedi main", daemon=True
                )
                execution_thread.start()
    finally:
        # Stop publishing before cancellation wakes a paused execution thread.
        with lock:
            closing = True
        if controller is not None:
            controller.close()
        if execution_thread is not None:
            execution_thread.join(timeout=0.05)
        reader.close()
        writer.close()


if __name__ == "__main__":
    main()

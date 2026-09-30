"""Resolve a debuggee's dotenv snapshot before starting or importing its runtime."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping


def launch_environment(cwd: Path, overrides: Mapping[str, str | None]) -> dict[str, str]:
    environment = os.environ.copy()
    removed = {name for name, value in overrides.items() if value is None}
    for name, value in overrides.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value

    if environment.get("PYTHON_DOTENV_DISABLED", "").casefold() not in {
        "1",
        "true",
        "t",
        "yes",
        "y",
    }:
        # Search from the debuggee, never from this installed package's location.
        for directory in (cwd, *cwd.parents):
            path = directory / ".env"
            if not path.exists():
                continue
            if not path.is_file():
                raise ValueError("Debug environment .env must be a regular file")
            try:
                from dotenv.parser import parse_stream
                from dotenv.variables import parse_variables
            except ImportError as exc:
                raise ValueError(
                    "Debug environment loading requires python-dotenv in the selected Python"
                ) from exc
            inherited = set(environment)
            try:
                with path.open(encoding="utf-8-sig") as stream:
                    for binding in parse_stream(stream):
                        if binding.error:
                            raise ValueError(
                                f"Invalid debug environment .env syntax at line {binding.original.line}"
                            )
                        name, value = binding.key, binding.value
                        if name is None or value is None or name in removed:
                            continue
                        value = "".join(
                            atom.resolve(environment) for atom in parse_variables(value)
                        )
                        if not name or "=" in name or "\0" in name or "\0" in value:
                            raise ValueError("Invalid debug environment .env entry")
                        if name not in inherited:
                            environment[name] = value
            except (OSError, UnicodeError) as exc:
                raise ValueError("Unable to read debug environment .env as UTF-8") from exc
            break

    # Kedi imports also call load_dotenv(). Do not rediscover a different file,
    # restore explicitly removed keys, or introduce secrets unknown to redaction.
    environment["PYTHON_DOTENV_DISABLED"] = "1"
    return environment

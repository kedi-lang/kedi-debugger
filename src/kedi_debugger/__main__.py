from __future__ import annotations

import argparse
import os
import sys

from .server import DebugAdapter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Kedi Debug Adapter Protocol backend")
    parser.add_argument("--stdio", action="store_true", required=True)
    parser.parse_args(argv)
    # Unbuffered duplicates avoid interpreter shutdown waiting on a blocked IO thread.
    with (
        os.fdopen(os.dup(sys.stdin.fileno()), "rb", buffering=0) as reader,
        os.fdopen(os.dup(sys.stdout.fileno()), "wb", buffering=0) as writer,
    ):
        return DebugAdapter(reader, writer).run()


if __name__ == "__main__":
    raise SystemExit(main())

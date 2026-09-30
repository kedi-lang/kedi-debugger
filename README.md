# Kedi Debugger

An optional, local Debug Adapter Protocol (DAP) backend shared by the Kedi VS Code
and Zed extensions. The protocol supervisor owns a separate Kedi worker process.
The normal runtime does not import this package or record debugger snapshots.

This package lives in [kedi-lang/kedi-debugger](https://github.com/kedi-lang/kedi-debugger)
and is pinned as the `debugger/` submodule in the Kedi repository. From an existing
Kedi checkout, initialize it with `git submodule update --init debugger`.

## Local Installation

The updated editor extensions automatically install this package in their shared
managed environment, including upgrades of existing managed installations. This
requires the matching runtime and debugger releases on the package index; source
changes do not publish those releases.

For local development or a selected host Python, use the same interpreter for
the editor, Kedi, debugger, and program dependencies:

```sh
python -m pip install -e /path/to/kedi
python -m pip install --no-deps -e /path/to/kedi/debugger
python -c 'import kedi_debugger; from kedi.debugging import DebugEvent, observe_execution'
```

This source checkout adds runtime hooks that older Kedi installations do not have.
The debugger and updated extensions have not been published automatically. A
missing package is an installation error, not a reason to select another Python.
Both extensions reuse the selected host interpreter or `~/.kedi/editor-venv`;
neither creates a second debugger environment or modifies a host environment.

The machine-facing entry point is `python -m kedi_debugger --stdio`.
`kedi debug --stdio` is an equivalent CLI bridge. Start the backend through an
editor, not an interactive terminal: stdin/stdout carry DAP frames.

## Launch Contract

```json
{
  "type": "kedi",
  "request": "launch",
  "name": "Debug Kedi",
  "program": "${file}",
  "cwd": "${workspaceFolder}",
  "args": [],
  "env": {},
  "stopOnEntry": true
}
```

`adapter` and `model` optionally select the existing CLI runtime defaults;
program/profile directives still follow normal Kedi rules. Before starting the
worker or importing Kedi, the debugger finds the nearest `.env` starting at
`cwd` and searching its parents. Without `cwd`, it starts at the program's
directory. It loads one file, not a merge of every parent file. API keys and
`KEDI_ADAPTER`, `KEDI_ADAPTER_MODEL`, and `MODEL_NAME` are available before model
selection, including when the editor was opened outside a terminal.

Launch `env` entries take priority over inherited environment variables, which
take priority over `.env` values. Strings override values; null removes a
variable even if `.env` defines it; an empty string remains an empty value.
Dotenv quoting, multiline values, and `${NAME}` interpolation are supported.
Explicit launch `adapter`/`model` fields take priority over environment defaults.
Missing `.env` files are optional; unreadable or invalid files fail launch without
printing their contents. The supervisor's own environment is never mutated.

Set `PYTHON_DOTENV_DISABLED=1` in the inherited environment or launch `env` to
skip dotenv discovery. After resolving the worker environment, the debugger sets
this flag for the worker to prevent later `load_dotenv()` calls from finding a
different file or restoring removed variables. Restart the debug session after
changing `.env`. Known credentials from the loaded file are masked in debugger
output and inspections. Keep credentials out of checked-in launch files.

The selected interpreter launches both supervisor and worker; launch arguments
cannot silently replace it.

## Execution Controls

- Breakpoints stop before executable Kedi statements. Unsupported locations and
  conditional/log/hit-count breakpoints are rejected, not silently relocated.
- Step into enters a Kedi procedure; next steps over it; step out reaches the
  next boundary after it returns. Embedded Python blocks are opaque units.
- Pause requests the next cooperative boundary. It cannot freeze an active
  network call or arbitrary Python instruction.
- Independent model jobs remain concurrent. A stop affects one lane and never
  claims that every thread stopped. Continue normally releases paused lanes;
  a single-thread request releases only the selected lane.
  Stepping also resumes paused peers by default so a capture can receive its
  result. Explicit single-thread stepping can wait for a paused producer; resume
  that producer separately when needed.
- Optional exception/event filters `model_input` and `model_result` expose the
  prepared model input before its conversation transaction and its returned
  result afterward. `exceptions` stops at raised Kedi execution boundaries.
- Request assembly is observation-only inside a conversation transaction. The
  `request` scope contains the actual assembled Kedi prompt/instructions/tool
  names, not an invented provider wire payload. Available usage is observed, not
  estimated. The `model_input` scope precedes request-transforming hooks.
  Nested synchronous tool execution is also observation-only while the model
  transaction owns its resources. A propagated tool failure can stop afterward,
  once the transaction has released them. Provider failures from parallel model
  jobs reach exception stops just like failures on the main lane.

Pausing does not suspend external deadlines, undo effects, replay a request, or
override tool approval. Interactive stdin and terminal approval prompts are not
supported in the DAP worker. Existing noninteractive approval policies continue
to apply; a denied tool is not automatically approved for debugging.

## Read-only Inspection

Native editor stack/scopes/variables show lexical locals, bounded closure scopes, globals, Python prelude
values, recent model observations, and changes in captured values. Completed
captures expose their already-published values, including typed fields, without
calling `resolve()` or waiting. Pending/failed/cancelled captures remain explicit.
Inspecting a result never makes another model or tool call. Unknown objects stay
opaque rather than running their repr, properties, serializers, or iterators.

Watch/evaluate accepts names and paths such as `answer`, `record.name`, and
`items[0]`, restricted to already captured values. It cannot run Python, call
functions, mutate state, or retrieve omitted/truncated values. Handles expire
when their lane resumes. After outstanding jobs drain, a bounded final snapshot stays in the process until
the editor disconnects; there is no persistent execution archive.

When distinct dictionary keys have the same display name (for example `1` and
`"1"`), watch evaluation rejects the ambiguous path instead of guessing. Inspect
the displayed variables directly in that case.

Snapshots bound items, depth, text length and encoded bytes. Limits and cycles
are visible, not represented as complete values. Sensitive field names and known
environment secrets are redacted, including source responses without shifting
their line positions. Arbitrary user text can still contain unknown
sensitive information; review before sharing screenshots or logs. There is no
Logfire dependency or telemetry exporter configured by the debugger.

Large containers cannot consume the slots reserved for later sibling bindings.
Each scope has a separate item budget within the bounded stop snapshot; empty
and scalar scopes have valid inspection references too. A truncated scope includes
a `<snapshot>` notice so omitted bindings are not mistaken for missing program
variables. Resolved promises display their memoized value, not a later replacement
in the shared model-result mapping.

## Restart and Run State

Use the editor's **Restart/Rerun** action after saving source or `.env` changes.
The adapter supports the DAP terminate/disconnect restart sequence: the editor
launches a fresh adapter and worker, with fresh configuration and breakpoints.
There is no in-place hot reload of an executing program. Attempting to continue
after a source edit leaves execution paused and explains the required restart
in the console.

Thread names stay stable. Running/stopped state comes from DAP control events,
not a cached suffix on the thread name. Clients supporting progress reporting
receive balanced capture-wait progress events; already-completed captures do
not report waiting. Completion ends outstanding progress and sends thread-exit
events before the program's exit code and session termination.

Statement stepping stops at the next eligible Kedi statement, not at each
internal model observation on the same line. Explicit model event breakpoints
continue to work. A statement is stopped **before** it executes, so a newly
assigned value becomes visible at the following stop. On normal completion,
editors may clear their Variables panel; inspect before continuing past the
last breakpoint when you need to retain the view.

## Boundaries

Launch trusted saved `.kedi` files only. There is no remote attach, hot reload,
reverse execution, arbitrary evaluate, Python-internal stepping, notebook/REPL
debugging, terminal input, or subagent-internal async stepping. Synchronous
observers on an asyncio loop are observation-only. Blocking unmanaged code may
need worker termination; that does not imply rollback or graceful cleanup of
remote services. Only the owned process group is terminated.

Source snapshots are frozen for the session. Changed sources are rejected before
configuration or resuming execution; restart to run an edited program. The actual
compiled source is checked too, including imported Kedi modules.

## Validation

The runtime integration tests live in the parent
[Kedi repository](https://github.com/kedi-lang/kedi/tree/stable/tests), not in
this package checkout. From that repository's development environment:

```sh
python -m pytest tests/test_debugging.py tests/test_debugger_*.py
```

These tests use deterministic adapters and actual DAP subprocesses. They do not
call Claude, other paid providers, or Terminal-Bench tasks. Editor extension
builds/tests are separate from these backend tests; installing/publishing the
extensions is a separate release step.

Protocol reference: [DAP overview](https://microsoft.github.io/debug-adapter-protocol/overview).

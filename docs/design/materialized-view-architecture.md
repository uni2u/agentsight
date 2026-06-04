# Materialized View Architecture

## Summary

AgentSight uses a live materialized view as the boundary between capture and
consumption.

```
Sources / analyzers                 View boundary                 Consumers
-------------------                 -------------                 ---------
SSL / process / stdio / system  ->  MaterializingAnalyzer             ->  FileLogger
HTTPParser / SSEProcessor       ->  MaterializedView            ->  SqliteSink
Proc + session sources              ViewUpdate stream               OTel
TimestampNormalizer / filters       in-memory query state           CLI/API
```

The important rule is that persistent outputs are derived from the view, not
from raw event storage. SQLite stores selected materialized tables. JSONL logs
store `ViewUpdate` records. Low-level `debug` commands can still print
runner/analyzer events to stdout, but file/API output stays on the ViewUpdate
path.

## Why

The old path had two kinds of complexity:

1. Raw events were written to SQLite first, then SQL adapters/projectors rebuilt
   the useful tables later.
2. Commands such as `stat`, `report`, and `top` duplicated merge logic for token
   totals, local sessions, tools, processes, and network targets.

That made SQLite a critical path dependency and made each command responsible
for knowing too much about storage internals.

The current design keeps the analyzer pipeline for single-stream transforms, but
makes the view the handoff point for everything downstream.

## Live Path

`build_trace_agent()` now always installs a `MaterializingAnalyzer` for `record` and
`trace`.

```
Runner event stream
  -> analyzer chain
  -> MaterializingAnalyzer
       -> normalize Event into CanonicalEvent
       -> ViewProjector produces ViewUpdate rows
       -> MaterializedView updates in-memory state
       -> ViewUpdateSink consumers are notified
```

The view currently materializes:

- `llm_calls`
- `token_usage`
- `audit_events`
- `tool_calls`
- `agent_sessions`
- `network_targets`
- `resource_samples`

This means a normal `record -o record.log` no longer writes every raw event. It
writes structured view updates such as:

```json
{"kind":"token_usage","row":{"model":"claude-sonnet-4","total_tokens":15}}
```

The actual row contains the full typed fields; the example is shortened.

## Consumer Boundary

Consumers implement `ViewUpdateSink`.

```rust
pub trait ViewUpdateSink: Send {
    fn update(&mut self, update: &ViewUpdate) -> ViewResult<()>;
}
```

Current consumers:

- `FileLogger`: writes view-update JSONL for `record`/`trace`/`debug`.
- `SqliteSink`: persists selected materialized view tables when `--db` is provided.
- `OtelExporter`: exports completed `llm_call` rows as GenAI spans.

## SQLite Role

SQLite is a materialized-view store, not raw event storage.

Removed tables:

- `raw_events`
- `canonical_events`
- `view_events`
- `adapter_runs`

Removed code:

- `framework/adapters/sql_adapter.rs`
- SQL adapter files under `collector/adapters/sql/`
- CLI flags for running adapters/projectors

Opening an old raw-event-only database now fails with a clear error asking the
user to re-import the JSONL capture.

## Restore And Import

There are two restore inputs:

1. View-update JSONL from current `record`/`trace` logs.
2. Legacy raw `Event` JSONL, kept for fixture and old-log compatibility.

`db import` tries `ViewUpdate` first. If a line is not a view update, it falls
back to the legacy `Event` parser and rebuilds view rows through
`MaterializedView`/`ViewProjector`.

`stat --db`, `report --db`, `top --db --once`, `prompts --db`, and
`db export` rebuild the in-memory view from SQLite with `sources::sqlite::load_view`,
then query the
`MaterializedView`. Command code does not reach through to `SqliteStore`
internals.

## API Role

- `/api/events` serves the configured JSONL log file. For `record`, `trace`, and
  `debug`, this is now view-update JSONL.
- `/api/v1/*` endpoints read SQLite materialized tables when a DB is configured.

## Command Flow

### record / trace

```
runners -> analyzers -> MaterializingAnalyzer/MaterializedView
                                |-> FileLogger(view JSONL)
                                |-> SqliteSink(--db)
                                |-> OtelExporter (--otel)
```

If `--db` is not provided, `MaterializingAnalyzer` still builds the same in-memory
view and emits the same view rows; no SQLite database is opened.

### top

Live `top` uses a `LiveView` that owns the previous `/proc` snapshot and sticky
session bindings. It does not require SQLite; CLI and TUI render from the
current materialized output instead of each maintaining their own live state.

### stat / report

When a DB is provided, commands rebuild a `MaterializedView` from SQLite and then
read through it. Without a DB, local agent session JSONL remains
available as a source for local-only summaries.

## Current Code Layout

```
collector/src/sources/
  proc.rs          /proc process/resource sampling source helpers
  session.rs       local Claude/Codex/Gemini/OpenClaw JSONL source helpers
  sqlite.rs        SQLite source that materializes DB rows into MaterializedView

collector/src/view/
  mod.rs           MaterializedView: in-memory aggregate/query state
  projector.rs     Event-to-ViewUpdate projection and pending request matching
  types.rs         owned query-facing rows, snapshots, and ViewUpdate contracts

collector/src/sinks/
  file_logger.rs   ViewUpdateSink for record/trace JSONL
  otel.rs          ViewUpdateSink for completed LLM calls
  sqlite.rs        ViewUpdateSink for SQLite persistence

collector/src/output/
  format.rs        CLI formatting and output structs
  tui.rs           live top TUI rendering

collector/src/framework/analyzers/
  materializing.rs MaterializingAnalyzer: event-stream analyzer that drives the view

collector/src/stores/
  sqlite.rs        SQLite row store

collector/src/cmd_trace.rs
  builds runners/analyzers and attaches view sinks

collector/src/cli_db.rs
  imports ViewUpdate JSONL or legacy raw Event JSONL
  reads MaterializedView snapshots for report/db commands
```

## Remaining Work

The raw SQL adapter layer is gone, default recording no longer persists raw
events, SQLite is split into source/sink boundary modules, row/update types are
owned by `view::types`, and live top has a `LiveView` state object.

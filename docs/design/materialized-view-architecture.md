# Materialized View Architecture

## Summary

AgentSight uses a live materialized view as the boundary between capture and
consumption.

```
Runners + analyzers                 Live view                         Consumers
-------------------                 ---------                         ---------
SSL / process / stdio / system  ->  StorageAnalyzer/ViewProjector  ->  FileLogger
HTTPParser / SSEProcessor           SQLite materialized tables    ->  SQLite DB
TimestampNormalizer / filters       ViewUpdate stream             ->  OTel
                                                                      CLI/API
```

The important rule is that persistent outputs are derived from the view, not
from raw event storage. SQLite stores selected materialized tables. JSONL logs
store `ViewUpdate` records. Raw event logging remains available only in low-level
`debug` commands where the user explicitly asks to inspect runner/analyzer
output.

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

`build_trace_agent()` now always installs a `StorageAnalyzer` for `record` and
`trace`.

```
Runner event stream
  -> analyzer chain
  -> StorageAnalyzer
       -> normalize Event into CanonicalEvent
       -> ViewProjector ingests CanonicalEvent
       -> materialized rows are written/updated
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
- `view_stats`

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
    fn llm_call(&mut self, _call: &LlmCallRow) {}
    fn token_usage(&mut self, _token: &TokenUsageRow) {}
    fn audit_event(&mut self, _audit: &AuditEventRow) {}
    fn tool_call(&mut self, _tool: &ToolCallRow) {}
    fn session(&mut self, _session: &SessionRow) {}
    fn network_target(&mut self, _target: &NetworkTargetRow) {}
    fn resource_sample(&mut self, _sample: &ResourceSampleRow) {}
}
```

Current consumers:

- `FileLogger`: writes view-update JSONL for `record`/`trace`.
- `SqliteStore`: persists materialized view tables when `--db` is provided.
- `OtelExporter`: exports completed `llm_call` rows as GenAI spans.

The same `FileLogger` type still implements `Analyzer` for debug subcommands,
but that is a raw diagnostic path, not the default recording path.

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
`StorageAnalyzer`/`ViewProjector`.

`stat --db`, `report --db`, `top --db --once`, `prompts --db`, and
`db export` read the materialized tables directly through `SqliteStore`.

## API Role

- `/api/events` serves the configured JSONL log file. For normal `record` and
  `trace`, this is now view-update JSONL.
- `/api/v1/*` endpoints read SQLite materialized tables when a DB is configured.

## Command Flow

### record / trace

```
runners -> analyzers -> StorageAnalyzer/ViewProjector
                                |-> FileLogger(view JSONL)
                                |-> SQLite materialized tables (--db)
                                |-> OtelExporter (--otel)
```

If `--db` is not provided, `StorageAnalyzer` uses an in-memory SQLite view so
FileLogger and OTel still consume the same view rows.

### top

Live `top` still uses the live process/session view in `cmd_perf.rs`; it does
not require SQLite. The architectural target is the same: maintain aggregate
state incrementally and render from that state rather than rescanning raw data
each frame.

### stat / report

When a DB is provided, commands read `SqliteStore::export_snapshot()` and query
materialized tables. Without a DB, local agent session JSONL remains available as
a source for local-only summaries.

## Current Code Layout

```
collector/src/framework/storage/
  analyzer.rs      StorageAnalyzer: event-stream analyzer that owns the view
  sqlite.rs        SqliteStore + ViewProjector + ViewUpdateSink rows

collector/src/framework/analyzers/
  file_logger.rs   raw Analyzer for debug, ViewUpdateSink for record/trace
  otel_exporter.rs ViewUpdateSink for completed LLM calls

collector/src/cmd_trace.rs
  builds runners/analyzers and attaches view sinks

collector/src/cli_db.rs
  imports ViewUpdate JSONL or legacy raw Event JSONL
  reads materialized snapshots for report/db commands
```

## Remaining Work

The raw SQL adapter layer is gone and default recording no longer persists raw
events. The remaining cleanup is command-level consolidation:

- move repeated local-session merge logic out of `cmd_perf.rs` and `cli_db.rs`;
- make live `top` and stored `stat/report` share the same query-facing view
  types;
- optionally split `SqliteStore` into source/sink modules once the command
  layer is thin enough to make that split useful.

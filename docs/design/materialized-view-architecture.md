# Materialized View Architecture

## Problem

The current data pipeline has three pain points:

1. **Duplicated merge logic.** `stat`, `report`, and `top` each build their own
   aggregated view by merging eBPF data, /proc samples, and local session JSONL.
   Token priority rules, model aggregation, and tool counting are reimplemented
   per command with inconsistent behavior.

2. **DB on the critical path.** SQLite sits between capture and display. The
   `record` command writes events to SQLite via adapters/projectors, then
   `stat`/`report` read them back. This adds complexity (schema drift, raw SQL
   in multiple files, adapter orchestration) without clear benefit — the same
   events already exist in the JSONL log file.

3. **Hard to program against.** External consumers must either parse JSONL or
   query SQLite internals. There is no stable Rust API for "give me the merged
   session view."

## Design

One in-memory materialized view, three source types feeding it, all consumers
reading from it.

```
Sources (push)             MaterializedView              Consumers (pull)
                        ┌───────────────────┐
EbpfSource  ──────────→ │                   │ ──→ TUI (top)
  ssl, process, stdio    │  tokens_by_model  │ ──→ CLI (stat, report)
                         │  processes        │ ──→ FileLogger (JSONL)
ProcSource  ──────────→ │  tools            │ ──→ SqliteSink (optional)
  cpu, rss, fd scan      │  sessions         │ ──→ HTTP API
                         │  prompts          │ ──→ OtelExporter
SessionSource ────────→ │  cost             │
  ~/.claude JSONL        │  ...              │
  ~/.codex JSONL         │                   │
                        └───────────────────┘
                                 ↑
                        can restore from DB or JSONL
```

### Source

A source produces a stream of typed events. Three implementations:

| Source | Reads from | Produces |
|--------|-----------|----------|
| `EbpfSource` | eBPF runners (via existing analyzer chain) | HTTP pairs, process exec/exit, token usage |
| `ProcSource` | /proc polling, /proc/\<pid\>/fd scanning | CPU%, RSS, session-path correlation |
| `SessionSource` | ~/.claude/\*, ~/.codex/\* JSONL files | Models, tokens, tools, prompt previews, cost |

The existing analyzer pipeline (HTTPParser, SSEProcessor, SSLFilter, etc.)
lives **inside** `EbpfSource`. Analyzers remain single-stream transforms —
unchanged from today. They are an implementation detail of one source, not a
global concept.

```rust
trait Source {
    fn stream(&self) -> EventStream;
    fn name(&self) -> &str;
}
```

### MaterializedView

A single struct that maintains aggregated state. Sources push events via
`ingest()`. Consumers read via query methods. All state lives in memory.

```rust
struct MaterializedView {
    tokens: BTreeMap<String, TokenCounter>,
    processes: BTreeMap<u32, ProcessInfo>,
    tools: BTreeMap<String, usize>,
    sessions: Vec<SessionInfo>,
    recent_events: RingBuffer<Event>,
    start_time: Instant,
    event_count: u64,
}

impl MaterializedView {
    // Write path — called by sources
    pub fn ingest(&mut self, event: &Event) { ... }

    // Read path — called by consumers
    pub fn summary(&self) -> Summary { ... }
    pub fn tokens_by_model(&self) -> Vec<ModelUsage> { ... }
    pub fn processes(&self) -> Vec<ProcessInfo> { ... }
    pub fn tools_top(&self, n: usize) -> Vec<ToolUsage> { ... }
    pub fn sessions(&self) -> Vec<SessionInfo> { ... }
}
```

`ingest()` is O(1) incremental update. Query methods read current state
directly — no re-aggregation.

Priority rules for conflicting data are defined once, inside `ingest()`:

- Tokens: local session > HTTP-extracted token_usage > agent_session metadata
- Tools: local session > HTTP-extracted tool_calls
- Processes: eBPF audit > /proc scan
- Models: local session > HTTP response headers

### Restore from storage

The same view struct can be populated from stored data instead of live sources:

```rust
impl MaterializedView {
    pub fn from_sources(sources: Vec<Box<dyn Source>>) -> Self { ... }
    pub fn from_sqlite(db: &str) -> Self { ... }
    pub fn from_jsonl(path: &str) -> Self { ... }
}
```

This means `stat --db path.db` and `stat` (reading JSONL + local files) both
produce the same `MaterializedView` and use the same query/display code.

### DB as optional sink

SQLite is not on the critical path. It is one of several optional consumers:

```
MaterializedView
  ├→ FileLogger       (always: write JSONL log)
  ├→ SqliteSink       (optional: record --db)
  ├→ TUI / CLI print  (always: display)
  ├→ WebServer        (optional: --server)
  └→ OtelExporter     (optional: --otel)
```

`SqliteSink` subscribes to the view's event stream and writes to SQLite.
The view does not know or care whether a DB exists.

When reading back (`stat --db`), SQLite is just another source — the view
replays stored events through `ingest()` and arrives at the same state.

## Per-command data flow

### record

```
EbpfSource + ProcSource + SessionSource
  → MaterializedView
    → FileLogger(record.log)
    → SqliteSink(session.db)   // optional
    → WebServer(:7395)         // optional
    → print summary on exit
```

### top (live)

```
EbpfSource + ProcSource + SessionSource
  → MaterializedView
    → TUI reads view.summary() each tick
    // no DB, pure in-memory
```

### stat

```
MaterializedView::from_jsonl(record.log)
  // or from_sqlite(session.db) with --db
  // or from local sessions only (no log)
  → print_stat(view.summary())
```

### report

```
MaterializedView::from_jsonl(record.log)
  // or from_sqlite(session.db) with --db
  → print_session_summary(view.summary())
```

## What changes

| Aspect | Current | New |
|--------|---------|-----|
| Merge logic | 3 commands, each ~200 lines | `ingest()` in one place |
| Token priority | Inconsistent across commands | Defined once in `ingest()` |
| DB role | Core data path (write + read) | Optional sink + optional restore source |
| Adapters/projectors | Complex SQL projection layer | Removed — view replaces them |
| Adding a new source | Modify every command | Implement `Source`, feed the view |
| Adding a new consumer | Add code in command files | Read from view |
| Programmable API | Query SQLite internals | `MaterializedView` methods |

## What does not change

- **eBPF programs** (`bpf/`): unchanged, still emit JSON to stdout.
- **Runner trait**: unchanged, still executes binaries and produces EventStream.
- **Analyzer trait**: unchanged, still single-stream transforms inside EbpfSource.
- **Frontend**: unchanged, still reads from `/api/events` HTTP endpoint.

## Prior art

| Tool | Pattern | DB role |
|------|---------|--------|
| Pixie | eBPF → in-memory columnar tables → PxL query | No DB; 24h rolling window |
| Hubble | eBPF → ring buffer → gRPC streaming | No DB; export to Prometheus/OTEL |
| Prometheus | Scrape → head block (memory) + WAL → PromQL | TSDB is both store and query engine |
| Vector | Source → Transform → Sink DAG | Stateless; DB is external sink |
| osquery | Virtual SQL tables generated from /proc on demand | No DB; RocksDB buffers events only |
| **AgentSight (proposed)** | Sources → MaterializedView → Sinks | Optional SQLite sink + restore source |

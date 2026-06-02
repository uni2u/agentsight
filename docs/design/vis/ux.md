# AgentSight UX: perf/top/strace/Nsight for Coding Agent Runs

## Goal

AgentSight should make one sentence true in both CLI and UI:

> See what coding agents actually do to your machine, and connect those actions
> back to the prompts, model calls, and tool decisions that triggered them.

The product should not feel like another generic LLM dashboard. It should feel
like a local systems tool for agent runs: record first, inspect later, export the
run artifact, and drill from high-level intent down to OS-level effects.

The UX model is:

```text
prompt / model call / tool decision
  -> process tree
    -> file, network, resource, stdio side effects
      -> result, risk, artifact
```

This document defines the desired command line and UI experience. It complements:

- `vis.md`: Agent Footprint Map, the agent equivalent of a flame graph.
- `agent-workspace-map.md`: workspace/file behavior visualizations.
- `why.md`: why boundary tracing/eBPF is needed.

## Product Positioning

AgentSight should borrow the interaction grammar of familiar systems tools:

| Tool | User expectation | AgentSight equivalent |
| --- | --- | --- |
| `perf stat` | run a command, print counters | `agentsight stat -- <agent>` |
| `perf top` / `top` | live ranked activity | `agentsight top` |
| `perf record` | capture a session artifact | `agentsight record -- <agent>` |
| `perf report` | inspect a saved artifact | `agentsight report` |
| `perf script` | dump ordered events | `agentsight script` |
| `perf diff` | compare runs | `agentsight diff` |
| `strace -f -tt -e ...` | follow subprocesses and filter events | `agentsight trace -f -tt -e process,file,network,llm` |
| Nsight Systems | time-correlated lanes and markers | Agent run timeline with LLM/tool/process/file lanes |

AgentSight is not trying to replace SDK trace tools. It should be the local,
framework-neutral run activity layer underneath them.

## Core UX Principles

### 1. Facts First, Interpretation Second

Default output should distinguish:

- observed facts: process exec, file write, network host, token usage
- inferred correlation: "this write likely followed this tool call"
- unavailable data: prompt not captured, SSL not attached, adapter not run

Never imply certainty where only timestamp correlation exists.

### 2. One Run Is the Primary Object

Everything revolves around a recorded run:

```text
run id
start/end time
root command or attached PID
SQLite DB path
capture capabilities
event counts
derived reports
exported artifacts
```

The UI should always show which run is loaded and whether it is live or static.

### 3. Intent-to-Effect Is the Main Story

The first view should not be raw logs, a generic timeline, or a process tree.
The first view should answer:

> What did the agent do, and why?

The primary object should be a causality ledger:

```text
User task
  LLM call
    tool decision
      process
        file/network/resource effects
```

### 4. Unattributed Behavior Must Be Visible

Unattributed behavior is a core differentiator. The UI must show a clear lane
for system activity that happened without an observed prompt/tool cause:

```text
Background / unattributed
  git status
  shell startup probes
  package manager postinstall
  network connection not tied to LLM traffic
```

This should not be hidden in raw logs.

### 5. Every View Must Export

Useful outputs should be shareable:

- terminal text
- JSON
- SQLite
- static HTML
- SVG for footprint/workspace maps
- Markdown report for PR review or incident notes

## Command Line UX

### Top-Level Shape

Preferred top-level command set:

```bash
agentsight stat    [options] [-- command ...]
agentsight top     [options]
agentsight record  [options] [-- command ...]
agentsight report  [options]
agentsight script  [options]
agentsight trace   [options]
agentsight diff    [options] <run-a> <run-b>
agentsight ui      [options]
agentsight export  [options]
agentsight list
agentsight discover
agentsight db      ...
```

`debug` commands can remain, but should be explicitly secondary:

```bash
agentsight debug ssl
agentsight debug process
agentsight debug system
```

### `agentsight stat`

Like `perf stat`: run a command or read a saved run and print counters.

Examples:

```bash
agentsight stat -- claude "fix the failing API test"
agentsight stat --db run.db
agentsight stat --json --db run.db
agentsight stat --repeat 5 -- claude -p "summarize this repo"
```

Default output should be quiet and counter-focused:

```text
AgentSight stat for: claude "fix the failing API test"

  13.241 s      elapsed time
       1        LLM calls
   1,380        tokens total              # 1,200 in, 180 out
       4        process execs
       4        process exits             # 2 success, 2 failure
       3        files touched             # 2 writes, 1 lockfile update
       2        network hosts             # api.anthropic.com, registry.npmjs.org
       1        failed commands
   42.8 MB      max RSS
    6.2 %       max CPU

  run db: ~/.local/share/agentsight/sessions/20260602-113015.db
```

Rules:

- `stat -- <command>` should suppress setup chatter by default.
- Use `--verbose` to show attach/probe details.
- Use `--no-ui` or make no web UI the default for `stat`.
- JSON output should be clean JSON. If a command is run, setup logs go to
  stderr or require `--json --db`.

### `agentsight top`

Like `top` or `perf top`: live ranked view.

Examples:

```bash
agentsight top
agentsight top --db run.db
agentsight top -p 1234
agentsight top -c claude
agentsight top --sort tokens
agentsight top --view files
agentsight top --once
```

Default layout:

```text
AgentSight top - live run 20260602-113015   00:02:13   events: 4,219

LLM / token activity
  tokens   calls   model
  128430      18   claude-sonnet-4

Processes
  execs  fail  cpu%  rss    command
     42     3  12.1  318M   node
      8     2   2.0   80M   npm

Files
  ops  writes  risk   path
   21      4   med    src/api/handler.ts
    3      1   high   ~/.aws/config

Network
  calls  bytes  host
    18   4.1M   api.anthropic.com
     2   1.2M   registry.npmjs.org

Unattributed
   6 execs, 12 file ops, 1 network host
```

Interactive keys:

```text
1        overview
2        processes
3        files
4        network
5        LLM calls
s        change sort
f        filter
t        time window
a        show attributed/unattributed
enter    drill into row
q        quit
```

### `agentsight record`

Like `perf record`: capture a run artifact.

Examples:

```bash
agentsight record -- claude "fix the failing API test"
agentsight record -c claude
agentsight record -p 1234
agentsight record --db run.db -- claude
agentsight record --output run.agentsight -- claude
```

Default output:

```text
AgentSight record
  target: claude "fix the failing API test"
  db: ~/.local/share/agentsight/sessions/20260602-113015.db
  ui: http://127.0.0.1:7395

Recording. Press Ctrl-C to stop.
```

At exit:

```text
Recorded 13.2s to ~/.local/share/agentsight/sessions/20260602-113015.db
Run:
  agentsight report --db ...
  agentsight stat --db ...
  agentsight ui --db ...
```

### `agentsight report`

Like `perf report`, but for agent runs.

Examples:

```bash
agentsight report
agentsight report --db run.db
agentsight report --section side-effects
agentsight report --markdown -o report.md
agentsight report --json
```

Default report structure:

```text
AgentSight report: claude "fix the failing API test"

Summary
  13s, 1 LLM call, 1,380 tokens, 4 processes, 3 files, 2 hosts

Intent -> effect chain
  user prompt: fix the failing API test
    model: claude-sonnet-4
    tool: Bash("npm test")
      process: npm -> node
      exit: failure, code 1
    tool: Edit("src/api/handler.ts")
      file: write src/api/handler.ts
    tool: Bash("npm test")
      process: npm -> node
      exit: success, code 0

Side effects
  files written:
    src/api/handler.ts
    tests/api.test.ts
    package-lock.json
  network:
    api.anthropic.com
    registry.npmjs.org

Unattributed activity
  none observed

Capture notes
  prompts: observed via TLS
  process/file events: observed via eBPF
  correlation: timestamp + process context
```

### `agentsight script`

Like `perf script`: ordered event stream.

Examples:

```bash
agentsight script --db run.db
agentsight script --db run.db -F time,pid,comm,kind,summary
agentsight script --db run.db -e process,file
agentsight script --json --db run.db
```

Example output:

```text
00.000  claude[1200] llm.request      POST api.anthropic.com/v1/messages
01.232  claude[1200] tool.call        Bash("npm test")
01.240  npm[1244]    process.exec     /usr/bin/npm test
01.510  node[1250]   file.open        /workspace/app/package.json
03.902  npm[1244]    process.exit     code 1
```

### `agentsight trace`

Like `strace`: detailed follow/filter mode.

Examples:

```bash
agentsight trace -f -tt -e process,file -- claude
agentsight trace -p 1234 -e file=write,delete,rename
agentsight trace -c claude -e network,llm
agentsight trace --summary-only -- claude
```

Design notes:

- `-f`: follow children.
- `-tt`: absolute timestamps.
- `-T`: include event duration when known.
- `-e`: event selection, similar to `strace -e`.
- `-o`: write raw event stream.
- `--db`: write normalized run DB.

### `agentsight diff`

Like `perf diff`: compare two agent runs.

Examples:

```bash
agentsight diff run-a.db run-b.db
agentsight diff --metric files run-a.db run-b.db
agentsight diff --metric tokens run-a.db run-b.db
agentsight diff --markdown -o diff.md run-a.db run-b.db
```

Questions answered:

- Did the new model read more files?
- Did it touch riskier paths?
- Did it use more tokens for the same task?
- Did it spawn more subprocesses?
- Did it introduce new network destinations?

### `agentsight ui`

Open or serve the UI for a run.

Examples:

```bash
agentsight ui
agentsight ui --db run.db
agentsight ui --port 7395 --db run.db
agentsight ui --snapshot trace.agentsight.json
```

The UI should be a run inspector, not a generic dashboard.

## Web UI Information Architecture

### First Screen: Run Ledger

The default view should be a dense run ledger:

```text
Run: claude "fix the failing API test"       13s   1,380 tokens
DB: ~/.local/share/agentsight/sessions/...   live/static

Timeline
00.000  user prompt
00.314  LLM call: claude-sonnet-4
01.232  tool: Bash("npm test")
01.240    process: npm -> node
03.902    exit: failure
04.110  tool: Edit("src/api/handler.ts")
04.115    file write: src/api/handler.ts
06.410  tool: Bash("npm test")
06.420    process: npm -> node
13.100    exit: success
```

Columns:

- time
- intent node
- effect summary
- status/risk
- tokens/cost
- attribution confidence

Clicking any row opens a side panel with raw details.

### Primary Navigation

Top-level tabs:

```text
Ledger | Footprint | Workspace | Processes | Files | Network | LLM | Metrics | Raw
```

The order matters. The product story starts with correlated behavior, not logs.

### View 1: Ledger

Purpose:

> Explain the run from prompt to machine effects.

Required features:

- expandable prompt/model/tool/process/file chain
- attributed vs unattributed toggle
- failed command highlighting
- sensitive path/risky side effect badges
- raw event drawer
- export selected chain as Markdown/JSON

### View 2: Footprint

Purpose:

> Static, shareable agent flame graph.

This implements the concept in `vis.md`.

Modes:

- width = tokens
- width = elapsed time
- width = process count
- width = risk-weighted side effects
- color = type or risk
- border = attribution confidence

Required outputs:

- SVG
- static HTML
- copyable Markdown link/embed

### View 3: Workspace

Purpose:

> Show where the agent spent attention and caused file effects.

This implements the concepts in `agent-workspace-map.md`.

Subviews:

- Attention Treemap
- Why This File Changed? provenance DAG
- Agent I/O Flame Graph
- Snapshot-aware workspace map
- Policy-aware filesystem map

Default should be changed-file focused:

```text
Changed files
  path
  read count
  write count
  first cause
  tests/commands involved
  risk
```

### View 4: Processes

Purpose:

> Show actual subprocess execution, including child processes the agent did not
> explicitly report.

Required features:

- process tree
- exit code/status
- duration
- cwd/argv
- parent tool/LLM attribution
- failed process filter
- background/unattributed process lane

### View 5: Files

Purpose:

> Make local side effects reviewable.

Required features:

- files read/written/created/deleted/renamed/truncated
- repo vs outside repo
- generated/cache/dependency paths
- secret/cloud/shell-profile risk classes
- diff hunk link when available
- provenance drawer: why this file changed

### View 6: Network

Purpose:

> Show network destinations and LLM/API activity.

Required features:

- host/path/method/status
- provider/model
- request/response availability
- auth header redaction status
- package registry/cloud API badges
- attributed tool/process chain

### View 7: LLM

Purpose:

> Inspect prompt/model calls without losing system context.

Required features:

- prompt/response previews
- token usage
- model/provider
- tool_use extraction when observable
- linked side effects after each call
- "no observed side effects" state

### View 8: Metrics

Purpose:

> Support performance/resource debugging without making performance the only
> story.

Required features:

- CPU/RSS over time
- process/resource correlation
- event-loss/capture-health counters
- overhead estimate when available

### View 9: Raw

Purpose:

> Escape hatch for systems users.

Required features:

- raw JSONL
- canonical events
- stored activity events
- SQL table browser or query presets
- copy event id

## Side Panel Design

Every row/card should open the same details drawer:

```text
Title: file write src/api/handler.ts

Attribution
  user prompt -> LLM call -> tool call -> process -> file event
  confidence: high

Observed facts
  time: ...
  pid: ...
  comm: ...
  cwd: ...
  argv: ...
  path: ...
  operation: write

Related
  previous LLM call
  next process exit
  diff hunk
  raw event
```

The drawer should use tabs:

```text
Summary | Facts | Raw | SQL
```

## Capture Health UX

AgentSight should always explain what it could and could not see:

```text
Capture health
  process tracing: ok
  file tracing: ok
  SSL/TLS plaintext: partial
  prompts: observed
  responses: observed
  tool calls: inferred from prompt payload
  event loss: 0
  adapters: claude-code v1
```

This belongs in:

- `stat`
- `report`
- UI header
- exported reports

## Empty and Partial States

Empty states should be action-oriented:

```text
No run loaded.

Start a run:
  agentsight stat -- claude
  agentsight record -- claude

Or open an existing run:
  agentsight ui --db run.db
```

Partial states should be explicit:

```text
No prompts captured.
Process/file/network facts are still available.

Likely causes:
  SSL binary was not discovered
  provider used unsupported TLS path
  traffic came from a different process
```

## Visual Language

AgentSight is an operational tool. It should feel closer to Nsight Systems,
perf, strace, and a PR review tool than to a marketing dashboard.

Preferred:

- dense tables
- timelines with lanes
- process/file provenance trees
- stable monospace identifiers
- restrained badges for risk/status
- export buttons
- keyboard shortcuts

Avoid:

- decorative hero UI
- vague health cards that cannot point to events
- charts that cannot be traced back to events
- hiding raw data behind summaries

## Keyboard UX

UI keyboard shortcuts:

```text
/        search/filter
1-9      switch primary tabs
f        filter by attributed/unattributed
r        reset filters
e        export current view
j/k      move selection
enter    open details drawer
esc      close drawer
?        shortcut help
```

## Search and Filter Model

Filters should mirror CLI event selectors:

```text
kind:process.exec
kind:file.write
path:~/.aws
host:registry.npmjs.org
comm:npm
status:failure
attribution:unattributed
risk:high
model:claude-sonnet
```

The same filter grammar should work in:

- `agentsight script -e ...`
- `agentsight top --filter ...`
- UI search bar
- report/export commands

## MVP Priorities

### P0: Make the Core Claim Visible

1. Run Ledger default view.
2. Side Effects summary in CLI `report`.
3. UI details drawer.
4. Capture health block.
5. Attributed vs unattributed grouping.

### P1: Make It Shareable

1. `agentsight report --markdown`.
2. Footprint SVG export.
3. Workspace changed-file table.
4. `agentsight script`.
5. `agentsight diff`.

### P2: Make It Feel Like a Systems Tool

1. Interactive `top`.
2. Filter grammar shared by CLI and UI.
3. Keyboard shortcuts.
4. Event-loss and overhead counters.
5. TUI mode for SSH-only environments.

## What Is Good Enough for the Next Release?

The next release is good enough when a user can run:

```bash
agentsight stat -- claude "fix the failing API test"
agentsight report
agentsight ui
```

And immediately answer:

1. What prompt/model/tool sequence happened?
2. What commands actually ran?
3. What files changed or were read?
4. What network destinations were contacted?
5. Which actions were not attributable to an observed tool decision?
6. Which details are observed vs inferred?

If the UI only shows process trees and raw logs, it is not good enough, even if
the underlying data is present.

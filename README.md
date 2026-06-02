# AgentSight: perf/strace for AI agents

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/eunomia-bpf/agentsight/actions/workflows/ci.yml/badge.svg)](https://github.com/eunomia-bpf/agentsight/actions/workflows/ci.yml)
[![arXiv:2508.02736](https://img.shields.io/badge/arXiv-2508.02736-b31b1b.svg)](https://arxiv.org/abs/2508.02736)
[![DOI:10.1145/3766882.3767169](https://img.shields.io/badge/DOI-10.1145%2F3766882.3767169-blue.svg)](https://dl.acm.org/doi/10.1145/3766882.3767169)

**English** | [中文](README.zh-CN.md)

LLM agent observability with eBPF. See what coding agents actually do
to your machine, and connect those actions back to the prompts, model calls, and
tool decisions that triggered them.

Run `agentsight` around Claude Code, Codex, Gemini CLI,
OpenCode, OpenClaw, or any command. AgentSight records a local trace of:

- processes and child processes, shell commands, cwd, argv, exit status, and duration
- files created, written, truncated, renamed, or deleted
- network destinations contacted
- prompts, responses, tool intent, and LLM/model/token usage when observable
  from network traffic or agent-native local session logs

No SDK, no proxy, no vendor integration. AgentSight observes with eBPF and TLS traffic tracing, so it works even when the agent is a
closed-source CLI. **✨ Zero Instrumentation Required**

## Quick Start

```bash
# Install
wget https://github.com/eunomia-bpf/agentsight/releases/latest/download/agentsight && chmod +x agentsight
# Launch your agent with monitoring. AgentSight may prompt for sudo
# to load eBPF probes; the agent itself still runs as your user.
./agentsight exec -- claude
# Or attach to an already-running agent by process name
sudo ./agentsight record -c claude
```

When the launched agent exits, `exec` prints a run summary. For the blog example:

```bash
./agentsight exec --db run.db -- claude "fix the failing API test"
```

```text
agentsight session · 7s · 1 API calls · 1380 tokens

  claude-sonnet-4-20250514 — 1 calls, 1380 tokens (in: 1200, out: 180)

2 processes spawned: node(1), npm(1)
3 files accessed: /workspace/app/src/api/handler.ts, /workspace/app/tests/api.test.ts, /workspace/app/package-lock.json
Network: api.anthropic.com, registry.npmjs.org
```

The summary is intentionally grounded in observable effects: model/token usage, spawned processes, touched files, and network targets, so the agent's final claim can be checked against what changed on the machine.

Open [http://127.0.0.1:7395](http://127.0.0.1:7395) to watch live.

<div align="center">
  <img src="https://github.com/eunomia-bpf/agentsight/raw/master/docs/demo-tree.png" alt="AgentSight Demo - Process Tree Visualization" width="800">
  <p><em>Real-time process tree visualization showing AI agent interactions and file operations</em></p>
</div>

<div align="center">
  <img src="https://github.com/eunomia-bpf/agentsight/raw/master/docs/demo-timeline.png" alt="AgentSight Demo - Timeline Visualization" width="800">
  <p><em>Real-time timeline visualization showing AI agent interactions and system calls</em></p>
</div>

<div align="center">
  <img src="https://github.com/eunomia-bpf/agentsight/raw/master/docs/demo-metrics.png" alt="AgentSight Demo - Metrics Visualization" width="800">
  <p><em>Real-time metrics visualization showing AI agent memory and CPU usage</em></p>
</div>

<div align="center">
  <p>👉 <strong>Try the <a href="https://agentsight.us">live demo</a></strong> — explore a real recorded Claude Code session right in your browser.</p>
</div>

## 🚀 Why AgentSight?

### Traditional Observability vs. System-Level Monitoring

Application-level tools such as [LangSmith](https://docs.langchain.com/langsmith/observability-concepts), [Langfuse](https://langfuse.com/docs/observability/overview), and [Phoenix](https://arize.com/docs/phoenix/) are great for traces, prompts, tokens, evals, and latency when you own the application code. Gateway/proxy tools such as [Helicone](https://docs.helicone.ai/getting-started/integration-method/gateway) are useful when you can route provider traffic through a managed endpoint.

AgentSight focuses on the layer those tools often miss: what the agent actually does at the system boundary. It observes existing binaries and CLI agents without SDKs or proxies, then correlates LLM traffic with process execution, file access, and system activity.

| **Challenge** | **Application-Level Tools** | **AgentSight Solution** |
|---------------|----------------------------|------------------------|
| **Framework Adoption** | ❌ SDK, callback, or gateway integration per app | ✅ Drop-in system tracer, no code changes |
| **Closed-Source CLIs** | ❌ Limited to what the tool exposes or logs | ✅ Observes existing binaries and CLI agents from outside |
| **Agent-Controlled Logs** | ❌ Logs can be incomplete, disabled, or modified | ✅ Kernel-level events independent of app logging |
| **TLS LLM Traffic** | ❌ Visible when routed through SDKs/proxies | ✅ Captures plaintext at SSL/TLS calls without a proxy |
| **System Actions** | ❌ Often misses subprocesses and local file activity | ✅ Tracks process execution, file access, and resource use |
| **Cross-Boundary Behavior** | ❌ Traces usually stop at framework/process boundaries | ✅ Correlates LLM traffic with process and file events |

AgentSight captures critical interactions that application-level tools miss:

- Subprocess executions that bypass instrumentation
- Plaintext LLM payloads at SSL/TLS call boundaries
- File operations and system resource access  
- Cross-boundary behavior across LLM, process, and file events

## Usage

### Prerequisites

- **Linux kernel**: 4.1+ with eBPF support (5.0+ recommended)
- **sudo access**: eBPF probes are auto-elevated; your agent stays unprivileged

For source builds, see [docs/build.md](docs/build.md).

### Installation

#### Release Binary

For local use, download the latest release binary and run `agentsight exec -- ...` as shown in Quick Start.

#### Docker

Docker is useful for container, CI, or isolated Linux environments, but it still needs privileged host access for eBPF. See [docs/docker.md](docs/docker.md).

#### Build from Source

Build requirements and source build commands live in [docs/build.md](docs/build.md).

### Querying Past Sessions

Every `exec` session is automatically saved to SQLite. Query with `agentsight db`:

```bash
agentsight db summary                 # high-level run summary
agentsight db token                   # token usage (auto-finds latest session)
agentsight db audit --json            # process spawns, file opens, API calls
agentsight db list                    # all recorded sessions
agentsight db export -o snapshot.json # export for web dashboard
```

During a session, visit [http://127.0.0.1:7395](http://127.0.0.1:7395) for live traffic, process trees, and metrics.

> **Privileges:** eBPF probes need root. AgentSight auto-elevates them via `sudo` (you may be prompted once). Your agent always runs as your normal user. If you prefer explicit sudo: `sudo -E ./agentsight exec -- claude` — the child is still dropped to your user.

**Discover what agents are installed locally:**

```bash
./agentsight discover
```

**Attach to a running agent with `record`:**

```bash
./agentsight record -c claude
./agentsight record -c python
./agentsight record -c node --binary-path docker://openclaw
```

Built-in SQL adapters cover Anthropic, Claude Code, Gemini CLI, and OpenClaw sessions. Use `--no-adapters` to disable, or `agentsight db adapters list --json` to inspect.

### Usage Examples

#### Zero-Config: `exec` (recommended)

`exec` is the simplest way to trace an agent. Put the command you want to run
after `exec --`; AgentSight handles everything else:

```bash
# Launch and trace Claude Code — no --binary-path or --comm needed
./agentsight exec -- claude

# Works for any agent: pass the command exactly as you'd normally run it
./agentsight exec -- claude -p "review my last commit"
./agentsight exec -- python my_agent.py
./agentsight exec -- node ./cli.js
```

What `exec` does automatically:

1. **Discovers the SSL binary** — resolves the command via `$PATH`, follows
   symlinks (e.g. `claude` → `~/.local/share/claude/versions/2.1.150`), and
   chases shebang wrappers (e.g. a `#!/usr/bin/env node` script → the real
   `node` ELF) so uprobes attach to the correct executable.
2. **Derives the `--comm` process filter** from the command name.
3. **Launches the agent** with your terminal attached (its TUI/REPL works
   normally) while SSL + process + system monitoring runs quietly in the
   background.
4. **Stops automatically** when the agent process exits.

> **`sudo` note**: under `sudo`, `exec` still finds *your* user-local installs
> (it reads `$SUDO_USER`'s home for `~/.local/bin`, `~/bin`, and `~/.nvm`), so
> `./agentsight exec -- claude` traces the claude in your home directory,
> not a different one on root's `$PATH`.

Useful flags: `--binary-path <path>` to override auto-discovery, `--no-server`
to disable the web UI, `--server-port <port>`, `-o <log-file>`.

#### Monitoring Claude Code

Claude Code is a Bun-based application with BoringSSL statically linked and
symbols stripped. AgentSight auto-detects BoringSSL functions via byte-pattern
matching when `--binary-path` is provided:

```bash
# Find the Claude binary version
CLAUDE_BIN=~/.local/share/claude/versions/$(claude --version | head -1)

# Record all Claude activity with web UI
./agentsight record -c claude --binary-path "$CLAUDE_BIN"
# Open http://127.0.0.1:7395 to view timeline

# Advanced: full trace with custom filters
./agentsight debug trace --ssl true --process true --comm claude \
  --binary-path "$CLAUDE_BIN" --server true --server-port 8080
```

This captures:
- **Conversation API**: `POST /v1/messages` requests with full prompt/response SSE streaming
- **Telemetry**: heartbeat, event logging, Datadog logs
- **Process activity**: file operations, subprocess executions

> **Note**: All SSL traffic in Claude flows through an internal "HTTP Client"
> thread, not the main "claude" thread. When `--binary-path` is specified,
> the `--comm` filter is automatically skipped for SSL monitoring (but still
> applied for process monitoring) to ensure traffic is captured correctly.

#### Monitoring Python AI Tools

```bash
# Monitor aider, open-interpreter, or any Python-based AI tool
./agentsight record -c "python"

# Custom port and log file
./agentsight record -c "python" --server-port 8080 --log-file /tmp/agent.log
```

#### Monitoring Node.js AI Tools (Gemini CLI, etc.)

> **Important**: Node.js (both NVM and system installs) **statically links
> OpenSSL into the `node` binary** — there is no system `libssl.so` to hook.
> SSL capture therefore requires pointing sslsniff at the `node` binary itself.

The easiest way is `exec`, which discovers the `node` binary automatically:

```bash
# Gemini CLI runs on Node — exec finds the right binary and traces it
./agentsight exec -- gemini
```

With `record`, AgentSight now auto-discovers the Node binary from `-c node`
(it detects that Node embeds OpenSSL and attaches to the binary instead of a
system library), so this just works without `--binary-path`:

```bash
# Monitor Gemini CLI or other Node.js AI tools — binary auto-discovered
./agentsight record -c node

# Pin the binary explicitly if auto-discovery picks the wrong Node install
./agentsight record -c node --binary-path ~/.nvm/versions/node/v20.0.0/bin/node
```

> **Behind an HTTP/HTTPS proxy?** Traffic is still TLS-encrypted inside the
> Node process (the proxy only tunnels it), so AgentSight captures it the same
> way — at the `SSL_read`/`SSL_write` calls before encryption.

#### Monitoring Agents in Docker Containers (OpenClaw, etc.)

For an agent running inside a Docker container, pass the container to
`--binary-path` with the `docker://` scheme. AgentSight resolves the container's
process tree and attaches sslsniff to the right binary automatically:

```bash
# OpenClaw is a Node.js agent that runs in a container — works out of the box
./agentsight record -c node --binary-path docker://openclaw

# Accepts a container name or ID; supported by record / trace / ssl
./agentsight debug trace --binary-path docker://openclaw --server
```

`docker inspect` reports the container's *init* process (often `tini`), which
has no SSL code. AgentSight walks the descendant process tree and attaches to the
first process whose binary actually embeds SSL (the `node` process). See
[docs/openclaw.md](docs/openclaw.md) for the full walkthrough.

#### Advanced Monitoring

```bash
# Combined SSL and process monitoring with web interface
./agentsight debug trace --ssl true --process true --server true

# Custom port and log file
./agentsight record -c "python" --server-port 8080 --log-file /tmp/agent.log
```

#### Export to OpenTelemetry (GenAI semantic conventions)

AgentSight can export captured LLM calls as OpenTelemetry **GenAI**
(`gen_ai.*`) spans over OTLP/HTTP — standards-compliant agent telemetry for any
agent, with zero in-process instrumentation. Send them to an OpenTelemetry
Collector and on to Jaeger, Grafana Tempo, Datadog, Honeycomb, etc.

```bash
# Export gen_ai.* spans to a collector (defaults to http://localhost:4318)
./agentsight debug trace --otel --otel-endpoint http://localhost:4318

# Include prompt/completion content (opt-in; off by default for privacy)
./agentsight debug trace --otel --otel-capture-content
```

Each LLM request/response pair becomes a `chat {model}` span with
`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.{input,output}_tokens`,
`gen_ai.response.finish_reasons`, and more. See [docs/otel.md](docs/otel.md) for
collector setup and backend integration.

#### Browser Plaintext Capture

For browser-specific plaintext capture, use the standalone `browsertrace` BPF
tool instead of `sslsniff`:

```bash
# Chrome / Chromium
sudo ./bpf/browsertrace --binary-path /opt/google/chrome/chrome

# Firefox on Ubuntu Snap
sudo ./bpf/browsertrace --binary-path /snap/firefox/current/usr/lib/firefox/firefox
```

> **Note**: On Ubuntu, `/usr/bin/firefox` is often a wrapper script rather than
> the real browser ELF. Point `browsertrace` at the actual Firefox binary.

#### Local MCP over stdio

For local MCP servers that communicate over `stdio` instead of HTTP/TLS, use
the standalone `stdiocap` BPF tool:

```bash
# Capture stdin/stdout/stderr payloads for a local MCP server process
sudo ./bpf/stdiocap -p <mcp_server_pid>
```

AgentSight also includes a minimal MCP fixture for local testing under
[`docs/mcp-test/README.md`](docs/mcp-test/README.md). It provides both `stdio`
and HTTP test modes so you can generate predictable MCP traffic before wiring
it into the Rust collector.

#### Direct eBPF Program Usage

```bash
# Run sslsniff directly on Claude binary
sudo ./bpf/sslsniff --binary-path ~/.local/share/claude/versions/2.1.39

# Run sslsniff on NVM Node.js
sudo ./bpf/sslsniff --binary-path ~/.nvm/versions/node/v20.0.0/bin/node --verbose

# Run browsertrace directly on Chrome
sudo ./bpf/browsertrace --binary-path /opt/google/chrome/chrome

# Run stdiocap directly on a local MCP server PID
sudo ./bpf/stdiocap -p 12345

# Run process tracer
sudo ./bpf/process -c python
```

#### Web Interface Access

`exec` and `record` start the web UI by default. Low-level `debug trace` starts it when you pass `--server`:
- **Timeline View**: http://127.0.0.1:7395/timeline
- **Process Tree**: http://127.0.0.1:7395/tree
- **Raw Logs**: http://127.0.0.1:7395/logs


## ❓ Frequently Asked Questions

**Q: What permissions does AgentSight need?**
A: eBPF probes need root privileges, so AgentSight may prompt for `sudo`. With `exec`, the monitored agent still runs as your normal user; only the probes are elevated.

**Q: What's the performance impact?**
A: Our evaluation reports less than 3% CPU overhead for typical traced agent workloads.

**Q: Where does captured data go?**
A: `exec` stores sessions locally in SQLite by default. Use `agentsight db summary`, `agentsight db audit --json`, and `agentsight db token` to inspect prior runs. Captured data can include prompts, responses, paths, headers, and network targets, so treat logs and DBs as sensitive.

**Q: Why doesn't AgentSight capture traffic from Claude Code, Node.js, or Gemini CLI?**
A: These applications statically link their SSL library (BoringSSL for Claude/Bun, OpenSSL for **all** Node.js — both NVM and system installs) into their own binary instead of using system `libssl.so`, so there's nothing for sslsniff to hook by default. AgentSight handles this for you: `exec` always discovers the binary, and `record -c node` now auto-discovers the Node binary too. For Claude, pass `--binary-path` (or use `exec`). See the "Zero-Config: exec" and "Monitoring Node.js AI Tools" sections.

**Q: What should I check if tracing fails?**
A: Verify you are on Linux with eBPF support, have `sudo` or `CAP_BPF`/`CAP_SYS_ADMIN`, and are using `exec` or the correct `--binary-path` for statically linked agents.

## 🤝 Contributing

We welcome contributions! After cloning and building (see [docs/build.md](docs/build.md)), you can:

```bash
# Run tests
make test

# Frontend development server
cd frontend && npm run dev

# Build debug versions with AddressSanitizer
make -C bpf debug
```

### Key Resources

- [CLAUDE.md](CLAUDE.md) - Project guidelines and architecture
- [collector/DESIGN.md](collector/DESIGN.md) - Framework design details
- [docs/why.md](docs/why.md) - Problem analysis and motivation

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**💡 The Future of AI Observability**: As AI agents become more autonomous and capable of self-modification, traditional observability approaches become insufficient. AgentSight provides independent, system-level monitoring for safe AI deployment at scale.

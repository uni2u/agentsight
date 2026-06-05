// Converts the raw recorded session in docs/ into an AgentSightSnapshot JSON
// that the frontend can load directly. Also copies screenshot assets for the
// demo landing banner.

import { readFileSync, writeFileSync, copyFileSync, mkdirSync, existsSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';

const here = dirname(fileURLToPath(import.meta.url));
const SRC = resolve(here, '../../docs/example_record_ claude_init.log');
const OUT = resolve(here, '../public/sample-snapshot.json');
const IMG_DIR = resolve(here, '../public/images');

const NS_PER_MS = 1_000_000;
const ANCHOR_MS = Date.parse('2026-04-29T10:00:00Z');
const NS_THRESHOLD = 1e13;

const lines = readFileSync(SRC, 'utf8').split('\n').filter((l) => l.trim());

let minTs = Infinity;
for (const line of lines) {
  const ts = JSON.parse(line).timestamp;
  if (typeof ts === 'number' && ts < minTs) minTs = ts;
}

const toMs = (ts) =>
  typeof ts === 'number' && ts > NS_THRESHOLD
    ? ANCHOR_MS + Math.round((ts - minTs) / NS_PER_MS)
    : ts;

let idCounter = 0;
const nextId = () => `evt-${++idCounter}`;

const truncate = (s, limit) =>
  typeof s === 'string' && s.length > limit ? s.slice(0, limit) + '... [truncated]' : s;

const auditEvents = [];
const processNodes = new Map();
const tokenSummary = new Map();
let llmCalls = 0;

for (const line of lines) {
  const raw = JSON.parse(line);
  const ts = toMs(raw.timestamp);
  const d = raw.data || {};
  const pid = raw.pid ?? d.pid ?? 0;
  const comm = raw.comm ?? d.comm ?? '';

  if (raw.source === 'process') {
    const evt = d.event || '';
    if (evt === 'EXEC') {
      processNodes.set(pid, {
        id: `proc-${pid}`, pid, ppid: d.ppid ?? null,
        start_timestamp_ms: ts, comm,
        command: d.filepath || comm,
        argv: d.argv ? d.argv.split(' ') : [],
        cwd: d.cwd ?? null, status: 'running',
      });
      auditEvents.push({
        id: nextId(), timestamp_ms: ts, audit_type: 'process',
        pid, comm, action: 'exec', target: d.filepath || null,
        status: 'observed', summary: `exec ${d.filepath || comm}`,
      });
    } else if (evt === 'EXIT') {
      const node = processNodes.get(pid);
      if (node) {
        node.end_timestamp_ms = ts;
        node.exit_code = d.exit_code ?? null;
        node.status = 'exited';
      }
      auditEvents.push({
        id: nextId(), timestamp_ms: ts, audit_type: 'process',
        pid, comm, action: 'exit', status: 'observed',
        summary: `process exit (code ${d.exit_code ?? '?'})`,
      });
    } else if (evt === 'FILE_OPEN') {
      auditEvents.push({
        id: nextId(), timestamp_ms: ts, audit_type: 'file',
        pid, comm, action: 'open', target: d.filepath || null,
        status: 'observed', summary: `open ${d.filepath || '?'}`,
      });
    }
  } else if (raw.source === 'http_parser') {
    const msgType = d.message_type || 'request';
    let bodyObj = null;
    if (typeof d.body === 'string' && d.body) {
      try { bodyObj = JSON.parse(d.body); } catch {}
    }
    const model = bodyObj?.model || d.model || d.headers?.['x-model'] || null;
    if (msgType === 'request') llmCalls++;

    if (model) {
      const inp = bodyObj?.usage?.input_tokens || d.input_tokens || 0;
      const out = bodyObj?.usage?.output_tokens || d.output_tokens || 0;
      const existing = tokenSummary.get(model) || { group: model, input_tokens: 0, output_tokens: 0, total_tokens: 0, calls: 0 };
      existing.input_tokens += inp;
      existing.output_tokens += out;
      existing.total_tokens += inp + out;
      existing.calls++;
      tokenSummary.set(model, existing);
    }

    const action = msgType === 'request' ? 'request' : 'response';
    auditEvents.push({
      id: nextId(), timestamp_ms: ts, audit_type: 'llm',
      pid, comm, action, subject: model,
      target: d.path || d.url || null,
      status: 'observed',
      summary: `${action === 'request' ? 'LLM request' : 'LLM response'}${model ? ` (${model})` : ''}`,
      details: { method: d.method, status_code: d.status_code, model, body: truncate(d.body, 2000) },
    });
  } else if (raw.source === 'sse_processor') {
    let model = null;
    let inp = 0, out = 0;
    for (const sse of d.sse_events || []) {
      const pd = sse.parsed_data || {};
      if (pd.type === 'message_start' && pd.message) {
        model = model || pd.message.model || null;
        const u = pd.message.usage;
        if (u) {
          inp += (u.input_tokens || 0) + (u.cache_creation_input_tokens || 0) + (u.cache_read_input_tokens || 0);
          out += u.output_tokens || 0;
        }
      }
      if (pd.type === 'message_delta' && pd.usage) {
        out += pd.usage.output_tokens || 0;
      }
    }
    if (model) {
      const existing = tokenSummary.get(model) || { group: model, input_tokens: 0, output_tokens: 0, total_tokens: 0, calls: 0 };
      existing.input_tokens += inp;
      existing.output_tokens += out;
      existing.total_tokens += inp + out;
      existing.calls++;
      tokenSummary.set(model, existing);
    }
    auditEvents.push({
      id: nextId(), timestamp_ms: ts, audit_type: 'llm',
      pid, comm, action: 'response', subject: model,
      status: 'observed',
      summary: `SSE stream response${model ? ` (${model})` : ''}`,
      details: { json_content: d.json_content, text_content: truncate(d.text_content, 2000), event_count: d.event_count, message_id: d.message_id },
    });
  } else if (raw.source === 'ssl') {
    auditEvents.push({
      id: nextId(), timestamp_ms: ts, audit_type: 'network',
      pid, comm, action: 'ssl',
      status: 'observed', summary: `SSL ${d.direction || 'data'}`,
    });
  }
}

const timestamps = auditEvents.map(e => e.timestamp_ms).filter(Boolean);
const snapshot = {
  schema_version: 1,
  generated_at: new Date().toISOString(),
  summary: {
    source: 'demo',
    view_events: auditEvents.length,
    llm_calls: llmCalls,
    token_usage_rows: tokenSummary.size,
    audit_events: auditEvents.length,
    sessions: 0,
    input_tokens: [...tokenSummary.values()].reduce((s, r) => s + r.input_tokens, 0),
    output_tokens: [...tokenSummary.values()].reduce((s, r) => s + r.output_tokens, 0),
    total_tokens: [...tokenSummary.values()].reduce((s, r) => s + r.total_tokens, 0),
    start_timestamp_ms: Math.min(...timestamps),
    end_timestamp_ms: Math.max(...timestamps),
  },
  token_summary: [...tokenSummary.values()],
  network_targets: [],
  process_nodes: [...processNodes.values()],
  audit_events: auditEvents,
  resource_samples: [],
  sessions: [],
  tool_calls: [],
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(snapshot));
console.log(`Wrote snapshot with ${auditEvents.length} events -> ${OUT}`);

// Copy screenshots for the demo banner
mkdirSync(IMG_DIR, { recursive: true });
const images = ['demo-timeline.png', 'demo-tree.png', 'demo-metrics.png', 'top-mode-demo.png'];
for (const img of images) {
  const src = resolve(here, `../../docs/${img}`);
  if (existsSync(src)) {
    copyFileSync(src, resolve(IMG_DIR, img));
    console.log(`Copied ${img}`);
  }
}

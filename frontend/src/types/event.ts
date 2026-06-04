// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

export interface ViewEvent {
  id: string;
  timestamp: number;
  source: string;
  pid: number;
  comm: string;
  data: any;
}

export interface ProcessedViewEvent extends ViewEvent {
  datetime: Date;
  formattedTime: string;
  sourceColor: string;
  sourceColorClass: string;
}

export interface SnapshotSummary {
  view_events?: number;
  llm_calls?: number;
  token_usage_rows?: number;
  audit_events?: number;
  sessions?: number;
}

export interface SnapshotTokenSummary {
  group: string;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  calls?: number;
}

export interface SnapshotNetworkTarget {
  pid?: number | null;
  comm?: string | null;
  host: string;
  path?: string | null;
  count?: number;
  error_count?: number;
  first_timestamp_ms?: number | null;
  last_timestamp_ms?: number | null;
}

export interface SnapshotAuditEvent {
  id: string;
  timestamp_ms: number;
  audit_type: string;
  pid?: number | null;
  comm?: string | null;
  subject?: string | null;
  action?: string | null;
  target?: string | null;
  status?: string | null;
  summary?: string | null;
  details?: unknown;
}

export interface SnapshotProcessNode {
  id: string;
  pid: number;
  ppid?: number | null;
  root_pid?: number | null;
  start_timestamp_ms?: number | null;
  end_timestamp_ms?: number | null;
  comm?: string | null;
  command?: string | null;
  argv?: string[];
  cwd?: string | null;
  exit_code?: number | null;
  status?: string | null;
}

export interface SnapshotResourceSample {
  timestamp_ms: number;
  pid?: number | null;
  comm?: string | null;
  cpu_percent?: number | null;
  rss_mb?: number | null;
}

export interface SnapshotSession {
  id: string;
  agent_type: string;
  agent_name?: string | null;
  pid?: number | null;
  comm?: string | null;
  start_timestamp_ms: number;
  end_timestamp_ms?: number | null;
  status?: string;
  model?: string | null;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  attributes?: unknown;
}

export interface AgentSightSnapshot {
  schema_version?: number;
  generated_at?: string;
  summary?: SnapshotSummary;
  token_summary?: SnapshotTokenSummary[];
  network_targets?: SnapshotNetworkTarget[];
  process_nodes?: SnapshotProcessNode[];
  audit_events?: SnapshotAuditEvent[];
  resource_samples?: SnapshotResourceSample[];
  sessions?: SnapshotSession[];
}

export function snapshotEventCount(snapshot: AgentSightSnapshot | null): number {
  if (!snapshot) return 0;
  return [
    snapshot.audit_events,
    snapshot.process_nodes,
    snapshot.network_targets,
    snapshot.resource_samples,
    snapshot.sessions,
  ].reduce((total, rows) => total + (Array.isArray(rows) ? rows.length : 0), 0);
}

export function snapshotToViewEvents(snapshot: AgentSightSnapshot | null): ViewEvent[] {
  if (!snapshot) return [];
  return [
    ...auditEvents(snapshot.audit_events),
    ...processNodeEvents(snapshot.process_nodes),
    ...networkEvents(snapshot.network_targets),
    ...resourceEvents(snapshot.resource_samples),
    ...sessionEvents(snapshot.sessions),
  ].sort((a, b) => a.timestamp - b.timestamp);
}

function auditEvents(rows?: SnapshotAuditEvent[]): ViewEvent[] {
  if (!Array.isArray(rows)) return [];
  return rows
    .filter(row => typeof row.timestamp_ms === 'number')
    .map(row => {
      const details = isRecord(row.details) ? row.details : {};
      return {
        id: row.id,
        timestamp: row.timestamp_ms,
        source: row.audit_type,
        pid: row.pid ?? 0,
        comm: row.comm ?? row.subject ?? '',
        data: {
          ...details,
          event: auditEventName(row),
          audit_type: row.audit_type,
          action: row.action,
          target: row.target,
          status: row.status,
          summary: row.summary,
          subject: row.subject,
          filename: row.audit_type === 'process' ? row.target : details.filename,
          filepath: row.audit_type === 'file' ? row.target : details.filepath,
          path: row.audit_type === 'file' ? row.target : details.path,
        },
      };
    });
}

function processNodeEvents(rows?: SnapshotProcessNode[]): ViewEvent[] {
  if (!Array.isArray(rows)) return [];
  return rows.map(row => ({
    id: `process-node-${row.id}`,
    timestamp: row.start_timestamp_ms ?? row.end_timestamp_ms ?? 0,
    source: 'process_node',
    pid: row.pid,
    comm: row.comm ?? '',
    data: row,
  }));
}

function networkEvents(rows?: SnapshotNetworkTarget[]): ViewEvent[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((row, index) => ({
    id: `network-${row.pid ?? 0}-${row.host}-${row.path ?? ''}-${index}`,
    timestamp: row.last_timestamp_ms ?? row.first_timestamp_ms ?? 0,
    source: 'network',
    pid: row.pid ?? 0,
    comm: row.comm ?? '',
    data: { ...row, event: 'NETWORK_TARGET' },
  }));
}

function resourceEvents(rows?: SnapshotResourceSample[]): ViewEvent[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((row, index) => ({
    id: `resource-${row.pid ?? 0}-${row.timestamp_ms}-${index}`,
    timestamp: row.timestamp_ms,
    source: 'system',
    pid: row.pid ?? 0,
    comm: row.comm ?? '',
    data: {
      event: 'RESOURCE_SAMPLE',
      cpu: { percent: row.cpu_percent ?? 0 },
      memory: { rss_mb: row.rss_mb ?? 0 },
    },
  }));
}

function sessionEvents(rows?: SnapshotSession[]): ViewEvent[] {
  if (!Array.isArray(rows)) return [];
  return rows.map(row => ({
    id: `session-${row.id}`,
    timestamp: row.end_timestamp_ms ?? row.start_timestamp_ms,
    source: 'session',
    pid: row.pid ?? 0,
    comm: row.comm ?? row.agent_name ?? row.agent_type,
    data: {
      ...(isRecord(row.attributes) ? row.attributes : {}),
      event: 'SESSION',
      session_id: row.id,
      agent_type: row.agent_type,
      agent_name: row.agent_name,
      status: row.status,
      model: row.model,
      input_tokens: row.input_tokens ?? 0,
      output_tokens: row.output_tokens ?? 0,
      total_tokens: row.total_tokens ?? 0,
    },
  }));
}

function auditEventName(row: SnapshotAuditEvent): string {
  if (row.audit_type === 'process') {
    if (row.action === 'exec') return 'EXEC';
    if (row.action === 'exit') return 'EXIT';
    return (row.action ?? 'PROCESS').toUpperCase();
  }
  if (row.audit_type === 'file') return 'FILE_WRITE';
  if (row.audit_type === 'llm') return 'LLM_CALL';
  return row.audit_type.toUpperCase();
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

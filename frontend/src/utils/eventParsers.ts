// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

import {
  AgentSightSnapshot,
  SnapshotAuditEvent,
  SnapshotProcessNode,
} from '@/types/event';
import { comparePrompts } from './jsonDiff';

export interface ProcessNode {
  id: string;
  pid: number;
  comm: string;
  ppid?: number;
  startTimestamp?: number;
  endTimestamp?: number;
  children: ProcessNode[];
  events: ParsedEvent[];
  timeline: TimelineItem[];
}

export interface TimelineItem {
  type: 'event' | 'process';
  timestamp: number;
  event?: ParsedEvent;
  process?: ProcessNode;
}

export interface ParsedEvent {
  id: string;
  timestamp: number;
  type: 'prompt' | 'response' | 'ssl' | 'file' | 'process' | 'stdio' | 'system';
  title: string;
  content: string;
  metadata: Record<string, any>;
  promptDiff?: {
    diff: string;
    summary: string;
    hasChanges: boolean;
    previousPromptId?: string;
  };
}

export function buildProcessTree(snapshot: AgentSightSnapshot | null): ProcessNode[] {
  const processMap = new Map<string, ProcessNode>();
  const nodesByPid = new Map<number, ProcessNode[]>();
  const promptHistoryByProcess = new Map<string, ParsedEvent[]>();

  for (const row of snapshot?.process_nodes ?? []) {
    const process = processFromRow(row);
    processMap.set(process.id, process);
    nodesByPid.set(process.pid, [...(nodesByPid.get(process.pid) ?? []), process]);
  }

  nodesByPid.forEach(nodes => nodes.sort((a, b) => firstTimestamp(a) - firstTimestamp(b)));

  for (const row of [...(snapshot?.audit_events ?? [])].sort((a, b) => a.timestamp_ms - b.timestamp_ms)) {
    const process = processForAudit(row, nodesByPid);
    if (!process) continue;

    const event = auditToParsedEvent(row);
    if (event.type === 'prompt') {
      const history = promptHistoryByProcess.get(process.id) ?? [];
      attachPromptDiff(event, history);
      promptHistoryByProcess.set(process.id, [...history, event].slice(-10));
    }
    process.events.push(event);
  }

  const childProcesses = new Set<string>();
  processMap.forEach(process => {
    const parent = parentProcess(process, nodesByPid);
    if (!parent) return;
    parent.children.push(process);
    childProcesses.add(process.id);
  });

  processMap.forEach(process => {
    process.events.sort((a, b) => a.timestamp - b.timestamp);
    process.children.sort((a, b) => firstTimestamp(a) - firstTimestamp(b));
    process.timeline = timelineForProcess(process);
  });

  return Array.from(processMap.values())
    .filter(process => !childProcesses.has(process.id))
    .sort((a, b) => firstTimestamp(a) - firstTimestamp(b));
}

export function timelineForProcess(process: ProcessNode): TimelineItem[] {
  return [
    ...process.events.map(event => ({ type: 'event' as const, timestamp: event.timestamp, event })),
    ...process.children.map(child => ({ type: 'process' as const, timestamp: firstTimestamp(child), process: child })),
  ].sort((a, b) => a.timestamp - b.timestamp);
}

function processFromRow(row: SnapshotProcessNode): ProcessNode {
  return {
    id: row.id,
    pid: row.pid,
    comm: row.comm ?? row.command ?? 'unknown',
    ppid: row.ppid ?? undefined,
    startTimestamp: row.start_timestamp_ms ?? undefined,
    endTimestamp: row.end_timestamp_ms ?? undefined,
    children: [],
    events: [],
    timeline: [],
  };
}

function processForAudit(
  row: SnapshotAuditEvent,
  nodesByPid: Map<number, ProcessNode[]>,
): ProcessNode | undefined {
  if (typeof row.pid !== 'number') return undefined;
  return lastMatching(
    nodesByPid.get(row.pid),
    process => containsTimestamp(process, row.timestamp_ms),
  );
}

function parentProcess(
  process: ProcessNode,
  nodesByPid: Map<number, ProcessNode[]>,
): ProcessNode | undefined {
  if (!process.ppid) return undefined;
  const start = firstTimestamp(process);
  return lastMatching(
    nodesByPid.get(process.ppid),
    parent => parent.id !== process.id && containsTimestamp(parent, start),
  );
}

function containsTimestamp(process: ProcessNode, timestamp: number): boolean {
  return (process.startTimestamp ?? 0) <= timestamp
    && (process.endTimestamp === undefined || timestamp <= process.endTimestamp);
}

function lastMatching<T>(items: T[] | undefined, predicate: (item: T) => boolean): T | undefined {
  if (!items) return undefined;
  for (let i = items.length - 1; i >= 0; i--) {
    if (predicate(items[i])) return items[i];
  }
  return undefined;
}

function firstTimestamp(process: ProcessNode): number {
  const childStart = process.children.reduce(
    (earliest, child) => Math.min(earliest, firstTimestamp(child)),
    Infinity,
  );
  const eventStart = process.events[0]?.timestamp ?? Infinity;
  const ownStart = process.startTimestamp ?? Infinity;
  const earliest = Math.min(ownStart, eventStart, childStart);
  return earliest === Infinity ? 0 : earliest;
}

function auditToParsedEvent(row: SnapshotAuditEvent): ParsedEvent {
  const details = isRecord(row.details) ? row.details : {};
  const type = auditEventType(row);
  const model = row.subject ?? stringValue(details.model);
  const target = row.target ?? stringValue(details.path) ?? stringValue(details.filepath);
  const metadata = {
    ...details,
    raw: row.details ?? row,
    original_source: row.audit_type,
    event: auditEventName(row),
    audit_type: row.audit_type,
    action: row.action,
    status: row.status,
    model,
    method: row.action,
    url: target,
    path: target,
    filepath: row.audit_type === 'file' ? target : details.filepath,
    filename: row.audit_type === 'process' ? target : details.filename,
    comm: row.comm,
    pid: row.pid,
  };

  return {
    id: row.id,
    timestamp: row.timestamp_ms,
    type,
    title: eventTitle(row, type, model, target),
    content: JSON.stringify(row.details ?? row, null, 2),
    metadata,
  };
}

function auditEventType(row: SnapshotAuditEvent): ParsedEvent['type'] {
  if (row.audit_type === 'llm') {
    return row.action === 'request' ? 'prompt' : 'response';
  }
  if (row.audit_type === 'file') return 'file';
  if (row.audit_type === 'process') return 'process';
  return 'ssl';
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

function eventTitle(
  row: SnapshotAuditEvent,
  type: ParsedEvent['type'],
  model?: string,
  target?: string,
): string {
  if (type === 'prompt') return `LLM request ${model ?? ''}`.trim();
  if (type === 'response') return `LLM ${row.action ?? 'response'} ${model ?? ''}`.trim();
  if (type === 'file') return `${row.action ?? 'file'} ${target ?? ''}`.trim();
  if (type === 'process') return `${row.action ?? 'process'} ${target ?? row.comm ?? ''}`.trim();
  return `${row.audit_type} ${target ?? ''}`.trim();
}

function attachPromptDiff(event: ParsedEvent, history: ParsedEvent[]) {
  const previousPrompt = history[history.length - 1];
  if (!previousPrompt) return;
  event.promptDiff = {
    ...comparePrompts(previousPrompt.metadata.raw, event.metadata.raw),
    previousPromptId: previousPrompt.id,
  };
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined;
}

function isRecord(value: unknown): value is Record<string, any> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

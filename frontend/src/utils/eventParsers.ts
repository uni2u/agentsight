// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

import { Event } from '@/types/event';
import { comparePrompts } from './jsonDiff';
import {
  decodeStdioMessage,
  formatStdioExpandedContent,
  isStdioSource,
} from './stdioParser';

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

export function parseEventData(event: Event): ParsedEvent | null {
  const eventType = determineEventType(event.source, event.data);

  switch (eventType) {
    case 'prompt':
      return parsePromptEvent(event);
    case 'response':
      return parseResponseEvent(event);
    case 'ssl':
      return parseSSLEvent(event);
    case 'file':
      return parseFileEvent(event);
    case 'process':
      return parseProcessEvent(event);
    case 'stdio':
      return parseStdioEvent(event);
    default:
      return parseGenericEvent(event);
  }
}

function determineEventType(source: string, data: any): ParsedEvent['type'] {
  const sourceStr = String(source || '').toLowerCase().trim();
  const dataType = String(data?.type || '').toLowerCase().trim();
  if (sourceStr === 'system' || dataType === 'system_metrics' || dataType === 'system_wide' || dataType.includes('system')) {
    return 'system';
  }

  if (isStdioSource(source)) return 'stdio';
  if (isPromptEvent(data)) return 'prompt';
  if (isResponseEvent(source, data)) return 'response';
  if (isFileEvent(source, data)) return 'file';
  if (isProcessEvent(source, data)) return 'process';
  if (source.toLowerCase().includes('ssl') || source === 'http_parser') return 'ssl';
  return 'ssl';
}

function isPromptEvent(data: any): boolean {
  return !!(
    data.model || 
    data.messages || 
    data.prompt || 
    data.inputs ||
    data.query ||
    (data.method === 'POST' && data.message_type === 'request' && 
     (data.path?.includes('/v1/') || data.path?.includes('/api/')))
  );
}

function isResponseEvent(source: string, data: any): boolean {
  return !!(
    data.choices ||
    data.completion ||
    data.response ||
    data.sse_events ||
    data.delta ||
    data.content_block ||
    (source === 'sse_processor' && data.sse_events) ||
    (data.message_type === 'response' && (data.model || data.usage))
  );
}

function isFileEvent(source: string, data: any): boolean {
  const eventName = String(data?.event ?? '');
  return source === 'file' || 
         data?.fd !== undefined ||
         (data?.operation && ['open', 'read', 'write', 'close'].includes(data.operation)) ||
         eventName.includes('FILE_') ||
         data?.filepath !== undefined;
}

function isProcessEvent(source: string, data: any): boolean {
  const eventName = String(data?.event ?? '');
  return (source === 'process' && !eventName.includes('FILE_')) ||
         data?.exec !== undefined ||
         data?.exit !== undefined ||
         eventName === 'EXEC' ||
         eventName === 'EXIT' ||
         (data?.ppid !== undefined && !eventName.includes('FILE_'));
}

function parsePromptEvent(event: Event): ParsedEvent {
  const data = event.data;
  let model = data.model || 'AI Request';
  const method = data.method || 'POST';
  
  let displayData = data;
  if (data.body && typeof data.body === 'string') {
    try {
      const parsedBody = JSON.parse(data.body);
      if (parsedBody.model) {
        model = parsedBody.model;
      }
      displayData = { ...data, body: parsedBody };
    } catch {}
  }
  
  const content = JSON.stringify(displayData, null, 2);
  
  const parsedEvent: ParsedEvent = {
    id: event.id,
    timestamp: event.timestamp,
    type: 'prompt',
    title: `${method} ${model}`,
    content,
    metadata: { model, method, url: `${data.host || ''}${data.path || ''}`, raw: data, original_source: event.source },
  };

  return parsedEvent;
}

function parseResponseEvent(event: Event): ParsedEvent {
  const data = event.data;
  let model = data.model || 'AI Response';
  
  let displayData = data;
  if (data.sse_events && Array.isArray(data.sse_events)) {
    for (const sseEvent of data.sse_events) {
      if (sseEvent.parsed_data?.message?.model) {
        model = sseEvent.parsed_data.message.model;
        break;
      }
    }
  }

  return parsedEvent(event, 'response', model, { model, raw: data }, displayData);
}

function parseSSLEvent(event: Event): ParsedEvent {
  const data = event.data;
  
  const method = data.method || 'UNKNOWN';
  const host = data.host || data.headers?.host || 'unknown';
  const path = data.path || '/';
  const statusCode = data.status_code;
  
  let title = `${method} ${host}${path}`;
  if (statusCode) title += ` (${statusCode})`;

  return parsedEvent(event, 'ssl', title, data);
}

function parseFileEvent(event: Event): ParsedEvent {
  const data = event.data;
  const operation = data.operation || data.event || 'file op';
  const path = data.path || data.filepath || 'unknown';

  return parsedEvent(event, 'file', `${operation} ${path}`, data);
}

function parseProcessEvent(event: Event): ParsedEvent {
  const data = event.data;
  const eventType = data.event || 'process';
  const filename = data.filename;
  const title = filename ? `${eventType}: ${filename}` : `${eventType} event`;

  return parsedEvent(event, 'process', title, data);
}

function parseStdioEvent(event: Event): ParsedEvent {
  const decoded = decodeStdioMessage(event.data);

  return {
    id: event.id,
    timestamp: event.timestamp,
    type: 'stdio',
    title: decoded.title,
    content: formatStdioExpandedContent(decoded),
    metadata: {
      ...event.data,
      original_source: event.source,
      stdio_kind: decoded.kind,
      rpc_method: decoded.method,
      rpc_id: decoded.id,
      tool_name: decoded.toolName,
      summary: decoded.summary,
      parsed_payload: decoded.parsedPayload,
    },
  };
}

function parseGenericEvent(event: Event): ParsedEvent {
  return parsedEvent(event, 'ssl', `${event.source} event`, event.data);
}

function parsedEvent(
  event: Event,
  type: ParsedEvent['type'],
  title: string,
  metadata: Record<string, any>,
  contentData: any = event.data,
): ParsedEvent {
  return {
    id: event.id,
    timestamp: event.timestamp,
    type,
    title,
    content: JSON.stringify(contentData, null, 2),
    metadata: { ...metadata, original_source: event.source },
  };
}

function getEarliestTimestamp(process: ProcessNode): number {
  let earliest = process.startTimestamp ?? process.events[0]?.timestamp ?? Infinity;
  process.children.forEach(child => {
    earliest = Math.min(earliest, getEarliestTimestamp(child));
  });
  return earliest === Infinity ? 0 : earliest;
}

function isProcessNodeEvent(event: Event): boolean {
  return event.source === 'process' && event.data?.event === 'PROCESS_NODE';
}

function processEventId(event: Event): string | undefined {
  return typeof event.data?.process_id === 'string' ? event.data.process_id : undefined;
}

function isSystemEvent(event: Event): boolean {
  const source = String(event.source || '').toLowerCase().trim();
  const dataType = String(event.data?.type || '').toLowerCase().trim();
  return source === 'system' || dataType === 'system_metrics' || dataType === 'system_wide' || dataType.includes('system');
}

export function buildProcessTree(events: Event[]): ProcessNode[] {
  const processMap = new Map<string, ProcessNode>();
  const nodesByPid = new Map<number, ProcessNode[]>();
  const promptHistoryByProcess = new Map<string, ParsedEvent[]>();

  events.forEach(event => {
    if (isSystemEvent(event) || !isProcessNodeEvent(event)) {
      return;
    }
    const { pid, comm } = event;
    const id = processEventId(event);
    if (!id) {
      return;
    }
    let process = processMap.get(id);
    if (!process) {
      process = { id, pid, comm: comm || 'unknown', children: [], events: [], timeline: [] };
      processMap.set(id, process);
      nodesByPid.set(pid, [...(nodesByPid.get(pid) ?? []), process]);
    }
    process.comm = comm || process.comm;
    if (event.data.ppid) {
      process.ppid = event.data.ppid;
    }
    if (typeof event.data.start_timestamp_ms === 'number') {
      process.startTimestamp = event.data.start_timestamp_ms;
    }
    if (typeof event.data.end_timestamp_ms === 'number') {
      process.endTimestamp = event.data.end_timestamp_ms;
    }
  });

  nodesByPid.forEach(nodes => nodes.sort((a, b) => getEarliestTimestamp(a) - getEarliestTimestamp(b)));

  events.forEach(event => {
    const process = processForEvent(event, processMap, nodesByPid);
    if (isSystemEvent(event) || !process) {
      return;
    }
    const parsedEvent = parseEventData(event);
    if (parsedEvent === null) {
      return;
    }
    if (parsedEvent.type === 'prompt') {
      const history = promptHistoryByProcess.get(process.id) ?? [];
      attachPromptDiff(parsedEvent, history);
      promptHistoryByProcess.set(process.id, [...history, parsedEvent].slice(-10));
    }
    process.events.push(parsedEvent);
  });
  
  const childProcesses = new Set<string>();
  
  processMap.forEach(process => {
    const parent = parentProcess(process, nodesByPid);
    if (parent) {
      parent.children.push(process);
      childProcesses.add(process.id);
    }
  });
  
  processMap.forEach(process => {
    process.events.sort((a, b) => a.timestamp - b.timestamp);
    process.timeline = [
      ...process.events.map(event => ({ type: 'event' as const, timestamp: event.timestamp, event })),
      ...process.children.map(process => ({ type: 'process' as const, timestamp: getEarliestTimestamp(process), process })),
    ].sort((a, b) => a.timestamp - b.timestamp);
  });

  return Array.from(processMap.values())
    .filter(process => !childProcesses.has(process.id))
    .sort((a, b) => getEarliestTimestamp(a) - getEarliestTimestamp(b));
}

function processForEvent(
  event: Event,
  processMap: Map<string, ProcessNode>,
  nodesByPid: Map<number, ProcessNode[]>,
): ProcessNode | undefined {
  if (!isProcessNodeEvent(event)) {
    return lastMatching(nodesByPid.get(event.pid), process => containsTimestamp(process, event.timestamp));
  }
  const id = processEventId(event);
  return id ? processMap.get(id) : undefined;
}

function parentProcess(
  process: ProcessNode,
  nodesByPid: Map<number, ProcessNode[]>,
): ProcessNode | undefined {
  if (!process.ppid) return undefined;
  const start = getEarliestTimestamp(process);
  return lastMatching(
    nodesByPid.get(process.ppid),
    parent => parent.id !== process.id && containsTimestamp(parent, start),
  );
}

function containsTimestamp(process: ProcessNode, timestamp: number): boolean {
  return (process.startTimestamp ?? 0) <= timestamp && (process.endTimestamp === undefined || timestamp <= process.endTimestamp);
}

function lastMatching<T>(items: T[] | undefined, predicate: (item: T) => boolean): T | undefined {
  if (!items) return undefined;
  for (let i = items.length - 1; i >= 0; i--) {
    if (predicate(items[i])) return items[i];
  }
  return undefined;
}

function attachPromptDiff(event: ParsedEvent, history: ParsedEvent[]) {
  const previousPrompt = history[history.length - 1];
  if (!previousPrompt) return;
  event.promptDiff = {
    ...comparePrompts(previousPrompt.metadata.raw, event.metadata.raw),
    previousPromptId: previousPrompt.id,
  };
}

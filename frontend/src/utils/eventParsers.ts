// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

import { Event } from '@/types/event';
import { comparePrompts } from './jsonDiff';
import {
  decodeStdioMessage,
  formatStdioExpandedContent,
  isStdioSource,
} from './stdioParser';

// Store prompt history per process for diff comparison
const promptHistoryByPid = new Map<number, ParsedEvent[]>();

export interface ProcessNode {
  pid: number;
  comm: string;
  ppid?: number;
  children: ProcessNode[];
  events: ParsedEvent[];
  timeline: TimelineItem[]; // Mixed events and child processes in chronological order
  isExpanded: boolean;
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
  isExpanded: boolean;
  // For prompts, store diff with previous prompt
  promptDiff?: {
    diff: string;
    summary: string;
    hasChanges: boolean;
    previousPromptId?: string;
  };
}

// Parse different types of events
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
  // Check for system events first
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
  // Simple heuristics for AI request detection
  const hasAIRequestIndicators = 
    data.model || 
    data.messages || 
    data.prompt || 
    data.inputs ||
    data.query ||
    (data.method === 'POST' && data.message_type === 'request' && 
     (data.path?.includes('/v1/') || data.path?.includes('/api/')));
    
  return !!hasAIRequestIndicators;
}

function isResponseEvent(source: string, data: any): boolean {
  // Simple heuristics for AI response detection
  const hasAIResponseIndicators = 
    data.choices ||
    data.completion ||
    data.response ||
    data.sse_events ||
    data.delta ||
    data.content_block ||
    (source === 'sse_processor' && data.sse_events) ||
    (data.message_type === 'response' && (data.model || data.usage));
    
  return !!hasAIResponseIndicators;
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
  
  // For http_parser events, parse the body field if it exists
  let displayData = data;
  if (data.body && typeof data.body === 'string') {
    try {
      const parsedBody = JSON.parse(data.body);
      // Extract model from parsed body if available
      if (parsedBody.model) {
        model = parsedBody.model;
      }
      // Use parsed body as display data
      displayData = { ...data, body: parsedBody };
    } catch (e) {
      // Keep original data if parsing fails
    }
  }
  
  // Simply show the JSON data as-is
  const content = JSON.stringify(displayData, null, 2);
  
  const parsedEvent: ParsedEvent = {
    id: event.id,
    timestamp: event.timestamp,
    type: 'prompt',
    title: `${method} ${model}`,
    content: content,
    metadata: { model, method, url: `${data.host || ''}${data.path || ''}`, raw: data, original_source: event.source },
    isExpanded: false
  };
  
  // Get prompt history for this process
  const pid = event.pid;
  if (!promptHistoryByPid.has(pid)) {
    promptHistoryByPid.set(pid, []);
  }
  
  const history = promptHistoryByPid.get(pid)!;
  
  // If there's a previous prompt, generate diff
  if (history.length > 0) {
    const previousPrompt = history[history.length - 1];
    const diffResult = comparePrompts(previousPrompt.metadata.raw, data);
    
    parsedEvent.promptDiff = {
      ...diffResult,
      previousPromptId: previousPrompt.id
    };
  }
  
  // Add this prompt to history
  history.push(parsedEvent);
  
  // Keep only last 10 prompts per process to avoid memory issues
  if (history.length > 10) {
    history.shift();
  }
  
  return parsedEvent;
}

function parseResponseEvent(event: Event): ParsedEvent {
  const data = event.data;
  let model = data.model || 'AI Response';
  
  // For sse_processor events, extract model and enhance display
  let displayData = data;
  if (data.sse_events && Array.isArray(data.sse_events)) {
    // Look for model in SSE events
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
    isExpanded: false
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
    isExpanded: false
  };
}

// Helper function to get the earliest timestamp for a process
function getEarliestTimestamp(process: ProcessNode): number {
  let earliest = Infinity;
  
  // Check process events
  if (process.events.length > 0) {
    earliest = Math.min(earliest, process.events[0].timestamp);
  }
  
  // Check child processes recursively
  process.children.forEach(child => {
    earliest = Math.min(earliest, getEarliestTimestamp(child));
  });
  
  return earliest === Infinity ? 0 : earliest;
}

function isProcessNodeEvent(event: Event): boolean {
  return event.source === 'process' && event.data?.event === 'PROCESS_NODE';
}

function isSystemEvent(event: Event): boolean {
  const source = String(event.source || '').toLowerCase().trim();
  const dataType = String(event.data?.type || '').toLowerCase().trim();
  return source === 'system' ||
    dataType === 'system_metrics' ||
    dataType === 'system_wide' ||
    dataType.includes('system');
}

// Build process hierarchy from materialized process nodes, then attach matching events.
export function buildProcessTree(events: Event[]): ProcessNode[] {
  const processMap = new Map<number, ProcessNode>();
  const eventsByPid = new Map<number, ParsedEvent[]>();

  // Process nodes are the only source of tree structure.
  events.forEach(event => {
    if (isSystemEvent(event) || !isProcessNodeEvent(event)) {
      return;
    }
    const { pid, comm } = event;
    const process = processMap.get(pid) ?? {
      pid,
      comm: comm || 'unknown',
      children: [],
      events: [],
      timeline: [],
      isExpanded: false
    };
    process.comm = comm || process.comm;
    if (event.data.ppid) {
      process.ppid = event.data.ppid;
    }
    processMap.set(pid, process);
  });

  events.forEach(event => {
    if (isSystemEvent(event) || !processMap.has(event.pid)) {
      return;
    }
    const parsedEvent = parseEventData(event);
    if (parsedEvent === null) {
      return;
    }
    if (!eventsByPid.has(event.pid)) {
      eventsByPid.set(event.pid, []);
    }
    eventsByPid.get(event.pid)!.push(parsedEvent);
  });
  
  // Assign events to processes
  eventsByPid.forEach((events, pid) => {
    const process = processMap.get(pid);
    if (process) {
      process.events = events.sort((a, b) => a.timestamp - b.timestamp);
    }
  });
  
  // Build tree structure
  const rootProcesses: ProcessNode[] = [];
  const childProcesses = new Set<number>();
  
  processMap.forEach((process, pid) => {
    if (process.ppid && processMap.has(process.ppid)) {
      const parent = processMap.get(process.ppid)!;
      parent.children.push(process);
      childProcesses.add(pid);
    }
  });
  
  // Build timeline for each process (mix events and child processes chronologically)
  processMap.forEach(process => {
    const timelineItems: TimelineItem[] = [];
    
    // Add all events as timeline items
    process.events.forEach(event => {
      timelineItems.push({
        type: 'event',
        timestamp: event.timestamp,
        event
      });
    });
    
    // Add child processes as timeline items (using their earliest timestamp)
    process.children.forEach(child => {
      timelineItems.push({
        type: 'process',
        timestamp: getEarliestTimestamp(child),
        process: child
      });
    });
    
    // Sort timeline by timestamp
    process.timeline = timelineItems.sort((a, b) => a.timestamp - b.timestamp);
  });
  
  // Root processes are those without parents
  processMap.forEach((process, pid) => {
    if (!childProcesses.has(pid)) {
      rootProcesses.push(process);
    }
  });
  
  // Sort root processes by their earliest timestamp
  return rootProcesses.sort((a, b) => getEarliestTimestamp(a) - getEarliestTimestamp(b));
}

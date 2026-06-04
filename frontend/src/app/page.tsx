// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

'use client';

import { useState, useEffect } from 'react';
import { LogView } from '@/components/LogView';
import { TimelineView } from '@/components/TimelineView';
import { ProcessTreeView } from '@/components/ProcessTreeView';
import { ResourceMetricsView } from '@/components/ResourceMetricsView';
import { UploadPanel } from '@/components/UploadPanel';
import { LanguageSwitcher } from '@/components/common/LanguageSwitcher';
import { useTranslation } from '@/i18n';
import { Event } from '@/types/event';

type ViewMode = 'log' | 'timeline' | 'process-tree' | 'metrics';

interface SnapshotTokenSummary {
  group: string;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  calls?: number;
}

interface SnapshotNetworkTarget {
  pid?: number | null;
  comm?: string | null;
  host: string;
  path?: string | null;
  count?: number;
  error_count?: number;
  first_timestamp_ms?: number | null;
  last_timestamp_ms?: number | null;
}

interface SnapshotAuditEvent {
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
  details?: Record<string, unknown> | null;
}

interface SnapshotProcessNode {
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

interface SnapshotSession {
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
  attributes?: Record<string, unknown> | null;
}

interface AgentSightSnapshot {
  schema_version?: number;
  generated_at?: string;
  summary?: Record<string, unknown>;
  token_summary?: SnapshotTokenSummary[];
  network_targets?: SnapshotNetworkTarget[];
  process_nodes?: SnapshotProcessNode[];
  audit_events?: SnapshotAuditEvent[];
  sessions?: SnapshotSession[];
}

function snapshotToEvents(snapshot: AgentSightSnapshot): Event[] {
  return [
    ...materializedAuditEvents(snapshot.audit_events),
    ...materializedProcessNodeEvents(snapshot.process_nodes),
    ...materializedNetworkEvents(snapshot.network_targets),
    ...materializedSessionEvents(snapshot.sessions),
    ...materializedTokenEvents(snapshot.token_summary, snapshot.generated_at),
  ].sort((a, b) => a.timestamp - b.timestamp);
}

function materializedAuditEvents(rows?: SnapshotAuditEvent[]): Event[] {
  if (!Array.isArray(rows)) return [];
  return rows
    .filter(row => typeof row.timestamp_ms === 'number')
    .map(row => {
      const details = isRecord(row.details) ? row.details : {};
      const eventName = auditEventName(row);
      const target = row.target ?? undefined;
      return {
        id: row.id,
        timestamp: row.timestamp_ms,
        source: row.audit_type,
        pid: row.pid ?? 0,
        comm: row.comm ?? row.subject ?? '',
        data: {
          ...details,
          event: eventName,
          audit_type: row.audit_type,
          action: row.action,
          target,
          status: row.status,
          summary: row.summary,
          subject: row.subject,
          filename: row.audit_type === 'process' ? target : details.filename,
          filepath: row.audit_type === 'file' ? target : details.filepath,
          path: row.audit_type === 'file' ? target : details.path,
        },
      };
    });
}

function materializedProcessNodeEvents(rows?: SnapshotProcessNode[]): Event[] {
  if (!Array.isArray(rows)) return [];
  return rows
    .filter(row => typeof row.pid === 'number')
    .map(row => ({
      id: `process-node-${row.id}-${row.start_timestamp_ms ?? row.end_timestamp_ms ?? 0}`,
      timestamp: row.start_timestamp_ms ?? row.end_timestamp_ms ?? 0,
      source: 'process',
      pid: row.pid,
      comm: row.comm ?? '',
      data: {
        event: 'PROCESS_NODE',
        process_id: row.id,
        ppid: row.ppid,
        root_pid: row.root_pid,
        filename: row.command,
        command: row.command,
        argv: row.argv ?? [],
        cwd: row.cwd,
        exit_code: row.exit_code,
        status: row.status,
        start_timestamp_ms: row.start_timestamp_ms,
        end_timestamp_ms: row.end_timestamp_ms,
      },
    }));
}

function materializedNetworkEvents(rows?: SnapshotNetworkTarget[]): Event[] {
  if (!Array.isArray(rows)) return [];
  return rows.map((row, index) => ({
    id: `network-${row.pid ?? 0}-${row.host}-${row.path ?? ''}-${index}`,
    timestamp: row.last_timestamp_ms ?? row.first_timestamp_ms ?? 0,
    source: 'network',
    pid: row.pid ?? 0,
    comm: row.comm ?? '',
    data: {
      event: 'NETWORK_TARGET',
      host: row.host,
      path: row.path,
      count: row.count ?? 0,
      error_count: row.error_count ?? 0,
      first_timestamp_ms: row.first_timestamp_ms,
      last_timestamp_ms: row.last_timestamp_ms,
    },
  }));
}

function materializedSessionEvents(rows?: SnapshotSession[]): Event[] {
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

function materializedTokenEvents(rows?: SnapshotTokenSummary[], generatedAt?: string): Event[] {
  if (!Array.isArray(rows)) return [];
  const timestamp = generatedAt ? Date.parse(generatedAt) || 0 : 0;
  return rows.map(row => ({
    id: `tokens-${row.group}`,
    timestamp,
    source: 'token',
    pid: 0,
    comm: row.group,
    data: {
      event: 'TOKEN_SUMMARY',
      model: row.group,
      input_tokens: row.input_tokens ?? 0,
      output_tokens: row.output_tokens ?? 0,
      total_tokens: row.total_tokens ?? 0,
      calls: row.calls ?? 0,
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseContentEvents(content: string): Event[] {
  return parseSnapshotContent(content) ?? parseJsonlEvents(content);
}

function parseSnapshotContent(content: string): Event[] | null {
  const trimmed = content.trim();
  if (!trimmed.startsWith('{')) {
    return null;
  }

  try {
    const parsed = JSON.parse(trimmed) as AgentSightSnapshot;
    if (!parsed || parsed.schema_version !== 1 || !isSnapshotPayload(parsed)) {
      return null;
    }
    return snapshotToEvents(parsed);
  } catch {
    return null;
  }
}

function isSnapshotPayload(snapshot: AgentSightSnapshot): boolean {
  return Array.isArray(snapshot.audit_events)
    || Array.isArray(snapshot.process_nodes)
    || Array.isArray(snapshot.network_targets)
    || Array.isArray(snapshot.sessions)
    || Array.isArray(snapshot.token_summary);
}

function parseJsonlEvents(content: string): Event[] {
  const events: Event[] = [];
  content.split('\n').forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    try {
      events.push(...jsonLineToEvents(JSON.parse(trimmed), index));
    } catch {
      // Ignore malformed lines; empty output below reports a user-facing error.
    }
  });
  return events.sort((a, b) => a.timestamp - b.timestamp);
}

function jsonLineToEvents(value: unknown, index: number): Event[] {
  if (!isRecord(value)) return [];
  if (typeof value.timestamp === 'number' && typeof value.source === 'string' && isRecord(value.data)) {
    return [{
      id: typeof value.id === 'string' ? value.id : `${value.source}-${value.timestamp}-${index}`,
      timestamp: value.timestamp,
      source: value.source,
      pid: typeof value.pid === 'number' ? value.pid : 0,
      comm: typeof value.comm === 'string' ? value.comm : '',
      data: value.data,
    }];
  }
  if (typeof value.kind === 'string' && isRecord(value.row)) {
    return viewUpdateToEvents(value.kind, value.row, index);
  }
  return [];
}

function viewUpdateToEvents(kind: string, row: Record<string, unknown>, index: number): Event[] {
  const r = row as any;
  switch (kind) {
    case 'audit_event':
      return materializedAuditEvents([r]);
    case 'process_node':
      return materializedProcessNodeEvents([r]);
    case 'network_target':
      return materializedNetworkEvents([r]);
    case 'session':
      return materializedSessionEvents([r]);
    case 'token_usage':
      return materializedTokenEvents([{
        group: String(r.model ?? r.provider ?? r.comm ?? `pid:${r.pid ?? 0}`),
        input_tokens: r.input_tokens,
        output_tokens: r.output_tokens,
        total_tokens: r.total_tokens,
        calls: 1,
      }], new Date(r.timestamp_ms ?? Date.now()).toISOString());
    case 'llm_call':
      return materializedAuditEvents([{
        id: `audit-${r.id ?? index}`,
        timestamp_ms: r.end_timestamp_ms ?? r.start_timestamp_ms ?? 0,
        audit_type: 'llm',
        pid: r.pid,
        comm: r.comm,
        subject: r.model,
        action: 'call',
        target: r.host,
        status: typeof r.status_code === 'number' && r.status_code >= 400 ? 'failure' : 'success',
        summary: 'LLM call',
        details: r.response ?? r.request ?? {},
      }]);
    case 'tool_call':
    case 'resource_sample':
      return [{
        id: `${kind}-${r.id ?? r.timestamp_ms ?? index}`,
        timestamp: r.timestamp_ms ?? r.end_timestamp_ms ?? r.start_timestamp_ms ?? 0,
        source: kind === 'tool_call' ? 'tool' : 'system',
        pid: r.pid ?? r.related_pid ?? 0,
        comm: r.comm ?? '',
        data: { ...r, event: kind.toUpperCase() },
      }];
    default:
      return [];
  }
}

export default function Home() {
  const { t } = useTranslation();
  const [file, setFile] = useState<File | null>(null);
  const [logContent, setLogContent] = useState<string>('');
  const [events, setEvents] = useState<Event[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('timeline');
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string>('');
  const [isParsed, setIsParsed] = useState(false);
  const [showUploadPanel, setShowUploadPanel] = useState(false);

  const loadEvents = (content: string, nextEvents: Event[], emptyMessage: string) => {
    if (nextEvents.length === 0) {
      setError(emptyMessage);
      return false;
    }
    setLogContent(content);
    setEvents(nextEvents);
    setIsParsed(true);
    setShowUploadPanel(false);
    localStorage.setItem('agent-tracer-log', content);
    localStorage.setItem('agent-tracer-events', JSON.stringify(nextEvents));
    return true;
  };

  const parseLogContent = (content: string) => {
    if (!content.trim()) {
      setError('Empty log content');
      return;
    }

    setLoading(true);
    setError('');

    try {
      loadEvents(content, parseContentEvents(content), 'No valid events found in the log file');
    } catch (err) {
      setError(`Failed to parse log content: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  const syncData = async () => {
    setSyncing(true);
    setError('');

    try {
      const snapshotResponse = await fetch('/api/v1/snapshot?event_limit=50000&audit_limit=50000');
      if (!snapshotResponse.ok) {
        throw new Error(`/api/v1/snapshot ${snapshotResponse.status} ${snapshotResponse.statusText}`);
      }
      const snapshot = await snapshotResponse.json() as AgentSightSnapshot;
      const snapshotEvents = snapshotToEvents(snapshot);
      const content = JSON.stringify(snapshot, null, 2);
      loadEvents(content, snapshotEvents, 'No events received from server');
    } catch (err) {
      setError(`Failed to sync data: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setSyncing(false);
    }
  };

  // Load data from localStorage on component mount; if none, fall back to the
  // bundled sample trace so the public demo shows real data on first visit.
  useEffect(() => {
    const savedContent = localStorage.getItem('agent-tracer-log');
    const savedEvents = localStorage.getItem('agent-tracer-events');

    if (savedContent && savedEvents) {
      setLogContent(savedContent);
      setEvents(JSON.parse(savedEvents));
      setIsParsed(true);
      return;
    }

    // No saved data: try to auto-load the bundled sample trace so the public
    // demo isn't empty on first visit. The file is copied into the static
    // export at build time (see the Pages deploy workflow). basePath-aware so
    // it works both at the domain root and under a project sub-path.
    const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? '';
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`${basePath}/sample-trace.log`);
        if (!res.ok) return; // No sample available (e.g. local dev) - keep empty state.
        const content = await res.text();
        if (cancelled || !content.trim()) return;
        const sampleEvents = parseContentEvents(content);
        if (sampleEvents.length === 0) return;
        setLogContent(content);
        setEvents(sampleEvents);
        setIsParsed(true);
        localStorage.setItem('agent-tracer-log', content);
        localStorage.setItem('agent-tracer-events', JSON.stringify(sampleEvents));
      } catch {
        // Network / static-host hiccup: silently keep the empty state.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFile = event.target.files?.[0];
    if (uploadedFile) {
      setFile(uploadedFile);
      setError('');
      setIsParsed(false);
      
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setLogContent(content);
      };
      reader.readAsText(uploadedFile);
    }
  };

  const handleTextPaste = (content: string) => {
    setLogContent(content);
    setIsParsed(false);
    setError('');
  };

  const clearData = () => {
    setFile(null);
    setLogContent('');
    setEvents([]);
    setError('');
    setIsParsed(false);
    localStorage.removeItem('agent-tracer-log');
    localStorage.removeItem('agent-tracer-events');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-end mb-4">
            <LanguageSwitcher />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            {t('app.title')}
          </h1>
          <p className="text-gray-600">
            {t('app.subtitle')}
          </p>
        </div>

        {/* Upload Panel */}
        {showUploadPanel && (
          <UploadPanel
            logContent={logContent}
            loading={loading}
            error={error}
            onFileUpload={handleFileUpload}
            onTextPaste={handleTextPaste}
            onParseLog={() => parseLogContent(logContent)}
          />
        )}

        {/* Main Content - Always show */}
        <div className="space-y-6">
          {/* Controls */}
          <div className="bg-white rounded-lg shadow-md p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                <div className="text-sm text-gray-600">
                  <span className="font-medium">{t('app.eventsLoaded', { count: events.length })}</span>
                </div>
                
                {file && (
                  <div className="text-sm text-gray-600">
                    {t('app.file')} <span className="font-medium">{file.name}</span>
                  </div>
                )}
                
                {syncing && (
                  <div className="flex items-center text-sm text-blue-600">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600 mr-2"></div>
                    {t('app.syncing')}
                  </div>
                )}
              </div>
              
              <div className="flex flex-wrap items-center gap-2 lg:gap-4">
                {/* View Mode Toggle */}
                <div className="flex flex-wrap rounded-lg border border-gray-200 p-1">
                  <button
                    onClick={() => setViewMode('log')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'log'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.logView')}
                  </button>
                  <button
                    onClick={() => setViewMode('timeline')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'timeline'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.timelineView')}
                  </button>
                  <button
                    onClick={() => setViewMode('process-tree')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'process-tree'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.processTree')}
                  </button>
                  <button
                    onClick={() => setViewMode('metrics')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'metrics'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.metrics')}
                  </button>
                </div>
                
                {/* Action Buttons */}
                <button
                  onClick={() => setShowUploadPanel(!showUploadPanel)}
                  className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-md transition-colors border border-gray-300"
                >
                  {showUploadPanel ? t('app.hideLog') : t('app.uploadLog')}
                </button>
                
                <button
                  onClick={syncData}
                  disabled={syncing}
                  className="px-4 py-2 text-sm text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded-md transition-colors border border-blue-300 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {t('app.syncData')}
                </button>
                
                <button
                  onClick={clearData}
                  className="px-4 py-2 text-sm text-red-600 hover:text-red-700 hover:bg-red-50 rounded-md transition-colors"
                >
                  {t('app.clearData')}
                </button>
              </div>
            </div>
          </div>

          {/* View Content */}
          {events.length > 0 ? (
            viewMode === 'log' ? (
              <LogView events={events} />
            ) : viewMode === 'timeline' ? (
              <TimelineView events={events} />
            ) : viewMode === 'process-tree' ? (
              <ProcessTreeView events={events} />
            ) : (
              <ResourceMetricsView events={events} />
            )
          ) : (
            <div className="bg-white rounded-lg shadow-md p-12 text-center">
              <div className="text-gray-500">
                {syncing ? (
                  <div className="flex flex-col items-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mb-4"></div>
                    <p className="text-lg">{t('app.loadingEvents')}</p>
                  </div>
                ) : (
                  <>
                    <p className="text-lg mb-4">{t('app.noEventsLoaded')}</p>
                    <div className="space-x-4">
                      <button
                        onClick={syncData}
                        className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors"
                      >
                        {t('app.syncFromServer')}
                      </button>
                      <button
                        onClick={() => setShowUploadPanel(true)}
                        className="px-6 py-3 bg-gray-600 text-white font-semibold rounded-lg hover:bg-gray-700 transition-colors"
                      >
                        {t('app.uploadLogFile')}
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { LogView } from '@/components/LogView';
import { TimelineView } from '@/components/TimelineView';
import { ProcessTreeView } from '@/components/ProcessTreeView';
import { ResourceMetricsView } from '@/components/ResourceMetricsView';
import { LanguageSwitcher } from '@/components/common/LanguageSwitcher';
import { useTranslation } from '@/i18n';
import {
  AgentSightSnapshot,
  snapshotEventCount,
  snapshotToViewEvents,
} from '@/types/event';

type ViewMode = 'log' | 'timeline' | 'process-tree' | 'metrics';

export default function Home() {
  const { t } = useTranslation();
  const [snapshot, setSnapshot] = useState<AgentSightSnapshot | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('timeline');
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string>('');

  const viewEvents = useMemo(() => snapshotToViewEvents(snapshot), [snapshot]);
  const eventCount = snapshotEventCount(snapshot);

  const syncData = useCallback(async () => {
    setSyncing(true);
    setError('');

    try {
      const response = await fetch('/api/v1/snapshot?audit_limit=50000');
      if (!response.ok) {
        throw new Error(`/api/v1/snapshot ${response.status} ${response.statusText}`);
      }
      setSnapshot(await response.json() as AgentSightSnapshot);
    } catch (err) {
      setError(`Failed to sync data: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setSyncing(false);
    }
  }, []);

  useEffect(() => {
    void syncData();
  }, [syncData]);

  const clearData = () => {
    setSnapshot(null);
    setError('');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
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

        <div className="space-y-6">
          <div className="bg-white rounded-lg shadow-md p-4">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                <div className="text-sm text-gray-600">
                  <span className="font-medium">{t('app.eventsLoaded', { count: eventCount })}</span>
                </div>

                {syncing && (
                  <div className="flex items-center text-sm text-blue-600">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600 mr-2"></div>
                    {t('app.syncing')}
                  </div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 lg:gap-4">
                <div className="flex flex-wrap rounded-lg border border-gray-200 p-1">
                  {(['log', 'timeline', 'process-tree', 'metrics'] as ViewMode[]).map(mode => (
                    <button
                      key={mode}
                      onClick={() => setViewMode(mode)}
                      className={`px-3 py-1 text-sm rounded-md transition-colors ${
                        viewMode === mode
                          ? 'bg-blue-600 text-white'
                          : 'text-gray-600 hover:bg-gray-100'
                      }`}
                    >
                      {mode === 'log'
                        ? t('app.logView')
                        : mode === 'timeline'
                          ? t('app.timelineView')
                          : mode === 'process-tree'
                            ? t('app.processTree')
                            : t('app.metrics')}
                    </button>
                  ))}
                </div>

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

            {error && (
              <div className="mt-4 p-3 bg-red-50 border border-red-200 rounded-md text-sm text-red-700">
                {error}
              </div>
            )}
          </div>

          {eventCount > 0 ? (
            viewMode === 'log' ? (
              <LogView events={viewEvents} />
            ) : viewMode === 'timeline' ? (
              <TimelineView events={viewEvents} />
            ) : viewMode === 'process-tree' ? (
              <ProcessTreeView snapshot={snapshot} />
            ) : (
              <ResourceMetricsView samples={snapshot?.resource_samples ?? []} />
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
                    <button
                      onClick={syncData}
                      className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors"
                    >
                      {t('app.syncFromServer')}
                    </button>
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

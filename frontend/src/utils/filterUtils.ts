// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

import { ParsedEvent, ProcessNode } from './eventParsers';
import { ProcessTreeFilters } from '@/components/process-tree/ProcessTreeFilters';

export function extractFilterOptions(processTree: ProcessNode[]) {
  const eventTypes = new Set<string>();
  const models = new Set<string>();
  const sources = new Set<string>();
  const commands = new Set<string>();

  const visit = (process: ProcessNode) => {
    if (process.comm) {
      commands.add(process.comm);
    }
    process.events.forEach(event => {
      eventTypes.add(event.type);
      sources.add(event.metadata?.original_source || sourceForEventType(event.type));
      if (event.type === 'prompt' || event.type === 'response') {
        const model = event.metadata?.model;
        if (model && model !== 'Unknown Model') {
          models.add(model);
        }
      }
    });
    process.children.forEach(visit);
  };

  processTree.forEach(visit);

  return {
    eventTypes: Array.from(eventTypes).sort(),
    models: Array.from(models).sort(),
    sources: Array.from(sources).sort(),
    commands: Array.from(commands).sort()
  };
}

function parsedEventMatchesFilters(
  event: ParsedEvent,
  source: string,
  comm: string,
  data: unknown,
  filters: ProcessTreeFilters,
): boolean {
  if (filters.eventTypes.length > 0 && !filters.eventTypes.includes(event.type)) {
    return false;
  }
  
  if (filters.sources.length > 0 && !filters.sources.includes(source)) {
    return false;
  }
  
  if (filters.commands.length > 0 && (!comm || !filters.commands.includes(comm))) {
    return false;
  }
  
  if (filters.models.length > 0) {
    const model = event.metadata?.model;
    if (!model || !filters.models.includes(model)) {
      return false;
    }
  }
  
  if (filters.timeRange.start && event.timestamp < filters.timeRange.start) {
    return false;
  }
  
  if (filters.timeRange.end && event.timestamp > filters.timeRange.end) {
    return false;
  }
  
  if (filters.searchText) {
    const searchLower = filters.searchText.toLowerCase();
    const searchableText = [
      event.title,
      event.content,
      comm,
      source,
      event.metadata?.model,
      JSON.stringify(data)
    ].filter(Boolean).join(' ').toLowerCase();
    
    if (!searchableText.includes(searchLower)) {
      return false;
    }
  }
  
  return true;
}

export function filterProcessTree(processTree: ProcessNode[], filters: ProcessTreeFilters): ProcessNode[] {
  return processTree.map(process => {
    const filteredEvents = process.events.filter(event => {
      const source = event.metadata?.original_source || sourceForEventType(event.type);
      return parsedEventMatchesFilters(event, source, process.comm, event.metadata, filters);
    });
    
    const filteredChildren = filterProcessTree(process.children, filters);
    
    if (filteredEvents.length > 0 || filteredChildren.length > 0) {
      return {
        ...process,
        events: filteredEvents,
        children: filteredChildren
      };
    }
    
    return null;
  }).filter((process): process is ProcessNode => process !== null);
}

function sourceForEventType(type: ParsedEvent['type']): string {
  if (type === 'prompt' || type === 'response') return 'http_parser';
  if (type === 'stdio') return 'stdio';
  if (type === 'file' || type === 'process') return 'process';
  return 'ssl';
}

export function getTotalEventCount(processTree: ProcessNode[]): number {
  return processTree.reduce((total, process) => {
    return total + process.events.length + getTotalEventCount(process.children);
  }, 0);
}

export function createDefaultFilters(): ProcessTreeFilters {
  return {
    eventTypes: [],
    models: [],
    sources: [],
    commands: [],
    searchText: '',
    timeRange: {}
  };
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

import type { en } from './en';

type TranslationKey = keyof typeof en;

export const ko: Record<TranslationKey, string> = {
  // App
  'app.title': 'AgentSight 분석기',
  'app.subtitle': '에이전트 활동의 실시간 물질화 뷰를 살펴봅니다',
  'app.eventsLoaded': '{count}개 이벤트 로드됨',
  'app.syncing': '동기화 중...',
  'app.logView': '로그 보기',
  'app.timelineView': '타임라인 보기',
  'app.processTree': '프로세스 트리',
  'app.metrics': '메트릭',
  'app.syncData': '데이터 동기화',
  'app.clearData': '데이터 지우기',
  'app.loadingEvents': '서버에서 이벤트를 불러오는 중...',
  'app.noEventsLoaded': '로드된 이벤트가 없습니다',
  'app.syncFromServer': '서버에서 데이터 동기화',

  // Modal
  'modal.eventDetails': '이벤트 상세',
  'modal.id': 'ID',
  'modal.source': '소스',
  'modal.process': '프로세스',
  'modal.pid': 'PID',
  'modal.time': '시간',
  'modal.timestamp': '타임스탬프',
  'modal.unixTimestamp': 'Unix 타임스탬프',
  'modal.decodedStdio': '디코딩된 표준 I/O',
  'modal.direction': '방향',
  'modal.fdRole': 'FD 역할',
  'modal.kind': '종류',
  'modal.messageId': '메시지 ID',
  'modal.method': '메서드',
  'modal.tool': '도구',
  'modal.rawData': '원시 데이터',

  // Filters
  'filter.searchEvents': '이벤트 검색...',
  'filter.allSources': '모든 소스',
  'filter.allProcesses': '모든 프로세스',
  'filter.allPids': '모든 PID',
  'filter.pid': 'PID {pid}',

  // Process Tree
  'processTree.title': '프로세스 트리 및 AI 프롬프트',
  'processTree.subtitle': '프로세스와 AI 프롬프트, API 호출을 계층형으로 표시합니다',
  'processTree.noProcesses': '표시할 프로세스가 없습니다',
  'processTree.noMatch': '현재 필터와 일치하는 프로세스가 없습니다',

  // Process Tree Filters
  'processTree.filters': '필터',
  'processTree.active': '활성',
  'processTree.aiOnly': 'AI만',
  'processTree.filesOnly': '파일만',
  'processTree.processesOnly': '프로세스만',
  'processTree.showing': '이벤트 {total}개 중 {filtered}개 표시',
  'processTree.clearAll': '모두 지우기',
  'processTree.search': '검색',
  'processTree.searchPlaceholder': '내용, 모델, 명령 검색...',
  'processTree.eventTypes': '이벤트 유형',
  'processTree.aiModels': 'AI 모델',
  'processTree.sources': '소스',
  'processTree.commands': '명령',
  'processTree.timeRange': '시간 범위',
  'processTree.to': '까지',

  // Badges
  'badge.prompt_one': '프롬프트 {count}개',
  'badge.prompt_other': '프롬프트 {count}개',
  'badge.response_one': '응답 {count}개',
  'badge.response_other': '응답 {count}개',
  'badge.ssl': 'SSL {count}개',
  'badge.file_one': '파일 {count}개',
  'badge.file_other': '파일 {count}개',
  'badge.process': '프로세스 {count}개',
  'badge.stdio': '표준 I/O {count}개',

  // Tags
  'tag.aiPrompt': 'AI 프롬프트',
  'tag.aiResponse': 'AI 응답',
  'tag.changed': '변경됨',
  'tag.ssl': 'SSL',
  'tag.stdio': '표준 I/O',

  // Resource Metrics
  'metrics.noData': '사용 가능한 시스템 리소스 메트릭이 없습니다',
  'metrics.noDataHint': '--system 플래그 또는 record 명령을 사용할 때 시스템 메트릭이 수집됩니다',
  'metrics.title': '리소스 메트릭',
  'metrics.cpu': 'CPU',
  'metrics.memory': '메모리',
  'metrics.allProcesses': '모든 프로세스({count}개 샘플)',
  'metrics.processOption': '{comm}(PID {pid}) - {count}개 샘플',
  'metrics.avgCpu': '평균 CPU',
  'metrics.peakCpu': '최대 CPU',
  'metrics.avgMemory': '평균 메모리',
  'metrics.peakMemory': '최대 메모리',
  'metrics.cpuOverTime': '시간별 CPU 사용량',
  'metrics.memoryOverTime': '시간별 메모리 사용량',
  'metrics.dataPoints': '데이터 포인트 {count}개',
  'metrics.detailedMetrics': '상세 메트릭',
  'metrics.table.time': '시간',
  'metrics.table.process': '프로세스',
  'metrics.table.pid': 'PID',
  'metrics.table.cpuPercent': 'CPU %',
  'metrics.table.memoryRss': '메모리(RSS)',

  // Timeline
  'timeline.title': '타임라인 보기',
  'timeline.durationInfo': '기간: {duration} - 이벤트 {count}개',
  'timeline.zoomHelp': '마우스 휠 + Ctrl/Cmd 또는 Ctrl/Cmd + +/- 키로 확대/축소합니다. Ctrl/Cmd + 0으로 초기화합니다.',
  'timeline.scrollHelp': '확대된 상태에서는 마우스 휠이나 방향키로 스크롤합니다.',
  'timeline.noEvents': '표시할 이벤트가 없습니다',
  'timeline.eventDetails': '타임라인 이벤트 상세',

  // Zoom Controls
  'timeline.zoomOut': '축소',
  'timeline.zoomIn': '확대',
  'timeline.resetZoom': '확대/축소 초기화',
  'timeline.reset': '초기화',
  'timeline.scrollLeft': '왼쪽으로 스크롤',
  'timeline.scroll': '스크롤',
  'timeline.scrollRight': '오른쪽으로 스크롤',

  // Timeline Minimap
  'timeline.overview': '타임라인 개요',
  'timeline.scrolled': '{percent}% 스크롤됨',

  // Timeline ScrollBar
  'timeline.scrollPosition': '스크롤 위치',

  // Log
  'log.noEvents': '현재 필터와 일치하는 이벤트가 없습니다.',
  'log.eventDetails': '로그 이벤트 상세',
};


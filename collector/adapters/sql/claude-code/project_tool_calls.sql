INSERT OR REPLACE INTO tool_calls (
  id, session_id, conversation_id, timestamp_ms, tool_name, tool_call_id,
  status, input_json, output_json, related_pid, related_event_id, adapter_id,
  confidence
)
SELECT
  'claude-tool-' || c.id || '-' || COALESCE(json_extract(e.value, '$.parsed_data.content_block.id'), e.key),
  'claude-code-pid-' || c.pid,
  'claude-conv-' || c.id,
  COALESCE(c.end_timestamp_ms, c.start_timestamp_ms),
  json_extract(e.value, '$.parsed_data.content_block.name'),
  json_extract(e.value, '$.parsed_data.content_block.id'),
  'observed',
  COALESCE(json_extract(e.value, '$.parsed_data.content_block.input'), '{}'),
  NULL,
  c.pid,
  c.response_event_id,
  'claude-code',
  0.85
FROM llm_calls c,
     json_each(c.response_body_json, '$.sse_events') AS e
WHERE c.response_body_json IS NOT NULL
  AND json_extract(e.value, '$.parsed_data.content_block.type') = 'tool_use';

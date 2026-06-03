INSERT OR REPLACE INTO tool_calls (
  id, session_id, conversation_id, timestamp_ms, tool_name, tool_call_id,
  start_timestamp_ms, end_timestamp_ms, duration_ms, status, input_json,
  output_json, related_pid, related_event_id, adapter_id, confidence
)
WITH tool_uses AS (
  SELECT
    c.id AS llm_call_id,
    c.pid AS pid,
    c.response_event_id AS response_event_id,
    COALESCE(c.end_timestamp_ms, c.start_timestamp_ms) AS start_ms,
    json_extract(e.value, '$.parsed_data.content_block.name') AS tool_name,
    json_extract(e.value, '$.parsed_data.content_block.id') AS tool_call_id,
    COALESCE(json_extract(e.value, '$.parsed_data.content_block.input'), '{}') AS input_json,
    e.key AS event_key
  FROM llm_calls c,
       json_each(c.response_body_json, '$.sse_events') AS e
  WHERE c.response_body_json IS NOT NULL
    AND json_extract(e.value, '$.parsed_data.content_block.type') = 'tool_use'
),
tool_results AS (
  SELECT
    c.start_timestamp_ms AS result_ms,
    json_extract(content.value, '$.tool_use_id') AS tool_call_id,
    content.value AS output_json
  FROM llm_calls c,
       json_each(c.request_body_json, '$.messages') AS msg,
       json_each(
         CASE
           WHEN json_type(msg.value, '$.content') = 'array'
           THEN json_extract(msg.value, '$.content')
           ELSE '[]'
         END
       ) AS content
  WHERE c.request_body_json IS NOT NULL
    AND json_extract(content.value, '$.type') = 'tool_result'
),
matched AS (
  SELECT
    u.*,
    (
      SELECT MIN(r.result_ms)
      FROM tool_results r
      WHERE r.tool_call_id = u.tool_call_id
        AND r.result_ms >= u.start_ms
    ) AS end_ms,
    (
      SELECT r.output_json
      FROM tool_results r
      WHERE r.tool_call_id = u.tool_call_id
        AND r.result_ms >= u.start_ms
      ORDER BY r.result_ms
      LIMIT 1
    ) AS output_json
  FROM tool_uses u
)
SELECT
  'claude-tool-' || llm_call_id || '-' || COALESCE(tool_call_id, event_key),
  'claude-code-pid-' || pid,
  'claude-conv-' || llm_call_id,
  start_ms,
  tool_name,
  tool_call_id,
  start_ms,
  end_ms,
  CASE WHEN end_ms IS NOT NULL THEN end_ms - start_ms ELSE NULL END,
  CASE WHEN end_ms IS NOT NULL THEN 'completed' ELSE 'observed' END,
  input_json,
  output_json,
  pid,
  response_event_id,
  'claude-code',
  0.85
FROM matched;

INSERT OR REPLACE INTO tool_calls (
  id, session_id, conversation_id, timestamp_ms, tool_name, tool_call_id,
  start_timestamp_ms, end_timestamp_ms, duration_ms, status, input_json,
  output_json, related_pid, related_event_id, adapter_id, confidence
)
WITH structured AS (
  SELECT
    c.id AS event_id,
    c.timestamp_ms AS end_ms,
    c.pid,
    c.comm,
    e.key AS event_key,
    json_extract(e.value, '$.tool_name') AS tool_name,
    json_extract(e.value, '$.request_id') AS request_id,
    CAST(json_extract(e.value, '$.duration_ms') AS INTEGER) AS duration_ms,
    CAST(json_extract(e.value, '$.tool_input_size_bytes') AS INTEGER) AS input_size_bytes,
    CAST(json_extract(e.value, '$.tool_result_size_bytes') AS INTEGER) AS result_size_bytes,
    0.75 AS confidence
  FROM canonical_events c,
       json_each(json_extract(c.attributes_json, '$.body')) AS e
  WHERE c.kind = 'http.request'
    AND c.host LIKE '%datadoghq.com'
    AND json_valid(json_extract(c.attributes_json, '$.body'))
    AND json_extract(e.value, '$.message') = 'tengu_tool_use_success'
),
raw_events AS (
  SELECT
    c.id AS event_id,
    c.timestamp_ms AS end_ms,
    c.pid,
    c.comm,
    json_extract(c.attributes_json, '$.data') AS body
  FROM canonical_events c
  WHERE c.source = 'ssl'
    AND json_extract(c.attributes_json, '$.data') LIKE '%"message":"tengu_tool_use_success"%'
),
raw_parsed AS (
  SELECT
    event_id,
    end_ms,
    pid,
    comm,
    '0' AS event_key,
    CASE WHEN instr(body, '"tool_name":"') > 0
      THEN substr(
        substr(body, instr(body, '"tool_name":"') + length('"tool_name":"')),
        1,
        instr(substr(body, instr(body, '"tool_name":"') + length('"tool_name":"')), '"') - 1
      )
      ELSE NULL END AS tool_name,
    CASE WHEN instr(body, '"request_id":"') > 0
      THEN substr(
        substr(body, instr(body, '"request_id":"') + length('"request_id":"')),
        1,
        instr(substr(body, instr(body, '"request_id":"') + length('"request_id":"')), '"') - 1
      )
      ELSE NULL END AS request_id,
    CASE WHEN instr(body, '"duration_ms":') > 0
      THEN CAST(substr(body, instr(body, '"duration_ms":') + length('"duration_ms":')) AS INTEGER)
      ELSE NULL END AS duration_ms,
    CASE WHEN instr(body, '"tool_input_size_bytes":') > 0
      THEN CAST(substr(body, instr(body, '"tool_input_size_bytes":') + length('"tool_input_size_bytes":')) AS INTEGER)
      ELSE NULL END AS input_size_bytes,
    CASE WHEN instr(body, '"tool_result_size_bytes":') > 0
      THEN CAST(substr(body, instr(body, '"tool_result_size_bytes":') + length('"tool_result_size_bytes":')) AS INTEGER)
      ELSE NULL END AS result_size_bytes,
    0.55 AS confidence
  FROM raw_events
),
telemetry AS (
  SELECT * FROM structured
  UNION ALL
  SELECT * FROM raw_parsed
)
SELECT
  'claude-tool-telemetry-' || event_id || '-' || COALESCE(request_id, event_key),
  'claude-code-pid-' || pid,
  'claude-conv-telemetry-' || pid,
  end_ms,
  tool_name,
  request_id,
  CASE WHEN duration_ms IS NOT NULL THEN end_ms - duration_ms ELSE NULL END,
  end_ms,
  duration_ms,
  'completed',
  json_object('input_size_bytes', input_size_bytes),
  json_object('result_size_bytes', result_size_bytes),
  pid,
  event_id,
  'claude-code',
  confidence
FROM telemetry
WHERE tool_name IS NOT NULL;

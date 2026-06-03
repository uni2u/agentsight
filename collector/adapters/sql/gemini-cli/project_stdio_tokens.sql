INSERT OR REPLACE INTO token_usage (
  id, llm_call_id, timestamp_ms, pid, comm, provider, model,
  input_tokens, output_tokens, cache_creation_tokens, cache_read_tokens,
  total_tokens, source, adapter_id, confidence
)
WITH stdout_json AS (
  SELECT
    c.id,
    c.timestamp_ms,
    c.pid,
    c.comm,
    json_extract(c.attributes_json, '$.data') AS body
  FROM canonical_events c
  WHERE c.source = 'stdio'
    AND json_extract(c.attributes_json, '$.direction') = 'WRITE'
    AND json_extract(c.attributes_json, '$.fd_role') = 'stdout'
    AND json_valid(json_extract(c.attributes_json, '$.data'))
    AND json_extract(json_extract(c.attributes_json, '$.data'), '$.stats.models') IS NOT NULL
),
model_stats AS (
  SELECT
    s.id,
    s.timestamp_ms,
    s.pid,
    s.comm,
    m.key AS model,
    m.value AS metrics
  FROM stdout_json s,
       json_each(json_extract(s.body, '$.stats.models')) AS m
),
parsed AS (
  SELECT
    id,
    timestamp_ms,
    pid,
    comm,
    model,
    COALESCE(CAST(json_extract(metrics, '$.tokens.prompt') AS INTEGER),
             CAST(json_extract(metrics, '$.tokens.input') AS INTEGER),
             0) AS input_tokens,
    COALESCE(CAST(json_extract(metrics, '$.tokens.candidates') AS INTEGER), 0)
      + COALESCE(CAST(json_extract(metrics, '$.tokens.thoughts') AS INTEGER), 0)
      + COALESCE(CAST(json_extract(metrics, '$.tokens.tool') AS INTEGER), 0) AS output_tokens,
    COALESCE(CAST(json_extract(metrics, '$.tokens.cached') AS INTEGER), 0) AS cache_read_tokens,
    COALESCE(CAST(json_extract(metrics, '$.tokens.total') AS INTEGER), 0) AS total_tokens
  FROM model_stats
)
SELECT
  'gemini-stdout-token-' || p.id || '-' || p.model,
  NULL,
  p.timestamp_ms,
  p.pid,
  p.comm,
  'gcp.gen_ai',
  p.model,
  p.input_tokens,
  p.output_tokens,
  0,
  p.cache_read_tokens,
  CASE
    WHEN p.total_tokens > 0 THEN p.total_tokens
    ELSE p.input_tokens + p.output_tokens
  END,
  'gemini_cli_stdout_stats',
  'gemini-cli',
  0.80
FROM parsed p
WHERE p.total_tokens > 0 OR p.input_tokens > 0 OR p.output_tokens > 0;

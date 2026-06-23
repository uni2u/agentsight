---
name: agentpprof-flamegraph
description: Generate semantic flamegraphs from local AI agent sessions using agentpprof. Use when the user asks to profile agent sessions, visualize token usage, create flamegraphs, or analyze agent behavior patterns. This skill guides iterative tag rule development for meaningful aggregation.
---

# agentpprof Flamegraph Generation

## Goal

Generate meaningful flamegraphs from local Codex/Claude Code sessions by iteratively developing tag rules that achieve high prompt coverage.

## Workflow

### 1. Initial Discovery

Run agentpprof without rules to see diagnostics:

```bash
agentpprof \
  --project-root /path/to/project \
  --view tokens \
  -o initial.json \
  --format json \
  --include-previews
```

The output includes:
- `tagging.total_prompts`: total prompts found
- `tagging.unmatched_prompts`: prompts without tags
- `tagging.unmatched_samples`: sample unmatched prompts (up to 20)
- `tagging.hint`: suggested next step

### 2. Analyze Unmatched Prompts

Look at `unmatched_samples` to identify patterns:
- Common keywords or phrases
- Chinese/English patterns
- Action types (review, debug, git, etc.)
- Project-specific terminology

### 3. Develop Tag Rules

Add `--tag-rule` arguments iteratively:

```bash
agentpprof \
  --project-root /path/to/project \
  --tag-rule 'prompt:review=(?i)review|审核|check' \
  --tag-rule 'prompt:debug=(?i)fix|bug|error|broken' \
  --tag-rule 'prompt:git=(?i)commit|push|pull|git' \
  --view tokens \
  -o iter1.folded
```

Rule syntax: `KIND:TAG=REGEX`
- KIND: `prompt`, `session`, `llm`, or `all`
- TAG: lowercase word, 3-12 letters (semantic, not vague)
- REGEX: case-insensitive patterns with `(?i)`

**Avoid vague tags** like `task`, `work`, `misc`, `thing`, `stuff`, `other` — they don't convey semantic meaning and won't aggregate well. Use specific tags like `debug`, `review`, `paper`, `naming` that describe the activity.

### 4. Check Coverage

Each run shows `coverage_pct`. Iterate until coverage is acceptable (ideally >80%).

### 5. Generate Final Flamegraphs

```bash
for view in tokens files network; do
  agentpprof \
    --project-root /path/to/project \
    "${TAG_RULES[@]}" \
    --view "$view" \
    -o "project-${view}.svg"
done
```

## Views

| View | Width means | Use for |
|------|-------------|---------|
| `tokens` | Token count | Where did model budget go? |
| `files` | File effect count | Which paths were touched? |
| `network` | Network effect count | Which domains were contacted? |

## Common Tag Patterns

```bash
# Paper writing
--tag-rule 'prompt:paper=(?i)paper|arxiv|latex|abstract|intro|section'

# Code review
--tag-rule 'prompt:review=(?i)review|审核|check|diff|pr'

# Git operations  
--tag-rule 'prompt:git=(?i)commit|push|pull|git|merge|rebase'

# Debugging
--tag-rule 'prompt:debug=(?i)fix|bug|error|broken|为啥|failed'

# Testing
--tag-rule 'prompt:test=(?i)test|cargo test|pytest|verify'

# Formatting/style
--tag-rule 'prompt:format=(?i)格式|style|format|font|图'

# Confirmations (short responses)
--tag-rule 'prompt:confirm=(?i)^嗯$|^是$|^好$|^ok$'

# Context continuations
--tag-rule 'prompt:context=(?i)session is being continued'

# Subagent delegations
--tag-rule 'prompt:delegate=(?i)subagent|task-notification'
```

## Explicit Session Files

For repeatable analysis, use `--session-file` instead of `--project-root`:

```bash
agentpprof \
  --session-file ~/.claude/projects/.../session1.jsonl \
  --session-file ~/.claude/projects/.../session2.jsonl \
  --project-name my-project \
  "${TAG_RULES[@]}" \
  --view tokens \
  -o output.svg
```

## Notes

- `--preset` enables built-in keyword rules for quick testing, but they are generic and unlikely to match your project well
- Without `--tag-rule` or `--preset`, all prompts are marked `unmatched`
- Flamegraphs require semantic tags to aggregate meaningfully
- Iterate on rules until coverage is acceptable, then save the command as a script

## Example Script

See `docs/flamegraph/examples/bpf-benchmark.sh` for a complete example with 100% coverage.

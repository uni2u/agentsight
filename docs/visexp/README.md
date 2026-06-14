# Semantic Tag Flamegraph Experiment

This directory contains a runnable experiment for the one-word semantic tag
design. It reads real local Codex and Claude JSONL sessions for this repository,
assigns one lowercase word to each session, user prompt, and LLM call, then emits
folded stacks and static SVG flamegraphs.

See [DESIGN.md](DESIGN.md) for the experiment contract, stack grammar, and
OSDI-facing interpretation. See [CLAIMS.md](CLAIMS.md) for which claims are
currently supported and which still require paired workloads or user studies.

The important invariant is aggregation:

```text
project:agentsight;agent:codex;session:design;prompt:flamegraph;tool:shell;cmd:rg;effect:read;path:docs/design;status:ok 7
```

The line above means seven raw tool/effect observations collapsed into one stack.
The SVG is a rendering of the folded stack file, not a per-session trace tree.

## Run

Fallback tagger, no model calls:

```bash
python3 docs/visexp/semantic_tag_flamegraph.py --out docs/visexp/out
```

llama.cpp annotation with a local GGUF:

```bash
python3 docs/visexp/semantic_tag_flamegraph.py \
  --model /path/to/model.Q4_K_M.gguf \
  --llama-cli ../llama.cpp-latest/build/bin/llama-cli \
  --llama-limit 200 \
  --out docs/visexp/out
```

The model prompt has a strict contract: return exactly one lowercase English
word. Invalid model output falls back to the deterministic local tagger.

## Outputs

- `out/index.html`: static report page.
- `out/system-flamegraph.svg`: system/tool footprint flamegraph.
- `out/token-flamegraph.svg`: token footprint flamegraph.
- `out/semantic-system.folded.txt`: collapsed system stacks.
- `out/nonsemantic-system.folded.txt`: baseline folded stacks with session and
  prompt tags removed.
- `out/semantic-token.folded.txt`: collapsed token stacks.
- `out/aggregation.json`: proof that raw events were collapsed into fewer
  unique stacks, with repeated stack examples.
- `out/input-manifest.json`: exact argv, selected session hashes, script hash,
  llama.cpp commit when available, and model checksum.
- `out/agent-diff.csv`: Codex-vs-Claude comparison after removing the agent
  frame from each normalized system stack, split by top/subagent cohort and
  normalized per 1000 observations.
- `out/command-summary.csv`: flat process/tool baseline.
- `out/prompt-tags.csv`: sanitized prompt hashes, previews, and one-word tags.
- `out/sessions.json`: per-session counts and tag summaries.

## What It Can And Cannot Show

It can show where sessions spend their work semantically, which prompt tags drive
repeated shell/edit/network/tool patterns, how much semantic tags add beyond a
non-semantic folded baseline, and where Codex and Claude differ on normalized
behavior diagnostics.

It cannot yet prove precise file/network side effects from session history alone.
The stack grammar is already ready for AgentSight's tool -> shell -> child
process -> file/network events; this prototype uses agent-native tool records as
the input effect stream.

## Test

```bash
python3 -m unittest docs/visexp/test_semantic_tag_flamegraph.py
python3 docs/visexp/verify_artifacts.py --out docs/visexp/out
```

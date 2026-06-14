# Semantic Tag Flamegraph Experiment Design

## Question

The experiment asks a narrower question than general agent observability:

> Can one-word semantic labels turn raw agent session history into aggregated
> system-behavior views that ordinary process logs, token dashboards, and trace
> trees do not provide?

The intended user is not trying to replay a session line by line. They want to
see where an agent is heavy, repetitive, divergent from another agent, or
semantically concentrated.

## Input

The prototype reads local Codex and Claude JSONL sessions for this repository.
It extracts:

- session metadata: source, model, cwd, subagent status;
- user prompts: hashed and redacted in committed artifacts;
- LLM calls: model and token usage when available;
- tool calls: shell/read/edit/network/subagent categories, command basename,
  effect class, status, path/domain group when safely inferable.

The current input is agent-native history, not the full AgentSight
tool -> shell -> child process -> file/network stream. The stack grammar already
has slots for those lower-level effects.

## Semantic Contract

The semantic layer is deliberately small:

- one lowercase ASCII word per session, prompt, and LLM call;
- no fixed ontology;
- invalid model output is rejected and replaced by deterministic fallback;
- committed artifacts store only tags, hashes, counts, and redacted prompt rows.

The demo uses `llama.cpp` with `qwen2.5-3b-instruct-q4_k_m.gguf` for the first
60 tag requests, then fallback for the rest. This keeps the run bounded while
showing that the local-small-model path works.

## Folded Stacks

The system footprint stack is:

```text
project;agent;session-tag;prompt-tag;tool;cmd;effect;path/domain/status
```

The token footprint stack is:

```text
project;agent;session-tag;prompt-tag;llm-tag;model;tokens
```

These are collapsed before rendering. If the same path occurs 167 times, the
folded file has one line with weight `167`, not 167 SVG rectangles. This is the
core distinction from a trace tree.

## Views

`system-flamegraph.svg` answers: which semantic prompt/session regions produce
the most repeated system/tool behavior?

`token-flamegraph.svg` answers: which semantic regions consume token mass within
the available source accounting. Token stacks are split by provenance kind:
`input`, `output`, `cache`, and `estimate`. This avoids presenting Claude cache
tokens and Codex estimated response tokens as the same measurement.

`nonsemantic-system.folded.txt` answers: what would remain if the same tool
stream were folded without session and prompt semantics?

`command-summary.csv` answers: what would a traditional flat tool/process
summary show?

`agent-diff.csv` answers: after removing the agent frame and normalizing by
cohort totals, which system stacks are Codex-heavy or Claude-heavy diagnostics?

`aggregation.json` is the audit receipt. It separates raw tool events from
expanded stack observations because one tool event may produce multiple
path/domain observations.

`verify_artifacts.py` checks that folded line counts and summed weights match
`aggregation.json`, prompt previews are redacted, tag contracts pass, and diff
columns use normalized rates.

`input-manifest.json` records exact argv, selected session content hashes, script
hash, model checksum, and local llama.cpp provenance where available.

`evaluate_artifacts.py` is the current OSDI-facing artifact audit. It asks
whether nonsemantic or flat baselines merge multiple prompt/session regions that
the semantic stack separates, then writes `evaluation.json`,
`semantic-mixing.csv`, `claim-gates.csv`, and `evaluation-summary.md`.

## What Is New Here

Traditional process tools can tell that `git`, `gh`, `sed`, or `cargo` ran.
Trace UIs can show tool calls in chronological order. Token dashboards can show
which model spent the most.

This experiment joins those observations to one-word semantic labels and then
aggregates across sessions and agents. The useful unit becomes:

```text
paper prompt -> gh process behavior, Claude-heavy
session prompt -> git read behavior, Codex-heavy
```

That is not visible from a process list, a span tree, or a token chart alone.

## Current Limits

The path/domain extraction from shell commands is conservative and lossy. It is
only a placeholder for AgentSight's precise system-effect stream.

The local model is invoked once per uncached tag, so this is a reproducible
offline experiment, not the production architecture. A production path should use
a resident `llama-server` or batch annotation.

Some fallback tags remain generic because the experiment enforces a fixed runtime
budget for model calls. The research claim should evaluate tag stability and
adequacy separately from flamegraph aggregation.

The behavior diff is a first-order comparison, not a causal claim. It reports
that two agents differ on normalized stack-observation rate; it does not prove
why. Paired workloads are required before making benchmark claims.

The token flamegraph is source-local/proxy accounting. Cross-agent cost claims
require comparable token accounting and should not be made from this artifact.

## Evaluation Hooks

The next OSDI-level evaluation should measure:

- contract validity: accepted tags satisfy the one-word grammar;
- aggregation strength: raw events per unique stack and repeated-stack reuse;
- semantic information gain: baseline buckets whose mixed prompt/session tags
  are only separable with semantic frames;
- human utility: users find repeated/different behavior faster than with raw
  trace trees, flat process summaries, token dashboards, and non-semantic folded
  baselines;
- stability: tag variance across reruns and small models;
- extensibility: replacing agent-native tool records with exact AgentSight
  process/file/network effects preserves the same stack grammar.

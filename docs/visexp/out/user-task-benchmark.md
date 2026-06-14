# User Task Benchmark Bundle

This bundle defines analysis tasks and answer keys for C5. It is not a human-study result.

## Tasks

- UT1 (find-hidden-semantic-mixing): Nonsemantic Mixing.
- UT2 (compare-flat-vs-semantic): Flat Effect Mixing.
- UT3 (find-repeated-heavy-behavior): Heaviest Repeated Semantic Stack.
- UT4 (find-agent-divergence): Top Agent-Difference Diagnostic.
- UT5 (find-token-hotspot): Largest Token Region.
- UT6 (avoid-overclaiming-tag-quality): Tag Stability Boundary.

## Claim Boundary

- The bundle makes C5 executable by defining questions, participant view conditions, and answer keys.
- `user-task-response-template.csv` defines the response schema consumed by `score_user_task_results.py`.
- Participants should see only their assigned view condition; oracle sources and answer keys are for graders.
- C5 remains unsupported until participant responses are collected and scored.

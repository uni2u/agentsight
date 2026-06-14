#!/usr/bin/env python3
import unittest
from collections import Counter
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from semantic_tag_flamegraph import (
    LlmEvent,
    SessionRecord,
    ToolEvent,
    UserRequest,
    build_agent_diff,
    build_folded_stacks,
    build_nonsemantic_system,
)
from evaluate_artifacts import (
    compression_summary,
    mixing_summary,
    tag_quality,
)
from tag_stability_smoke import (
    annotator_metrics,
    cross_annotator_metrics,
    smoke_verdict,
)
from user_task_benchmark import parse_variants, participant_packets, stack_frame


class AggregationTests(unittest.TestCase):
    def test_repeated_system_stack_is_collapsed(self) -> None:
        session = SessionRecord(source="codex", path=Path("session.jsonl"), session_id="s1")
        session.session_tag = "design"
        session.user_requests.append(UserRequest(0, None, "abc", "write docs", tag="design"))
        for idx in range(3):
            session.tools.append(
                ToolEvent(
                    ts_ms=None,
                    request_index=0,
                    tool_name="exec_command",
                    category="shell",
                    command="rg flamegraph docs",
                    command_name="rg",
                    effect="read",
                    status="ok",
                    path_groups=["docs/design"],
                    source_id=str(idx),
                )
            )

        system, token, _ = build_folded_stacks([session], "agentsight")

        self.assertEqual(sum(system.values()), 3)
        self.assertEqual(len(system), 1)
        self.assertIn("cmd:rg", next(iter(system)))
        self.assertEqual(token, Counter())

    def test_token_stack_uses_token_weight(self) -> None:
        session = SessionRecord(source="claude", path=Path("session.jsonl"), session_id="s2")
        session.session_tag = "audit"
        session.user_requests.append(UserRequest(0, None, "abc", "review code", tag="review"))
        session.llm_calls.append(
            LlmEvent(
                ts_ms=None,
                request_index=0,
                model="claude-opus",
                text_hash="def",
                preview="reviewed",
                input_tokens=10,
                output_tokens=5,
                cache_tokens=20,
                tag="review",
            )
        )

        _, token, _ = build_folded_stacks([session], "agentsight")

        self.assertEqual(sum(token.values()), 35)
        self.assertEqual(len(token), 3)
        self.assertTrue(any("kind:input" in stack for stack in token))
        self.assertTrue(any("kind:output" in stack for stack in token))
        self.assertTrue(any("kind:cache" in stack for stack in token))

    def test_nonsemantic_baseline_removes_prompt_frames(self) -> None:
        sessions = []
        for prompt_tag in ("design", "debug"):
            session = SessionRecord(source="codex", path=Path(f"{prompt_tag}.jsonl"), session_id=prompt_tag)
            session.session_tag = prompt_tag
            session.user_requests.append(UserRequest(0, None, prompt_tag, prompt_tag, tag=prompt_tag))
            session.tools.append(
                ToolEvent(
                    ts_ms=None,
                    request_index=0,
                    tool_name="exec_command",
                    category="shell",
                    command="git status",
                    command_name="git",
                    effect="read",
                    status="ok",
                )
            )
            sessions.append(session)

        system, _, _ = build_folded_stacks(sessions, "agentsight")
        nonsemantic = build_nonsemantic_system(system)

        self.assertEqual(sum(system.values()), 2)
        self.assertEqual(len(system), 2)
        self.assertEqual(len(nonsemantic), 1)
        self.assertNotIn("prompt:", next(iter(nonsemantic)))

    def test_agent_diff_uses_rate_normalization(self) -> None:
        system = Counter(
            {
                "project:agentsight;agent:codex;session:x;prompt:x;tool:shell;cmd:git;effect:read;status:ok": 10,
                "project:agentsight;agent:codex;session:x;prompt:x;tool:shell;cmd:sed;effect:read;status:ok": 90,
                "project:agentsight;agent:claude;session:x;prompt:x;tool:shell;cmd:git;effect:read;status:ok": 5,
                "project:agentsight;agent:claude;session:x;prompt:x;tool:shell;cmd:sed;effect:read;status:ok": 5,
            }
        )

        diff = build_agent_diff(system)
        git_row = next(row for row in diff if "cmd:git" in row["stack"] and row["cohort"] == "top")

        self.assertEqual(git_row["codex"], 10)
        self.assertEqual(git_row["claude"], 5)
        self.assertEqual(git_row["winner"], "claude")
        self.assertAlmostEqual(git_row["codex_rate_per_1k"], 100.0)
        self.assertAlmostEqual(git_row["claude_rate_per_1k"], 500.0)

    def test_mixing_summary_detects_prompt_information_loss(self) -> None:
        system = Counter(
            {
                "project:agentsight;agent:codex;session:design;prompt:flamegraph;tool:shell;cmd:git;effect:read;status:ok": 3,
                "project:agentsight;agent:codex;session:debug;prompt:test;tool:shell;cmd:git;effect:read;status:ok": 2,
                "project:agentsight;agent:codex;session:debug;prompt:test;tool:shell;cmd:rg;effect:read;status:ok": 1,
            }
        )

        summary = mixing_summary(system, ("session:", "prompt:"), "nonsemantic")

        self.assertEqual(summary["mixed_bucket_count"], 1)
        self.assertEqual(summary["mixed_weight"], 5)
        self.assertEqual(summary["max_semantic_variants_per_bucket"], 2)

    def test_tag_quality_finds_same_hash_conflicts_and_generic_share(self) -> None:
        rows = [
            {"prompt_hash": "abc", "prompt_tag": "flamegraph"},
            {"prompt_hash": "abc", "prompt_tag": "visual"},
            {"prompt_hash": "def", "prompt_tag": "prompt"},
        ]
        sessions = [{"session_tag": "design"}]
        aggregation = {"tag_contract": {"invalid_count": 0}}

        quality = tag_quality(rows, sessions, aggregation)

        self.assertEqual(quality["same_hash_multi_tag_count"], 1)
        self.assertEqual(quality["invalid_prompt_tag_count"], 0)
        self.assertAlmostEqual(quality["generic_prompt_row_share_pct"], 33.333)

    def test_compression_summary_reports_collapsed_observations(self) -> None:
        stacks = Counter({"a;b": 4, "a;c": 1})

        summary = compression_summary(stacks)

        self.assertEqual(summary["total_observations"], 5)
        self.assertEqual(summary["unique_stacks"], 2)
        self.assertEqual(summary["collapsed_observations"], 3)
        self.assertEqual(summary["compression_ratio"], 2.5)

    def test_tag_stability_metrics_report_repeated_run_stability(self) -> None:
        rows = [
            {"annotator": "fallback", "fragment_id": "a", "tag": "debug", "valid": True, "generic": False},
            {"annotator": "fallback", "fragment_id": "a", "tag": "debug", "valid": True, "generic": False},
            {"annotator": "fallback", "fragment_id": "b", "tag": "work", "valid": True, "generic": True},
            {"annotator": "fallback", "fragment_id": "b", "tag": "work", "valid": True, "generic": True},
            {"annotator": "llama", "fragment_id": "a", "tag": "debug", "valid": True, "generic": False},
            {"annotator": "llama", "fragment_id": "a", "tag": "debug", "valid": True, "generic": False},
            {"annotator": "llama", "fragment_id": "b", "tag": "model", "valid": True, "generic": False},
            {"annotator": "llama", "fragment_id": "b", "tag": "model", "valid": True, "generic": False},
        ]

        metrics = annotator_metrics(rows)
        cross = cross_annotator_metrics(rows)
        verdict = smoke_verdict({"annotator_metrics": metrics})

        self.assertEqual(metrics["fallback"]["exact_stable_fragment_share_pct"], 100.0)
        self.assertEqual(metrics["fallback"]["generic_output_share_pct"], 50.0)
        self.assertEqual(cross["pairs"][0]["modal_exact_match_pct"], 50.0)
        self.assertEqual(verdict, "smoke_supported")

    def test_user_task_helpers_parse_variants_and_stack_frames(self) -> None:
        variants = parse_variants("session:a/prompt:b=7; session:c/prompt:d=2")
        stack = "project:agentsight;session:paper;prompt:debug;cmd:git;effect:read"

        self.assertEqual(variants[0]["semantic"], "session:a/prompt:b")
        self.assertEqual(variants[0]["weight"], 7)
        self.assertEqual(stack_frame(stack, "prompt:"), "debug")
        self.assertEqual(stack_frame(stack, "model:", "none"), "none")

    def test_participant_packets_exclude_oracles(self) -> None:
        tasks = [
            {
                "task_id": "UTX",
                "claim": "C5",
                "skill": "demo",
                "title": "Demo",
                "question": "Find the answer.",
                "participant_view_conditions": [
                    {"condition": "semantic", "views": ["system-flamegraph.svg"]},
                ],
                "answer_format": {"weight": "int"},
            }
        ]

        packets = participant_packets(tasks)

        self.assertEqual(packets[0]["contains_oracle"], False)
        self.assertNotIn("oracle", packets[0])


if __name__ == "__main__":
    unittest.main()

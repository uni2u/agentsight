#!/usr/bin/env python3
"""Generate a sanitized user-task benchmark bundle from visexp artifacts.

The bundle is a protocol artifact for C5. It gives participants concrete
analysis questions and gives reviewers a deterministic answer key. It is not a
human-study result by itself.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_variants(text: str) -> list[dict[str, Any]]:
    variants = []
    for part in text.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        semantic, weight_text = part.rsplit("=", 1)
        try:
            weight = int(weight_text)
        except ValueError:
            continue
        variants.append({"semantic": semantic.strip(), "weight": weight})
    return variants


def stack_frame(stack: str, prefix: str, default: str = "unknown") -> str:
    for frame in stack.split(";"):
        if frame.startswith(prefix):
            return frame.split(":", 1)[1]
    return default


def row_by_kind(rows: list[dict[str, str]], kind: str, rank: int = 1) -> dict[str, str]:
    for row in rows:
        if row.get("baseline_kind") == kind and int(row.get("rank", 0) or 0) == rank:
            return row
    raise AssertionError(f"missing {kind} rank {rank}")


def answer_fields(answer: dict[str, Any]) -> list[str]:
    return sorted(answer)


def task(
    task_id: str,
    title: str,
    question: str,
    participant_view_conditions: list[dict[str, Any]],
    oracle_sources: list[str],
    oracle: dict[str, Any],
    baseline_contrast: str,
    skill: str,
) -> dict[str, Any]:
    return {
        "task_id": task_id,
        "claim": "C5",
        "skill": skill,
        "title": title,
        "question": question,
        "participant_view_conditions": participant_view_conditions,
        "oracle_sources": oracle_sources,
        "answer_format": {field: type(value).__name__ for field, value in oracle.items()},
        "oracle": oracle,
        "scoring": {
            "method": "exact field match against oracle unless the field is marked explanatory",
            "required_fields": answer_fields(oracle),
        },
        "baseline_contrast": baseline_contrast,
    }


def conditions(*items: tuple[str, list[str]]) -> list[dict[str, Any]]:
    return [{"condition": name, "views": views} for name, views in items]


def build_tasks(out_dir: Path) -> list[dict[str, Any]]:
    aggregation = read_json(out_dir / "aggregation.json")
    evaluation = read_json(out_dir / "evaluation.json")
    mixing_rows = read_csv_rows(out_dir / "semantic-mixing.csv")
    agent_rows = read_csv_rows(out_dir / "agent-diff.csv")

    nonsemantic = row_by_kind(mixing_rows, "nonsemantic_without_session_prompt", 1)
    nonsemantic_variants = parse_variants(nonsemantic["top_semantic_variants"])
    flat = row_by_kind(mixing_rows, "flat_effect_without_project_agent_session_prompt", 1)
    flat_variants = parse_variants(flat["top_semantic_variants"])
    top_system = aggregation["top_system_stacks"][0]
    top_token = aggregation["top_token_stacks"][0]
    top_agent = next(row for row in agent_rows if row.get("cohort") == "top")
    stability = evaluation.get("tag_stability_smoke") or {}
    stability_pair = (stability.get("cross_annotator_metrics", {}).get("pairs") or [{}])[0]

    return [
        task(
            "UT1",
            "Nonsemantic Mixing",
            (
                "Find the highest-weight nonsemantic folded bucket. Report the "
                "baseline stack, total weight, semantic variant count, and top "
                "semantic variant."
            ),
            conditions(
                ("semantic", ["system-flamegraph.svg", "semantic-system.folded.txt"]),
                ("nonsemantic", ["nonsemantic-system.folded.txt"]),
                ("flat", ["command-summary.csv"]),
            ),
            ["semantic-mixing.csv", "evaluation.json"],
            {
                "baseline_kind": nonsemantic["baseline_kind"],
                "baseline_stack": nonsemantic["baseline_stack"],
                "weight": int(nonsemantic["weight"]),
                "semantic_variant_count": int(nonsemantic["semantic_variant_count"]),
                "top_semantic_variant": nonsemantic_variants[0]["semantic"],
                "top_semantic_variant_weight": nonsemantic_variants[0]["weight"],
            },
            (
                "A nonsemantic folded stack can show the combined bucket, but not "
                "which session/prompt regions produced it."
            ),
            "find-hidden-semantic-mixing",
        ),
        task(
            "UT2",
            "Flat Effect Mixing",
            (
                "Find the highest-weight flat effect bucket after removing project, "
                "agent, session, and prompt frames. Report its variant count and "
                "top semantic variant."
            ),
            conditions(
                ("semantic", ["system-flamegraph.svg", "semantic-system.folded.txt"]),
                ("flat", ["command-summary.csv"]),
                ("nonsemantic", ["nonsemantic-system.folded.txt"]),
            ),
            ["semantic-mixing.csv", "evaluation.json"],
            {
                "baseline_kind": flat["baseline_kind"],
                "baseline_stack": flat["baseline_stack"],
                "weight": int(flat["weight"]),
                "semantic_variant_count": int(flat["semantic_variant_count"]),
                "top_semantic_variant": flat_variants[0]["semantic"],
                "top_semantic_variant_weight": flat_variants[0]["weight"],
            },
            (
                "A flat process/effect summary can report the command/effect, but "
                "not the task regions hidden inside that bucket."
            ),
            "compare-flat-vs-semantic",
        ),
        task(
            "UT3",
            "Heaviest Repeated Semantic Stack",
            (
                "Identify the heaviest semantic system stack and report its session "
                "tag, prompt tag, command, effect, and weight."
            ),
            conditions(
                ("semantic", ["system-flamegraph.svg", "semantic-system.folded.txt"]),
                ("nonsemantic", ["nonsemantic-system.folded.txt"]),
                ("flat", ["command-summary.csv"]),
            ),
            ["aggregation.json", "semantic-system.folded.txt"],
            {
                "stack": top_system["stack"],
                "weight": int(top_system["weight"]),
                "session": stack_frame(top_system["stack"], "session:"),
                "prompt": stack_frame(top_system["stack"], "prompt:"),
                "cmd": stack_frame(top_system["stack"], "cmd:"),
                "effect": stack_frame(top_system["stack"], "effect:"),
            },
            (
                "A trace tree requires scanning many occurrences; the folded stack "
                "turns repeated behavior into one weighted answer."
            ),
            "find-repeated-heavy-behavior",
        ),
        task(
            "UT4",
            "Top Agent-Difference Diagnostic",
            (
                "In the top-level cohort, identify the largest normalized "
                "Codex-vs-Claude behavioral difference and report the winner, "
                "delta per 1000 observations, and normalized stack."
            ),
            conditions(
                ("semantic-diff", ["agent-diff.csv"]),
                ("flat", ["command-summary.csv"]),
            ),
            ["agent-diff.csv"],
            {
                "cohort": top_agent["cohort"],
                "winner": top_agent["winner"],
                "rate_delta_per_1k": float(top_agent["rate_delta_per_1k"]),
                "codex_rate_per_1k": float(top_agent["codex_rate_per_1k"]),
                "claude_rate_per_1k": float(top_agent["claude_rate_per_1k"]),
                "stack": top_agent["stack"],
            },
            (
                "Raw per-agent counts are confounded by total volume; this view "
                "normalizes stacks before presenting the diagnostic."
            ),
            "find-agent-divergence",
        ),
        task(
            "UT5",
            "Largest Token Region",
            (
                "Identify the largest token stack and report the session tag, "
                "prompt tag, model, token kind, and weight."
            ),
            conditions(
                ("semantic-token", ["token-flamegraph.svg", "semantic-token.folded.txt"]),
                ("folded-token", ["semantic-token.folded.txt"]),
            ),
            ["aggregation.json", "semantic-token.folded.txt"],
            {
                "stack": top_token["stack"],
                "weight": int(top_token["weight"]),
                "session": stack_frame(top_token["stack"], "session:"),
                "prompt": stack_frame(top_token["stack"], "prompt:"),
                "model": stack_frame(top_token["stack"], "model:"),
                "kind": stack_frame(top_token["stack"], "kind:"),
            },
            (
                "A token dashboard can show aggregate cost, but this task asks for "
                "the semantic region and provenance kind of the largest token mass."
            ),
            "find-token-hotspot",
        ),
        task(
            "UT6",
            "Tag Stability Boundary",
            (
                "Decide whether the current tag stability smoke proves semantic "
                "adequacy. Report the smoke verdict, llama repeated-run stability, "
                "fallback-vs-llama exact match, and the correct conclusion."
            ),
            conditions(
                ("summary", ["tag-stability-summary.md"]),
                ("json", ["tag-stability-smoke.json"]),
            ),
            ["tag-stability-smoke.json"],
            {
                "smoke_verdict": stability.get("smoke_verdict", "missing"),
                "llama_stable_pct": float(
                    stability.get("annotator_metrics", {})
                    .get("llama", {})
                    .get("exact_stable_fragment_share_pct", 0.0)
                ),
                "fallback_vs_llama_exact_pct": float(stability_pair.get("modal_exact_match_pct", 0.0)),
                "semantic_adequacy_proven": False,
            },
            (
                "This task checks that users do not over-read stability smoke as "
                "semantic adequacy evidence."
            ),
            "avoid-overclaiming-tag-quality",
        ),
    ]


def write_answer_key(path: Path, tasks: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["task_id", "answer_json"], lineterminator="\n")
        writer.writeheader()
        for item in tasks:
            writer.writerow(
                {
                    "task_id": item["task_id"],
                    "answer_json": json.dumps(item["oracle"], sort_keys=True),
                }
            )


def write_response_template(path: Path, packets: list[dict[str, Any]]) -> None:
    fields = [
        "participant_id",
        "packet_id",
        "task_id",
        "condition",
        "response_json",
        "task_time_seconds",
        "confidence",
        "notes",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        for packet in packets:
            writer.writerow(
                {
                    "participant_id": "",
                    "packet_id": packet["packet_id"],
                    "task_id": packet["task_id"],
                    "condition": packet["condition"],
                    "response_json": "{}",
                    "task_time_seconds": "",
                    "confidence": "",
                    "notes": "",
                }
            )


def participant_packets(tasks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    packets = []
    forbidden = {"semantic-mixing.csv", "aggregation.json"}
    for item in tasks:
        for condition in item["participant_view_conditions"]:
            views = list(condition["views"])
            leaked = sorted(set(views) & forbidden)
            if leaked:
                raise AssertionError(
                    f"{item['task_id']} {condition['condition']} exposes oracle-only views: {leaked}"
                )
            packets.append(
                {
                    "packet_id": f"{item['task_id']}-{condition['condition']}",
                    "task_id": item["task_id"],
                    "claim": item["claim"],
                    "skill": item["skill"],
                    "condition": condition["condition"],
                    "title": item["title"],
                    "question": item["question"],
                    "views": views,
                    "answer_format": item["answer_format"],
                    "contains_oracle": False,
                }
            )
    return packets


def write_participant_summary(path: Path, packets: list[dict[str, Any]]) -> None:
    lines = [
        "# User Task Participant Packets",
        "",
        "These packets are participant-facing condition assignments. They intentionally omit oracles and answer keys.",
        "",
        "## Packets",
        "",
    ]
    for packet in packets:
        lines.append(
            f"- {packet['packet_id']}: {packet['title']} using {packet['condition']} views."
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_summary(path: Path, bundle: dict[str, Any]) -> None:
    lines = [
        "# User Task Benchmark Bundle",
        "",
        "This bundle defines analysis tasks and answer keys for C5. It is not a human-study result.",
        "",
        "## Tasks",
        "",
    ]
    for item in bundle["tasks"]:
        lines.append(
            f"- {item['task_id']} ({item['skill']}): {item['title']}."
        )
    lines.extend(
        [
            "",
            "## Claim Boundary",
            "",
            "- The bundle makes C5 executable by defining questions, participant view conditions, and answer keys.",
            "- `user-task-response-template.csv` defines the response schema consumed by `score_user_task_results.py`.",
            "- Participants should see only their assigned view condition; oracle sources and answer keys are for graders.",
            "- C5 remains unsupported until participant responses are collected and scored.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = Path(args.out).resolve()
    tasks = build_tasks(out_dir)
    packets = participant_packets(tasks)
    bundle = {
        "schema_version": 1,
        "claim": "C5",
        "status": "pilot_packet_ready_no_participants",
        "source_artifacts": [
            "aggregation.json",
            "evaluation.json",
            "semantic-mixing.csv",
            "agent-diff.csv",
            "semantic-system.folded.txt",
            "semantic-token.folded.txt",
            "tag-stability-smoke.json",
        ],
        "participant_protocol": {
            "design": "within-subject counterbalanced order across visualization families",
            "metrics": ["task_time_seconds", "answer_accuracy", "false_positive_count", "confidence"],
            "minimum_pilot_participants": 4,
            "paper_run_participants": "12-20",
            "oracle_visibility": "participants see only one assigned view condition; oracle_sources are for graders",
            "claim_gate": "C5 can move beyond unsupported only after scored participant responses exist.",
        },
        "participant_packet_files": [
            "user-task-participant-packets.json",
            "user-task-participant-packets.md",
            "user-task-response-template.csv",
        ],
        "tasks": tasks,
    }
    (out_dir / "user-task-benchmark.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    write_answer_key(out_dir / "user-task-answer-key.csv", tasks)
    (out_dir / "user-task-participant-packets.json").write_text(
        json.dumps({"schema_version": 1, "packets": packets}, indent=2),
        encoding="utf-8",
    )
    write_participant_summary(out_dir / "user-task-participant-packets.md", packets)
    write_response_template(out_dir / "user-task-response-template.csv", packets)
    write_summary(out_dir / "user-task-benchmark.md", bundle)
    print(json.dumps({"tasks": len(tasks), "packets": len(packets), "out": str(out_dir)}, indent=2))
    return bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "out"))
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())

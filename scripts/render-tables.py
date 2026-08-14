#!/usr/bin/env python3
"""Render the evaluation tables from the JSON that experiment.sh produced.

Reads docs/benchmark/data/<tag>/*.json and writes Markdown plus CSV. Nothing is
computed here that the runtime did not already compute: this only arranges it.
"""

import argparse
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ARM_LABELS = {
    "unconfined": "unconfined",
    "minicrun-denylist": "minicrun denylist",
    "learn": "learn",
    "enforce": "enforce",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Result subdirectory to render")
    parser.add_argument("--data", type=Path, default=REPO_ROOT / "docs/benchmark/data")
    parser.add_argument("--out", type=Path, default=None, help="Markdown output path")
    return parser.parse_args()


def load_results(directory: Path) -> list[dict]:
    results = []
    for path in sorted(directory.glob("*.json")):
        if path.name == "environment.json":
            continue
        results.append(json.loads(path.read_text()))
    return results


def fmt_pct(value) -> str:
    return "-" if value is None else f"{value * 100:.1f}%"


def fmt_ms(summary) -> str:
    if not summary or not summary.get("n"):
        return "-"
    return f"{summary['median']} ({summary['p25']}-{summary['p75']})"


def surface_table(results: list[dict]) -> list[list[str]]:
    rows = [
        [
            "workload",
            "allowed",
            "docker baseline",
            "vs docker",
            "vs arch",
            "newly blocked",
            "over-allowed",
        ]
    ]
    for result in results:
        comparison = result.get("comparison") or {}
        rows.append(
            [
                result["workload"],
                str(comparison.get("profile_allowed", "-")),
                str(comparison.get("baseline_allowed", "-")),
                fmt_pct(comparison.get("reduction_vs_baseline")),
                fmt_pct(comparison.get("reduction_vs_universe")),
                str(len(comparison.get("newly_blocked", []))),
                str(len(comparison.get("over_allowed", []))),
            ]
        )
    return rows


def cve_table(results: list[dict]) -> list[list[str]]:
    rows = [["workload", "relevant", "blocked by profile", "blocked by docker", "newly blocked"]]
    for result in results:
        cve = ((result.get("comparison") or {}).get("cve")) or {}
        if not cve:
            continue
        rows.append(
            [
                result["workload"],
                str(cve.get("container_relevant", "-")),
                str(cve.get("mitigated_by_profile", "-")),
                str(cve.get("mitigated_by_baseline", "-")),
                str(len(cve.get("newly_mitigated", []))),
            ]
        )
    return rows


def latency_table(results: list[dict]) -> list[list[str]]:
    rows = [["workload", "arm", "time to ready ms, median (p25-p75)", "total run ms", "n"]]
    for result in results:
        for arm, label in ARM_LABELS.items():
            data = (result.get("arms") or {}).get(arm)
            if not data:
                continue
            ready = data.get("time_to_ready_ms") or {}
            rows.append(
                [
                    result["workload"],
                    label,
                    fmt_ms(ready),
                    fmt_ms(data.get("total_run_ms")),
                    str(ready.get("n", 0)),
                ]
            )
    return rows


def denial_table(results: list[dict]) -> list[list[str]]:
    rows = [["workload", "arm", "ready", "functional", "false denial rate"]]
    for result in results:
        for arm, label in ARM_LABELS.items():
            data = (result.get("arms") or {}).get(arm)
            if not data:
                continue
            rows.append(
                [
                    result["workload"],
                    label,
                    str(data.get("ready_ok", "-")),
                    str(data.get("functional_ok", "-")),
                    fmt_pct(data.get("false_denial_rate")),
                ]
            )
    return rows


def to_markdown(rows: list[list[str]]) -> str:
    if len(rows) < 2:
        return "_no data_\n"
    header, *body = rows
    lines = ["| " + " | ".join(header) + " |", "|" + "|".join(["---"] * len(header)) + "|"]
    lines += ["| " + " | ".join(row) + " |" for row in body]
    return "\n".join(lines) + "\n"


def write_csv(path: Path, rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        csv.writer(handle).writerows(rows)


def main() -> int:
    args = parse_args()
    directory = args.data / args.tag
    if not directory.is_dir():
        print(f"error: no results at {directory}", file=sys.stderr)
        return 2

    results = load_results(directory)
    if not results:
        print(f"error: no result files in {directory}", file=sys.stderr)
        return 2

    env_path = directory / "environment.json"
    if env_path.exists():
        environment = json.loads(env_path.read_text())
    else:
        # Every result embeds the same environment block, so either source works.
        environment = results[0].get("environment", {})

    tables = {
        "surface": surface_table(results),
        "cve": cve_table(results),
        "latency": latency_table(results),
        "false-denial": denial_table(results),
    }
    for name, rows in tables.items():
        write_csv(directory / "tables" / f"{name}.csv", rows)

    commit = str(environment.get("git_commit", "unknown"))[:12]
    out = args.out or (REPO_ROOT / f"docs/benchmark/results-{args.tag}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        f"""# Evaluation results: {args.tag}

Generated by `scripts/render-tables.py`. Definitions are in
`docs/research/methodology.md`; the numbers do not mean anything without it.

Kernel `{environment.get('kernel', 'unknown')}` on {environment.get('cores', '?')} cores,
runtime commit `{commit}`, started {environment.get('started_at', 'unknown')}.

## Attack surface

Allowed syscall counts are intersected with the syscalls this architecture
defines. The Docker baseline is read the way Docker reads it, with default
capabilities, so capability-gated rules do not count.

{to_markdown(tables['surface'])}
## CVE coverage

A CVE counts as blocked only when every one of its attack paths has at least one
denied syscall. Entries below high confidence in `data/cve-syscall-map.json`
must be verified against NVD before these numbers are quoted.

{to_markdown(tables['cve'])}
## Startup latency

Median with the interquartile range. Learn mode is a one-off offline cost and is
not comparable to the other arms.

{to_markdown(tables['latency'])}
## False denial

A run counts as functional only when it starts, answers its readiness probe and
passes its smoke command.

{to_markdown(tables['false-denial'])}
"""
    )

    print(f"wrote {out}")
    print(f"wrote {directory / 'tables'}/*.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main())

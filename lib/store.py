"""
Sentinel local history store.

The default public prototype stores one merged summary per line in a JSONL file.
This keeps the system portable and dependency-free while still enabling useful
historical searches.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Iterable, List


def resolve_history_file() -> Path:
    base_dir = Path(os.environ.get("SENTINEL_HOME", os.getcwd())).resolve()
    raw_path = os.environ.get("HISTORY_FILE", "history/summaries.jsonl")
    path = Path(raw_path)
    return path if path.is_absolute() else base_dir / path


def load_history(path: Path) -> List[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def write_history(path: Path, rows: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def store_findings(summary_path: str) -> None:
    history_path = resolve_history_file()
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    rows = load_history(history_path)
    rows = [
        row
        for row in rows
        if not (row.get("date") == summary.get("date") and row.get("hostname") == summary.get("hostname"))
    ]
    rows.append(summary)
    rows.sort(key=lambda item: (item.get("date", ""), item.get("hostname", "")))
    write_history(history_path, rows)
    print(f"[store] stored {summary.get('date')} for {summary.get('hostname')} in {history_path}")


def build_search_text(summary: dict) -> str:
    fragments = [
        summary.get("date", ""),
        summary.get("hostname", ""),
        summary.get("status", ""),
        " ".join(summary.get("top_actions", [])),
    ]
    for finding in summary.get("all_findings", []):
        fragments.extend(
            [
                finding.get("id", ""),
                finding.get("severity", ""),
                finding.get("category", ""),
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("recommendation", ""),
                finding.get("package_or_system") or "",
                finding.get("cve_id") or "",
            ]
        )
    return " ".join(fragment for fragment in fragments if fragment).lower()


def score_text(query_tokens: List[str], text: str) -> int:
    return sum(text.count(token) for token in query_tokens)


def search_history(query: str, n_results: int = 5, hostname: str | None = None) -> List[dict]:
    query_tokens = [token.lower() for token in query.split() if token.strip()]
    rows = load_history(resolve_history_file())
    scored = []
    for row in rows:
        if hostname and row.get("hostname") != hostname:
            continue
        search_text = build_search_text(row)
        score = score_text(query_tokens, search_text)
        if score > 0:
            scored.append((score, row))
    scored.sort(key=lambda item: (-item[0], item[1].get("date", "")))
    return [row for _, row in scored[:n_results]]


def print_search_results(results: List[dict]) -> None:
    for row in results:
        counts = row.get("counts", {})
        print(f"{row.get('date')} [{row.get('hostname')}] status={row.get('status')}")
        print(
            "  counts:",
            ", ".join(
                f"{severity}={counts.get(severity, 0)}"
                for severity in ("critical", "high", "medium", "low", "info")
            ),
        )
        if row.get("top_actions"):
            print(f"  top_actions: {' | '.join(row['top_actions'])}")
        for finding in row.get("all_findings", [])[:5]:
            print(
                f"  - {finding.get('id')} [{finding.get('severity')}] "
                f"{finding.get('title')} ({finding.get('category')})"
            )
        print("")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sentinel local history store")
    sub = parser.add_subparsers(dest="command")

    store_cmd = sub.add_parser("store", help="Store summary.json")
    store_cmd.add_argument("path", help="Path to summary.json")

    search_cmd = sub.add_parser("search", help="Search history")
    search_cmd.add_argument("query", help="Search query")
    search_cmd.add_argument("-n", type=int, default=5, help="Number of results")
    search_cmd.add_argument("--host", help="Filter by hostname")

    args = parser.parse_args()

    if args.command == "store":
        store_findings(args.path)
        return 0
    if args.command == "search":
        print_search_results(search_history(args.query, args.n, args.host))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

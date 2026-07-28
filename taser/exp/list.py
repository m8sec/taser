#!/usr/bin/env python3
# Author: @m8sec
# License: BSD 3-Clause
#
# Description:
# List packaged Taser example scripts and summarize their header metadata.

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List

from taser import BANNER


METADATA_KEYS = {
    "description": "description",
    "desc": "description",
    "info": "info",
}

STOP_KEYS = {
    "author",
    "license",
    "usage",
    "requirements",
    "requirement",
}


def _clean_comment(line: str) -> str:
    line = line.strip()
    if line.startswith("#"):
        line = line[1:]
    return line.strip()


def _read_header_comments(path: Path) -> List[str]:
    comments = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            stripped = raw_line.strip()
            if stripped.startswith("#!") or not stripped:
                continue
            if not stripped.startswith("#"):
                break
            comments.append(_clean_comment(raw_line))
    return comments


def _extract_metadata(path: Path) -> Dict[str, str]:
    metadata = {"description": "", "info": ""}
    active_key = ""

    for line in _read_header_comments(path):
        if ":" in line:
            key, value = [part.strip() for part in line.split(":", 1)]
            lowered = key.lower()
            if lowered in METADATA_KEYS:
                active_key = METADATA_KEYS[lowered]
                if value:
                    metadata[active_key] = value
                continue
            if lowered in STOP_KEYS:
                active_key = ""
                continue
        if active_key and line:
            current = metadata[active_key]
            metadata[active_key] = "{} {}".format(current, line).strip()
        elif active_key and not line:
            active_key = ""

    return metadata


def discover_examples() -> List[Dict[str, str]]:
    exp_dir = Path(__file__).resolve().parent
    examples = []

    for path in sorted(exp_dir.glob("*.py"), key=lambda item: item.stem.lower()):
        if path.name.startswith("_") or path.name in ("__init__.py", "list.py"):
            continue
        metadata = _extract_metadata(path)
        summary = metadata.get("description") or metadata.get("info") or "No description found."
        examples.append(
            {
                "name": path.stem,
                "module": "taser.exp.{}".format(path.stem),
                "path": os.path.relpath(path, Path.cwd()),
                "description": summary,
                "info": metadata.get("info", ""),
            }
        )

    return examples


def render_examples(examples: List[Dict[str, str]]) -> str:
    if not examples:
        return "No example scripts found.\n"
    width = max(len(example["name"]) for example in examples)
    lines = []
    for example in examples:
        lines.append("{:<{}} - {}".format(example["name"], width, example["description"]))
        if example.get("info"):
            lines.append("{}   {}".format(" " * width, example["info"]))
    return "\n".join(lines) + "\n"


def build_parser():
    parser = argparse.ArgumentParser(
        description="\t\t{}".format(sys.argv[0]),
        formatter_class=argparse.RawTextHelpFormatter,
        usage=argparse.SUPPRESS,
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    return parser


def cli(argv=None):
    args = build_parser().parse_args(argv)
    examples = discover_examples()
    if args.json:
        sys.stdout.write(json.dumps(examples, indent=2) + "\n")
    else:
        sys.stdout.write(BANNER)
        sys.stdout.write(render_examples(examples))


if __name__ == "__main__":
    cli()

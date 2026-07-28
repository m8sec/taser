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
import textwrap
from pathlib import Path
from typing import Dict, List

from taser import BANNER

SCRIPT_CATEGORIES = {"web", "dns", "net", "fs", "win", "misc", "prox", "radmin"}
DESCRIPTION_WRAP_WIDTH = 175

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


def infer_category(path: Path) -> str:
    for part in path.parts:
        if part in SCRIPT_CATEGORIES:
            return part
    return "misc"


def build_module_name(path: Path, package_root: Path) -> str:
    relative = path.relative_to(package_root.parent).with_suffix("")
    return ".".join(relative.parts)


def discover_examples() -> List[Dict[str, str]]:
    package_root = Path(__file__).resolve().parents[1]
    search_root = package_root / "exp"
    examples = []
    cwd = Path.cwd().resolve()

    for path in sorted(search_root.rglob("*.py"), key=lambda item: str(item).lower()):
        if path.name.startswith("_") or path.name == "__init__.py":
            continue
        if path.parent == search_root:
            continue
        metadata = _extract_metadata(path)
        summary = metadata.get("description") or metadata.get("info") or "No description found."
        module_name = build_module_name(path, package_root)
        try:
            display_path = os.path.relpath(path, cwd)
        except ValueError:
            display_path = str(path)
        examples.append(
            {
                "name": path.stem,
                "category": infer_category(path),
                "module": module_name,
                "invoke": "python -m {}".format(module_name),
                "path": display_path,
                "description": summary,
                "info": metadata.get("info", ""),
            }
        )

    return examples


def render_examples(examples: List[Dict[str, str]]) -> str:
    if not examples:
        return "No example scripts found.\n"
    name_width = max(len(example["name"]) for example in examples)
    exp_width = max(len(example["invoke"]) for example in examples)
    lines = []
    for example in examples:
        prefix = "  + {:<{}}  {:<{}}  - ".format(
            example["name"],
            name_width,
            example["invoke"],
            exp_width,
        )
        wrapped_description = textwrap.wrap(
            example["description"],
            width=DESCRIPTION_WRAP_WIDTH,
            initial_indent=prefix,
            subsequent_indent=" " * len(prefix),
        ) or [prefix.rstrip()]
        lines.extend(wrapped_description)
        if example.get("info"):
            info_indent = " " * len(prefix)
            lines.extend(
                textwrap.wrap(
                    example["info"],
                    width=DESCRIPTION_WRAP_WIDTH,
                    initial_indent=info_indent,
                    subsequent_indent=info_indent,
                )
            )
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

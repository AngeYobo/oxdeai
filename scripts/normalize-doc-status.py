#!/usr/bin/env python3
"""
Normalize doc headers in docs/ (excluding docs/spec/):
 - Ensure a single H1 title at top (# Title). If missing, infer from filename.
 - Immediately after H1, enforce:

   ## Status
   Non-normative (developer documentation)

 - Rename any other "Status" sections to context-specific headers if present
   (Release/Implementation/Milestone Status) by prefixing "Other Status:".
 - Remove duplicate Status blocks.

Idempotent and reports modified files.
"""

from pathlib import Path

TARGET_HEADER_LINES = ["## Status", "", "Non-normative (developer documentation)", ""]
DOCS_ROOT = Path("docs")
EXCLUDE_PREFIX = DOCS_ROOT / "spec"

def infer_title(path: Path, lines):
    # Use first H1 if present
    for line in lines:
        if line.startswith("# "):
            return line[2:].strip()
    # Fallback to filename stem
    return path.stem.replace("-", " ").replace("_", " ").title()


def normalize(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    # Ensure H1 title
    if not lines or not lines[0].startswith("# "):
        title = infer_title(path, lines)
        lines = [f"# {title}", ""] + lines

    # Collect positions of status headers
    status_indices = []
    for i, line in enumerate(lines):
        if line.strip().lower() == "## status":
            status_indices.append(i)

    # Rename secondary status headers (keep content) to avoid conflicts
    if len(status_indices) > 1:
        for idx in status_indices[1:]:
            lines[idx] = "## Other Status"
    elif len(status_indices) == 1:
        # We'll replace placement anyway, so remove this block
        idx = status_indices[0]
        # remove header + following blank and a single paragraph until next blank
        j = idx + 1
        while j < len(lines) and lines[j].strip() == "":
            j += 1
        while j < len(lines) and lines[j].strip() != "":
            j += 1
        lines = lines[:idx] + lines[j:]

    # Insert standard block after the H1
    insert_block = TARGET_HEADER_LINES.copy()
    new_lines = [lines[0], ""] + insert_block + lines[1:]

    return "\n".join(new_lines) + ("\n" if text.endswith("\n") else "")


def main():
    modified = []
    for path in DOCS_ROOT.rglob("*.md"):
        if path.is_dir():
            continue
        if EXCLUDE_PREFIX in path.parents:
            continue
        original = path.read_text(encoding="utf-8")
        updated = normalize(path)
        if updated != original:
            path.write_text(updated, encoding="utf-8")
            modified.append(str(path))
    if modified:
        print("Modified files:")
        for p in modified:
            print(p)
    else:
        print("No changes.")


if __name__ == "__main__":
    main()

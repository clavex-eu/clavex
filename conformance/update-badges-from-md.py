#!/usr/bin/env python3
"""
conformance/update-badges-from-md.py

Reads the conformance summary table from CONFORMANCE.md (already committed to
the repo) and writes up-to-date shields.io endpoint JSON badge files.

Runs on every CI push — no running conformance suite required.

Usage:
    python3 conformance/update-badges-from-md.py [--md CONFORMANCE.md]
"""

import argparse
import json
import os
import re
import sys

# Maps plan aliases (as they appear in CONFORMANCE.md rows) to badge files.
# Must stay in sync with the PER_PLAN_BADGES dict in update-conformance-md.py.
PER_PLAN_BADGES = {
    "clavex-fapi":            ("FAPI 2.0", "conformance-fapi-badge.json"),
    "clavex-fapi-dpop":       ("FAPI 2.0", "conformance-fapi-badge.json"),
    "clavex-fapi-jarm":       ("JARM",     "conformance-jarm-badge.json"),
    "clavex-fapi-mtls":       ("mTLS",     "conformance-mtls-badge.json"),
    "clavex-oid4vci-issuer":  ("OID4VCI",  "conformance-oid4vci-badge.json"),
    "clavex-oid4vp-verifier": ("OID4VP",   "conformance-oid4vp-badge.json"),
}

def _colour(pct: float) -> str:
    if pct >= 0.98:
        return "brightgreen"
    if pct >= 0.90:
        return "green"
    if pct >= 0.75:
        return "yellow"
    return "red"


def parse_conformance_md(path: str) -> dict[str, tuple[int, int, int]]:
    """Read old/new summary columns, including linked labels; never infer skips."""
    results = {}
    columns = None
    with open(path, encoding="utf-8") as source:
        for line in source:
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if cells and cells[0] == "Plan":
                columns = cells
                continue
            if not columns or len(cells) != len(columns):
                continue
            label = cells[0]
            linked = re.search(r"\]\(#(clavex-[^)]+)\)", label)
            alias = linked.group(1) if linked else label.strip("`")
            if not alias.startswith("clavex-"):
                continue
            def number(name):
                index = next((i for i, column in enumerate(columns) if name.lower() in column.lower()), None)
                return int(cells[index]) if index is not None else 0
            total, passed = number("Tests"), number("Passed")
            skipped = number("Skipped")
            if min(total, passed, skipped) < 0 or passed + skipped > total:
                raise ValueError(f"Invalid summary counts for {alias}")
            results[alias] = (passed, skipped, total)
    return results


def build_badge(label: str, passed: int, skipped: int, total: int) -> dict:
    pct = passed / total if total else 0.0
    colour = _colour(pct)
    # Floor (truncate) the percentage so badges match the "Pass rate" column in
    # CONFORMANCE.md, which is rendered with int truncation \u2014 never round up.
    rate = 100 * passed // total if total else 0
    if not total:
        message = "\u2014"
    elif skipped:
        message = f"{rate}% \u00b7 {skipped} skipped"
    else:
        message = f"{rate}%"
    return {
        "schemaVersion": 1,
        "label": label,
        "message": message,
        "color": colour,
    }


def build_overall_badge(results: dict[str, tuple[int, int, int]]) -> dict:
    """Aggregate every plan into the top-level OIDC Conformance badge."""
    passed = sum(p for p, _s, _t in results.values())
    total = sum(t for _p, _s, t in results.values())
    pct = passed / total if total else 0.0
    return {
        "schemaVersion": 1,
        "label": "OIDC Conformance",
        "message": f"{passed}/{total} passing" if total else "\u2014",
        "color": _colour(pct),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--md",
        default=os.path.join(os.path.dirname(__file__), "..", "CONFORMANCE.md"),
        help="Path to CONFORMANCE.md (default: repo root)",
    )
    args = parser.parse_args()

    md_path = os.path.abspath(args.md)
    out_dir = os.path.dirname(md_path)  # same directory as CONFORMANCE.md (repo root)

    results = parse_conformance_md(md_path)
    if not results:
        print("ERROR: no conformance table rows found in CONFORMANCE.md — badges unchanged", file=sys.stderr)
        sys.exit(1)

    write_badges(results, out_dir)


def write_badges(results, out_dir):
    written: set[str] = set()
    for alias, (label, badge_file) in PER_PLAN_BADGES.items():
        if alias not in results:
            continue
        if badge_file in written:
            continue
        passed, skipped, total = results[alias]
        badge = build_badge(label, passed, skipped, total)
        path = os.path.join(out_dir, badge_file)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(badge, f)
            f.write("\n")
        written.add(badge_file)
        pct = passed / total * 100 if total else 0
        skip_note = f"  ({skipped} skipped)" if skipped else ""
        print(f"  {badge_file:45s}  {label}: {passed}/{total} = {100 * passed // total if total else 0}%{skip_note}  →  {badge['message']} ({badge['color']})")

    if not written:
        print("No matching per-plan badge aliases; writing the overall badge only", file=sys.stderr)

    # Top-level OIDC Conformance badge — aggregate of every plan in the table.
    overall = build_overall_badge(results)
    overall_path = os.path.join(out_dir, "conformance-badge.json")
    with open(overall_path, "w", encoding="utf-8") as f:
        json.dump(overall, f)
        f.write("\n")
    written.add("conformance-badge.json")
    print(f"  {'conformance-badge.json':45s}  OIDC Conformance  →  {overall['message']} ({overall['color']})")

    print(f"\nUpdated {len(written)} badge file(s) from supplied summary")


if __name__ == "__main__":
    main()

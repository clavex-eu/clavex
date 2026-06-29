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
    "clavex-haip":            ("HAIP",     "conformance-haip-badge.json"),
    "clavex-fapi2-ciba-poll": ("FAPI-CIBA", "conformance-ciba-badge.json"),
    "clavex-openid-federation-op": ("OpenID Federation", "conformance-federation-badge.json"),
}

# Regex for a Markdown table row: | plan | tests | passed | review | failed | rate% |
_ROW_RE = re.compile(
    r"^\|\s*(?P<plan>clavex-\S+)\s*"   # plan alias
    r"\|\s*(?P<tests>\d+)\s*"          # total tests
    r"\|\s*(?P<passed>\d+)\s*"         # passed
    r"\|\s*(?P<review>\d+)\s*"         # review
    r"\|\s*(?P<failed>\d+)\s*"         # failed
    r"\|\s*(?P<rate>\d+)%\s*\|",       # pass rate %
    re.IGNORECASE,
)


def _colour(pct: float) -> str:
    if pct >= 0.98:
        return "brightgreen"
    if pct >= 0.90:
        return "green"
    if pct >= 0.75:
        return "yellow"
    return "red"


def parse_conformance_md(path: str) -> dict[str, tuple[int, int, int]]:
    """
    Returns {plan_alias: (passed, skipped, total)} for every row found in the table.
    skipped = total - passed - review - failed  (tests not counted as pass/fail).
    """
    results: dict[str, tuple[int, int, int]] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = _ROW_RE.match(line.strip())
                if m:
                    plan   = m.group("plan")
                    total  = int(m.group("tests"))
                    passed = int(m.group("passed"))
                    review = int(m.group("review"))
                    failed = int(m.group("failed"))
                    skipped = max(0, total - passed - review - failed)
                    results[plan] = (passed, skipped, total)
    except FileNotFoundError:
        print(f"ERROR: {path} not found", file=sys.stderr)
        sys.exit(1)
    return results


def build_badge(label: str, passed: int, skipped: int, total: int) -> dict:
    pct = passed / total if total else 0.0
    colour = _colour(pct)
    # Floor (truncate) the percentage so badges match the "Pass rate" column in
    # CONFORMANCE.md, which is rendered with int truncation \u2014 never round up.
    rate = int(pct * 100)
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
        print("WARNING: no conformance table rows found in CONFORMANCE.md — badges unchanged", file=sys.stderr)
        sys.exit(0)

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
        print(f"  {badge_file:45s}  {label}: {passed}/{total} = {pct:.0f}%{skip_note}  →  {badge['message']} ({badge['color']})")

    if not written:
        print("No matching plan aliases found in CONFORMANCE.md — no badges updated", file=sys.stderr)
        sys.exit(1)

    # Top-level OIDC Conformance badge — aggregate of every plan in the table.
    overall = build_overall_badge(results)
    overall_path = os.path.join(out_dir, "conformance-badge.json")
    with open(overall_path, "w", encoding="utf-8") as f:
        json.dump(overall, f)
        f.write("\n")
    written.add("conformance-badge.json")
    print(f"  {'conformance-badge.json':45s}  OIDC Conformance  →  {overall['message']} ({overall['color']})")

    print(f"\nUpdated {len(written)} badge file(s) from {md_path}")


if __name__ == "__main__":
    main()

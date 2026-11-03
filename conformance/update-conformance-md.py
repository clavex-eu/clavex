#!/usr/bin/env python3
"""
conformance/update-conformance-md.py

Reads the current test results from an OIDF Conformance Suite instance and
rewrites CONFORMANCE.md at the repo root with an up-to-date table.

Called automatically by the nightly CI job after run-tests.py finishes.
Can also be run manually:

    python3 conformance/update-conformance-md.py \
        --suite-url https://www.certification.openid.net \
        --suite-token <token> \
        --op-base    https://id.clavex.eu

Outputs: CONFORMANCE.md (repo root)
"""

import argparse
import os
import re
import importlib.util
from plan_selection import latest_plans
from manual_review import collect_reviews, render_reviews
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

if os.environ.get("SUITE_INSECURE") == "1":
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OUT_FILE = "CONFORMANCE.md"

# Human-readable names for known plan aliases
PLAN_LABELS = {
    "clavex-basic":        "OIDC Basic OP (code + PKCE)",
    "clavex-basic-post":   "OIDC Basic OP (client_secret_post)",
    "clavex-config":       "OIDC Config OP (Discovery)",
    "clavex-dynamic":      "OIDC Dynamic OP (DCR)",
    "clavex-form-post":    "OIDC Form Post OP",
    "clavex-hybrid":       "OIDC Hybrid Flow",
    "clavex-par":          "PAR (RFC 9126)",
    "clavex-device":       "Device Authorization (RFC 8628)",
    "clavex-fapi-dpop":    "FAPI 2.0 Baseline — DPoP",
    "clavex-fapi-mtls":    "FAPI 2.0 Baseline — mTLS",
    "clavex-fapi-msig":    "FAPI 2.0 Message Signing",
    "clavex-ciba":         "CIBA Poll (OpenID CIBA Core)",
    "clavex-oid4vci-issuer": "OID4VCI Issuer (Final)",
    "clavex-oid4vp-verifier": "OID4VP Verifier (Final)",
}

RESULT_EMOJI = {
    "PASSED":      "✅",
    "REVIEW":      "🔍",
    "WARNING":     "⚠️",
    "FAILED":      "❌",
    "SKIPPED":     "⏭️",
    "INTERRUPTED": "⛔",
    "UNKNOWN":     "❓",
}


def _get(sess, suite_url, path):
    r = sess.get(f"{suite_url}{path}", verify=(os.environ.get("SUITE_CA_FILE") or os.environ.get("SUITE_INSECURE") != "1"), timeout=30)
    r.raise_for_status()
    return r.json()


def _plan_id(plan):
    return plan.get("_id") or plan.get("id") or plan.get("planId") or ""


def _plan_alias(plan):
    return (
        (plan.get("config") or {}).get("alias")
        or plan.get("alias")
        or plan.get("name")
        or _plan_id(plan)
    )


def _module_name(mod):
    return mod.get("testModule") or mod.get("testModuleName") or mod.get("name") or "?"


def _final_result(info):
    result = (info.get("result") or "").upper()
    status = (info.get("status") or "").upper()
    if result in ("PASSED", "FAILED", "REVIEW", "WARNING", "SKIPPED", "INTERRUPTED"):
        return result
    if status in ("FINISHED", "INTERRUPTED", "SKIPPED"):
        return status
    return "UNKNOWN"


def fetch_results(sess, suite_url):
    """Return list of (alias, label, modules_results) tuples, deduplicated by creation timestamp."""
    try:
        raw = _get(sess, suite_url, "/api/plan?length=1000")
    except Exception as e:
        print(f"ERROR: cannot reach suite at {suite_url}: {e}", file=sys.stderr)
        sys.exit(1)

    if isinstance(raw, dict):
        raw_plans = raw.get("data") or []
    else:
        raw_plans = raw or []

    plans = [p if isinstance(p, dict) else {"_id": str(p)} for p in raw_plans]

    # Enrich with module list
    enriched = []
    for p in plans:
        if "modules" not in p:
            try:
                detail = _get(sess, suite_url, f"/api/plan/{_plan_id(p)}")
                p = {**p, **detail}
            except Exception:
                pass
        enriched.append(p)

    deduped = latest_plans(enriched)

    results = []
    for plan in deduped:
        alias = _plan_alias(plan)
        label = PLAN_LABELS.get(alias, alias)
        modules = plan.get("modules") or []
        mod_results = []
        for mod in modules:
            name = _module_name(mod)
            instances = mod.get("instances") or []
            last_inst = instances[-1] if instances else None
            result = "UNKNOWN"
            suite_url_link = ""
            if last_inst:
                try:
                    info = _get(sess, suite_url, f"/api/info/{last_inst}")
                    result = _final_result(info)
                    suite_url_link = f"{suite_url}/log-detail.html?log={last_inst}"
                except Exception:
                    pass
            mod_results.append((name, result, suite_url_link))
        results.append((alias, label, mod_results))

    return results


def build_badge_url(passed, total):
    """Build a shields.io badge URL for embedding in README."""
    colour = "red"
    if total > 0:
        pct = passed / total
        if pct >= 0.98:
            colour = "brightgreen"
        elif pct >= 0.90:
            colour = "green"
        elif pct >= 0.75:
            colour = "yellow"
    label = f"OIDC%20Conformance"
    message = f"{passed}%2F{total}%20tests%20passing"
    return f"https://img.shields.io/badge/{label}-{message}-{colour}"


def render_md(results, op_base, suite_url, run_ts, manual_rows=None):
    """Return the full CONFORMANCE.md content as a string."""
    total_passed = sum(
        1 for _, _, mods in results
        for _, r, _ in mods if r == "PASSED"
    )
    total_review = sum(
        1 for _, _, mods in results
        for _, r, _ in mods if r == "REVIEW"
    )
    total_tests = sum(len(mods) for _, _, mods in results)

    badge_url = build_badge_url(total_passed, total_tests)
    ts_human = run_ts.strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append(f"# Clavex — OIDF Conformance Results\n")
    lines.append(
        f"[![OIDC Conformance]({badge_url})]({suite_url})\n"
    )
    lines.append(
        f"> **Last run:** {ts_human}  |  "
        f"**OP:** `{op_base}`  |  "
        f"**Suite:** [{suite_url}]({suite_url})\n"
    )
    lines.append(
        "_Results are derived from suite records. "
        "REVIEW requires case-specific human evidence and validation; "
        "it is not automatically passed. Skipped and incomplete cases are not passes. "
        "See the reproduction guide at `conformance/REPRODUCIBILITY.md` for "
        "version scope, reporting limitations and tooling availability. "
        "Suite results are not certification._\n"
    )

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Plan | Tests | ✅ Passed | 🔍 Review | ❌ Failed | Skipped | Other / incomplete | Pass rate |")
    lines.append("|------|------:|----------:|----------:|----------:|--------:|-------------------:|----------:|")

    for alias, label, mods in results:
        p = sum(1 for _, r, _ in mods if r == "PASSED")
        rv = sum(1 for _, r, _ in mods if r == "REVIEW")
        f = sum(1 for _, r, _ in mods if r == "FAILED")
        skipped = sum(1 for _, r, _ in mods if r == "SKIPPED")
        other = len(mods) - p - rv - f - skipped
        t = len(mods)
        rate = f"{100*p//t}%" if t else "—"  # floor — keep in sync with badge generator
        slug = re.sub(r"[^a-z0-9_-]+", "-", alias.lower())
        lines.append(f"| [{label}](#{slug}) | {t} | {p} | {rv} | {f} | {skipped} | {other} | **{rate}** |")

    lines.append("")

    # Per-plan detail
    lines.append("## Per-plan Results\n")

    for alias, label, mods in results:
        slug = re.sub(r"[^a-z0-9_-]+", "-", alias.lower())
        p = sum(1 for _, r, _ in mods if r == "PASSED")
        t = len(mods)
        lines.append(f'<a id="{slug}"></a>\n')
        lines.append(f"### {label}\n")
        lines.append(f"**Alias:** `{alias}` &nbsp;|&nbsp; **{p}/{t} passing**\n")
        lines.append("| Test module | Result | Log |")
        lines.append("|-------------|--------|-----|")
        for name, result, link in mods:
            emoji = RESULT_EMOJI.get(result, "❓")
            log_cell = f"[view]({link})" if link else "—"
            lines.append(f"| `{name}` | {emoji} {result} | {log_cell} |")
        lines.append("")

    if manual_rows is not None:
        lines.append(render_reviews(manual_rows))

    lines.append("---")
    lines.append(
        f"_Auto-generated by `conformance/update-conformance-md.py` "
        f"at {ts_human}._\n"
    )

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Update CONFORMANCE.md from suite API")
    ap.add_argument("--suite-url", default="https://localhost.emobix.co.uk:8443")
    ap.add_argument("--suite-token", default=os.environ.get("SUITE_TOKEN"))
    ap.add_argument("--op-base", default="https://id.clavex.eu")
    ap.add_argument("--review-registry", default=None, help="Local per-instance review registry (default: conformance/.local/manual-reviews.jsonl)")
    ap.add_argument("--out", default=OUT_FILE, help="Output file path")
    args = ap.parse_args()

    sess = requests.Session()
    if args.suite_token:
        sess.headers["Authorization"] = f"Bearer {args.suite_token}"

    print(f"Fetching results from {args.suite_url} …")
    results = fetch_results(sess, args.suite_url)

    if not results:
        print("No plans found — CONFORMANCE.md not updated.", file=sys.stderr)
        sys.exit(0)

    run_ts = datetime.now(timezone.utc)
    review_args = {"path": args.review_registry} if args.review_registry else {}
    manual_rows = collect_reviews(sess, args.suite_url, results, **review_args)
    md = render_md(results, args.op_base, args.suite_url, run_ts, manual_rows)

    with open(args.out, "w") as f:
        f.write(md)

    total_passed = sum(
        1 for _, _, mods in results for _, r, _ in mods if r == "PASSED"
    )
    total_tests = sum(len(mods) for _, _, mods in results)

    # Use the same parser/writer as the push-triggered badge workflow.
    spec = importlib.util.spec_from_file_location("conformance_badges", os.path.join(os.path.dirname(__file__), "update-badges-from-md.py"))
    badges = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(badges)
    badges.write_badges(badges.parse_conformance_md(args.out), os.path.dirname(os.path.abspath(args.out)))

    print(
        f"Written {args.out}  ({total_passed}/{total_tests} passing, "
        f"{len(results)} plans)"
    )


if __name__ == "__main__":
    main()

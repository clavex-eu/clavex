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
import sys
import time
from datetime import datetime, timezone

import requests
import urllib3

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
    r = sess.get(f"{suite_url}{path}", verify=False, timeout=30)
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
    """Return list of (alias, label, modules_results) tuples, newest-first deduped."""
    try:
        raw = _get(sess, suite_url, "/api/plan")
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

    # Deduplicate: keep newest per alias (API returns newest-first)
    seen = set()
    deduped = []
    for p in enriched:
        alias = _plan_alias(p)
        if alias not in seen:
            seen.add(alias)
            deduped.append(p)

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


def render_md(results, op_base, suite_url, run_ts):
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
        "_Results are updated automatically by the nightly CI job "
        "(`.github/workflows/conformance.yml`). "
        "🔍 REVIEW tests require a manual screenshot upload on the suite UI — "
        "they are functionally correct._\n"
    )

    # Summary table
    lines.append("## Summary\n")
    lines.append("| Plan | Tests | ✅ Passed | 🔍 Review | ❌ Failed | Pass rate |")
    lines.append("|------|------:|----------:|----------:|----------:|----------:|")

    for alias, label, mods in results:
        p = sum(1 for _, r, _ in mods if r == "PASSED")
        rv = sum(1 for _, r, _ in mods if r == "REVIEW")
        f = sum(1 for _, r, _ in mods if r in ("FAILED", "INTERRUPTED"))
        t = len(mods)
        rate = f"{int(p/t*100)}%" if t else "—"  # floor — keep in sync with badge generator
        slug = alias.replace(" ", "-").lower()
        lines.append(f"| [{label}](#{slug}) | {t} | {p} | {rv} | {f} | **{rate}** |")

    lines.append("")

    # Per-plan detail
    lines.append("## Per-plan Results\n")

    for alias, label, mods in results:
        slug = alias.replace(" ", "-").lower()
        p = sum(1 for _, r, _ in mods if r == "PASSED")
        t = len(mods)
        lines.append(f"### {label}\n")
        lines.append(f"**Alias:** `{alias}` &nbsp;|&nbsp; **{p}/{t} passing**\n")
        lines.append("| Test module | Result | Log |")
        lines.append("|-------------|--------|-----|")
        for name, result, link in mods:
            emoji = RESULT_EMOJI.get(result, "❓")
            log_cell = f"[view]({link})" if link else "—"
            lines.append(f"| `{name}` | {emoji} {result} | {log_cell} |")
        lines.append("")

    lines.append("---")
    lines.append(
        f"_Auto-generated by `conformance/update-conformance-md.py` "
        f"at {ts_human}._\n"
    )

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Update CONFORMANCE.md from suite API")
    ap.add_argument("--suite-url", default="https://localhost.emobix.co.uk:8443")
    ap.add_argument("--suite-token", default=None)
    ap.add_argument("--op-base", default="https://id.clavex.eu")
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
    md = render_md(results, args.op_base, args.suite_url, run_ts)

    with open(args.out, "w") as f:
        f.write(md)

    total_passed = sum(
        1 for _, _, mods in results for _, r, _ in mods if r == "PASSED"
    )
    total_tests = sum(len(mods) for _, _, mods in results)

    # Write a shields.io endpoint JSON so README badge stays current.
    import json, os
    badge_colour = "red"
    if total_tests > 0:
        pct = total_passed / total_tests
        badge_colour = "brightgreen" if pct >= 0.98 else "green" if pct >= 0.90 else "yellow" if pct >= 0.75 else "red"
    badge_data = {
        "schemaVersion": 1,
        "label": "OIDC Conformance",
        "message": f"{total_passed}/{total_tests} passing",
        "color": badge_colour,
    }
    badge_path = os.path.join(os.path.dirname(args.out), "conformance-badge.json")
    with open(badge_path, "w") as f:
        json.dump(badge_data, f)

    # Per-suite badges for README (FAPI 2.0, JARM, mTLS, OID4VCI, OID4VP)
    PER_PLAN_BADGES = {
        "clavex-fapi":           ("FAPI 2.0", "conformance-fapi-badge.json"),
        "clavex-fapi-dpop":      ("FAPI 2.0", "conformance-fapi-badge.json"),
        "clavex-fapi-jarm":      ("JARM",     "conformance-jarm-badge.json"),
        "clavex-fapi-mtls":      ("mTLS",     "conformance-mtls-badge.json"),
        "clavex-oid4vci-issuer": ("OID4VCI",  "conformance-oid4vci-badge.json"),
        "clavex-oid4vp-verifier":("OID4VP",   "conformance-oid4vp-badge.json"),
        "clavex-haip":           ("HAIP",     "conformance-haip-badge.json"),
        "clavex-fapi2-ciba-poll":("FAPI-CIBA", "conformance-ciba-badge.json"),
        "clavex-openid-federation-op": ("OpenID Federation", "conformance-federation-badge.json"),
    }
    written_badges = set()
    for alias, _label, mods in results:
        if alias not in PER_PLAN_BADGES or not mods:
            continue
        badge_label, badge_file = PER_PLAN_BADGES[alias]
        if badge_file in written_badges:
            continue
        written_badges.add(badge_file)
        p = sum(1 for _, r, _ in mods if r == "PASSED")
        t = len(mods)
        pct = p / t if t else 0
        colour = (
            "brightgreen" if pct >= 0.95 else
            "green"       if pct >= 0.90 else
            "yellow"      if pct >= 0.75 else
            "red"
        )
        # OID4VCI / OID4VP badges show a pass/fail checkmark instead of a %.
        if badge_file in ("conformance-oid4vci-badge.json", "conformance-oid4vp-badge.json"):
            message = "\u2713" if pct >= 0.95 else ("\u2717" if t else "\u2014")
        else:
            message = f"{int(pct*100)}%" if t else "\u2014"  # floor \u2014 match CONFORMANCE.md
        per_badge = {
            "schemaVersion": 1,
            "label": badge_label,
            "message": message,
            "color": colour,
        }
        per_path = os.path.join(os.path.dirname(args.out), badge_file)
        with open(per_path, "w") as f:
            json.dump(per_badge, f)
        print(f"Written {per_path}  ({badge_label}: {p}/{t} = {pct*100:.0f}%)")

    print(
        f"Written {args.out}  ({total_passed}/{total_tests} passing, "
        f"{len(results)} plans)"
    )


if __name__ == "__main__":
    main()

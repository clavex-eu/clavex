"""Shared plan selection for execution and published reports (no suite I/O)."""
import datetime

def _plan_id(p):
    return p.get("_id") or p.get("id") or p.get("planId") or ""

def _plan_alias(p):
    return (p.get("config") or {}).get("alias") or p.get("alias") or p.get("name") or _plan_id(p)

def latest_plans(plans: list[dict]) -> list[dict]:
    """Select by the actual creation timestamp, independent of API ordering."""
    latest = {}
    timestamps = {}
    for plan in plans:
        alias = _plan_alias(plan)
        raw = plan.get("started")
        try:
            stamp = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=datetime.timezone.utc)
        except (AttributeError, TypeError, ValueError):
            stamp = None
        if alias in latest and (stamp is None or timestamps[alias] is None):
            raise ValueError(f"Duplicate plan alias {alias} has no valid creation timestamp; select an exact plan ID")
        if alias not in latest or stamp > timestamps[alias]:
            latest[alias], timestamps[alias] = plan, stamp
    return list(latest.values())

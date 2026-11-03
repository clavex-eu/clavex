"""Bounded plan concurrency; modules within a plan always remain sequential."""
import asyncio
from contextlib import asynccontextmanager


def plan_resources(plan):
    clients = set()
    def walk(value):
        if isinstance(value, dict):
            client = value.get('client_id')
            if isinstance(client, str) and client:
                clients.add('client:' + client)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)
    walk(plan.get('config') or {})
    names = [module.get('testModule', module.get('name', '')) for module in plan.get('modules', [])]
    # Unknown client allocation, federation setup and logout may mutate shared
    # tenant state, or depend on tight expiry timing (CIBA). Run them exclusively.
    if not clients or any('logout' in name or 'federation' in name or 'ciba' in name for name in names):
        return {'*'}
    alias = (plan.get('config') or {}).get('alias') or plan.get('alias') or plan.get('_id') or plan.get('id')
    clients.add('alias:' + str(alias))
    return clients


class PlanGate:
    def __init__(self, jobs):
        self.jobs = jobs
        self.condition = asyncio.Condition()
        self.active = []

    @asynccontextmanager
    async def reserve(self, plan):
        resources = plan_resources(plan)
        async with self.condition:
            def available():
                return len(self.active) < self.jobs and all(
                    '*' not in resources and '*' not in current and resources.isdisjoint(current)
                    for current in self.active
                )
            await self.condition.wait_for(available)
            self.active.append(resources)
        try:
            yield
        finally:
            async with self.condition:
                self.active.remove(resources)
                self.condition.notify_all()

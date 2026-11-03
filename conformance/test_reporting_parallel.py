"""Offline report/badge and scheduling checks; never starts a real suite module."""
import asyncio
import contextlib
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from plan_scheduler import PlanGate, plan_resources

ROOT=Path(__file__).resolve().parent

def module(filename):
    spec=importlib.util.spec_from_file_location(filename.replace('-','_'),ROOT/filename)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


class ReportingTests(unittest.TestCase):
    def test_real_report_generator_and_badges_preserve_skips_and_incomplete(self):
        report=module('update-conformance-md.py');badges=module('update-badges-from-md.py')
        results=[('clavex-fapi','FAPI Label',[('pass','PASSED',''),('skip','SKIPPED',''),('manual','INTERRUPTED',''),('failure','FAILED','')])]
        md=report.render_md(results,'https://op.example','https://suite.example',datetime.now(timezone.utc))
        self.assertIn('| Skipped | Other / incomplete |',md)
        self.assertIn('<a id="clavex-fapi"></a>', md)
        self.assertIn('| 4 | 1 | 0 | 1 | 1 | 1 | **25%** |',md)
        self.assertNotIn('they are functionally correct',md)
        self.assertEqual(badges.build_badge('Test',29,0,100)['message'],'29%')
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'CONFORMANCE.md';path.write_text(md)
            parsed=badges.parse_conformance_md(str(path));self.assertEqual(parsed,{'clavex-fapi':(1,1,4)})
            with contextlib.redirect_stdout(io.StringIO()):badges.write_badges(parsed,tmp)
            self.assertEqual(json.loads((Path(tmp)/'conformance-fapi-badge.json').read_text())['message'],'25% · 1 skipped')
            self.assertEqual(json.loads((Path(tmp)/'conformance-badge.json').read_text())['message'],'1/4 passing')
            path.write_text('| Plan | Tests | Passed | Review | Failed | Pass rate |\n|---|---|---|---|---|---|\n| clavex-fapi | 4 | 1 | 1 | 0 | 25% |\n')
            self.assertEqual(badges.parse_conformance_md(str(path)),{'clavex-fapi':(1,0,4)},'unknown historical remainder must not be invented as skipped')

    def test_report_api_tls_and_oldest_first_plans(self):
        report=module('update-conformance-md.py')
        old={'_id':'old','config':{'alias':'same'},'started':'2026-11-02T10:00:00Z','modules':[]}
        new={'_id':'new','config':{'alias':'same'},'started':'2026-11-02T19:00:00Z','modules':[{'testModule':'module','instances':['instance']} ]}
        class Session:
            def get(self,url,**kw):
                self.verify=kw['verify']
                if '/api/plan?' in url:
                    assert 'length=1000' in url
                    body={'data':[old,new]}
                else:body={'result':'SKIPPED','status':'SKIPPED'}
                return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:body)
        sess=Session()
        with patch.dict(os.environ,{'SUITE_CA_FILE':'/explicit/test-ca.pem'},clear=True):
            results=report.fetch_results(sess,'https://suite.example')
        self.assertEqual(sess.verify,'/explicit/test-ca.pem')
        self.assertEqual(results[0][2][0][1],'SKIPPED')


class PlanSchedulingTests(unittest.TestCase):
    def test_disjoint_plans_overlap_shared_clients_and_unknown_plans_do_not(self):
        async def scenario():
            gate=PlanGate(2);active={};overlaps=[];peak=0
            def plan(alias,clients):return {'config':{'alias':alias,**{f'client{i}':{'client_id':c}for i,c in enumerate(clients)}}}
            async def run(alias,clients):
                nonlocal peak
                async with gate.reserve(plan(alias,clients)):
                    for other,otherclients in active.items():
                        self.assertTrue(clients and otherclients)
                        self.assertTrue(set(clients).isdisjoint(otherclients))
                        overlaps.append((alias,other))
                    active[alias]=clients;peak=max(peak,len(active))
                    await asyncio.sleep(0.03)
                    active.pop(alias)
            await asyncio.gather(run('first',['one']),run('second',['two']),run('shared',['one']),run('unknown',[]))
            self.assertEqual(peak,2);self.assertTrue(overlaps);self.assertFalse(gate.active)
        asyncio.run(scenario())

    def test_timing_sensitive_or_global_state_plans_are_exclusive(self):
        for name in ['fapi-ciba-id1-auth-req-id-expired','oidcc-logout','openid-federation-op']:
            self.assertEqual(plan_resources({'config':{'client':{'client_id':'known'}},'modules':[{'testModule':name}]}),{'*'})

    def test_release_on_cancellation_does_not_lock_later_plan(self):
        async def scenario():
            gate=PlanGate(1);entered=asyncio.Event();p={'config':{'client':{'client_id':'same'}}}
            async def waiting():
                async with gate.reserve(p):
                    entered.set();await asyncio.sleep(60)
            task=asyncio.create_task(waiting());await entered.wait();task.cancel()
            with self.assertRaises(asyncio.CancelledError):await task
            async with gate.reserve(p):pass
            self.assertFalse(gate.active)
        asyncio.run(scenario())

    def test_main_parallel_execution_keeps_shared_clients_serial_and_counts_results(self):
        runner=module('run-tests.py')
        plans=[{'_id':alias,'config':{'alias':alias,'client':{'client_id':client}},'modules':[{'testModule':'success'},{'testModule':'skip'}]} for alias,client in [('one','shared'),('two','independent'),('three','shared')]]
        active={};calls=[]
        class Session:
            headers={}
            def get(self,*a,**kw):return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:plans)
            def post(self,*a,**kw):raise AssertionError('No real suite module may be created')
        async def fake_module(**kwargs):
            plan_id=kwargs['plan_id'];client=next(p['config']['client']['client_id']for p in plans if p['_id']==plan_id)
            self.assertNotIn(plan_id,active)
            self.assertNotIn(client,active.values())
            active[plan_id]=client
            await asyncio.sleep(0.01)
            active.pop(plan_id);calls.append(plan_id)
            return 'SKIPPED' if kwargs['module_name']=='skip' else 'PASSED'
        with patch.object(runner.requests,'Session',return_value=Session()),patch.object(runner,'_suite_browser_args',return_value=[]),patch.object(runner,'run_module',side_effect=fake_module),patch('sys.argv',['runner','--jobs','2']),contextlib.redirect_stdout(io.StringIO())as output:
            asyncio.run(runner.main())
        self.assertEqual(len(calls),6);self.assertFalse(active)
        self.assertIn('(6 total)',output.getvalue())
        self.assertIn('3 SKIPPED',output.getvalue())

    def test_retry_failed_does_not_repeat_passed_or_skipped_modules(self):
        runner=module('run-tests.py');called=[]
        plan={'_id':'local','config':{'alias':'local','client':{'client_id':'test'}},'modules':[{'testModule':name,'instances':[name]} for name in ['PASSED','SKIPPED','FAILED']]}
        class Session:
            headers={}
            def get(self,url,**kw):
                data=[plan] if '/api/plan?' in url else {'status':'FINISHED','result':url.rsplit('/',1)[-1]}
                return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:data)
        async def fake_module(**kwargs):
            called.append(kwargs['module_name']);return 'PASSED'
        with patch.object(runner.requests,'Session',return_value=Session()),patch.object(runner,'_suite_browser_args',return_value=[]),patch.object(runner,'run_module',side_effect=fake_module),patch('sys.argv',['runner','--rerun-failed']),contextlib.redirect_stdout(io.StringIO())as output:
            asyncio.run(runner.main())
        self.assertEqual(called,['FAILED'])
        self.assertIn('(3 total)',output.getvalue())
        self.assertIn('1 SKIPPED',output.getvalue())

    def test_manual_evidence_option_never_starts_a_module(self):
        runner=module('run-tests.py')
        policies=json.loads((ROOT/'manual-evidence.json').read_text())
        class Session:
            headers = {}
            def get(self,url,**kwargs):
                data=[{'_id':'local','config':{'alias':'clavex-test','client':{'client_id':'test'}},'modules':[{'testModule':next(iter(policies))}]}]
                return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:data)
            def post(self,*a,**kw):raise AssertionError('Must not create or start a module')
        with patch.object(runner.requests,'Session',return_value=Session()),patch.object(runner,'_suite_browser_args',return_value=[]),patch('sys.argv',['runner','--skip-manual-evidence','--jobs','2']),contextlib.redirect_stdout(io.StringIO()) as output:
            asyncio.run(runner.main())
        self.assertIn('MANUAL_REQUIRED',output.getvalue())
        self.assertIn('no instance started',output.getvalue())


if __name__=='__main__':unittest.main()

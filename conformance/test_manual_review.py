"""Offline review/evidence checks. No real suite mutations or module execution."""
import asyncio
import base64
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

import manual_review as review

PNG = base64.b64decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jZ1kAAAAASUVORK5CYII=')
IMAGE = 'data:image/png;base64,' + base64.b64encode(PNG).decode()
SUITE = 'https://suite.example'


class Session:
    def __init__(self):
        self.info = {'testName': 'module', 'planId': 'plan', 'status': 'INTERRUPTED', 'result': 'REVIEW'}
        self.images = [{'_id': 'entry', 'img': IMAGE}]
        self.posts = []
        self.verifies = []

    def get(self, url, **kwargs):
        self.verifies.append(kwargs['verify'])
        body = self.images if url.endswith('/images') else self.info
        return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: copy.deepcopy(body))

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        placeholder = url.rsplit('/', 1)[-1]
        for image in self.images:
            if image.get('upload') == placeholder:
                image.pop('upload')
                image['img'] = kwargs['data']
                self.info['result'] = 'REVIEW'
                return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: copy.deepcopy(image))
        return types.SimpleNamespace(raise_for_status=lambda: None, json=lambda: None)


class ManualReviewTests(unittest.TestCase):
    def test_append_decisions_bind_suite_instance_images_and_result(self):
        session = Session()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'reviews.jsonl'
            with patch.dict(os.environ, {'SUITE_CA_FILE': '/public/ca.pem'}, clear=True):
                review.record_review(session, SUITE, 'instance', 'approved', 'Reviewer', 'Looks correct', path)
            records = review.load_records(path)
            self.assertEqual(review.review_state(records, SUITE, 'instance', session.info, session.images), 'approved')
            self.assertIsNone(review.review_state(records, SUITE, 'new-instance', session.info, session.images))
            self.assertIsNone(review.review_state(records, 'https://other.example', 'instance', session.info, session.images))
            changed = {**session.info, 'result': 'FAILED'}
            self.assertEqual(review.review_state(records, SUITE, 'instance', changed, session.images), 'stale')
            self.assertEqual(review.review_state(records, SUITE, 'instance', session.info, [{'_id': 'other', 'img': IMAGE}]), 'stale')
            review.record_review(session, SUITE, 'instance', 'rejected', 'Reviewer', 'Correction', path)
            self.assertEqual(len(review.load_records(path)), 2)
            self.assertEqual(review.review_state(review.load_records(path), SUITE, 'instance', session.info, session.images), 'rejected')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(session.posts, [], 'Local decisions must never update the suite')
        self.assertIn('/public/ca.pem', session.verifies)

    def test_missing_pending_running_failed_and_skipped_cannot_be_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            for status, result, images in [('INTERRUPTED', None, []), ('INTERRUPTED', None, [{'_id':'entry','upload':'pending'}]), ('RUNNING', None, [{'_id':'entry','img':IMAGE}]), ('FINISHED','FAILED',[{'_id':'entry','img':IMAGE}]), ('SKIPPED','SKIPPED',[{'_id':'entry','img':IMAGE}])]:
                session=Session();session.info.update(status=status,result=result);session.images=images
                with self.assertRaises(ValueError):
                    review.record_review(session,SUITE,'instance','approved','Reviewer','Reviewed',Path(tmp)/'reviews')
            self.assertFalse((Path(tmp)/'reviews').exists())
        for value in ['../other', 'id?query', 'id/other']:
            with self.assertRaises(ValueError):review.instance_path(value)

    def test_waiting_review_with_complete_images_can_be_reviewed_without_suite_write(self):
        session = Session()
        session.info.update(status='WAITING', result='REVIEW')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'reviews'
            review.record_review(session, SUITE, 'instance', 'approved', 'Reviewer', 'Image verified', path)
            records = review.load_records(path)
            self.assertEqual(records[0]['snapshot']['status'], 'WAITING')
            self.assertEqual(review.review_state(records, SUITE, 'instance', session.info, session.images), 'approved')
            self.assertEqual(session.posts, [])
            self.assertEqual(session.info['status'], 'WAITING')
            for result, images in [(None, session.images), ('REVIEW', []), ('REVIEW', [{'_id':'entry','img':IMAGE,'upload':'pending'}])]:
                session.info['result'] = result
                session.images = images
                with self.assertRaises(ValueError):
                    review.record_review(session, SUITE, 'other', 'approved', 'Reviewer', 'Image verified', path)
            self.assertEqual(len(review.load_records(path)), 1)

    def test_capture_upload_is_real_scoped_and_does_not_approve(self):
        session=Session();session.info.update(status='WAITING',result=None)
        session.images=[{'_id':'entry','upload':'placeholder'}]
        calls=[]
        async def screenshot(**kwargs):calls.append(kwargs);return PNG
        page=types.SimpleNamespace(url='https://op.example/error',screenshot=screenshot)
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(asyncio.run(review.capture_pending(session,SUITE,'instance',page,tmp)))
            self.assertEqual(len(calls),1)
            self.assertEqual(session.posts[0][0],SUITE+'/api/log/instance/images/placeholder')
            self.assertEqual(len(list(Path(tmp).rglob('*.png'))),1)
            metadata=json.loads(next(Path(tmp).rglob('*.json')).read_text())
            self.assertIsNone(metadata['decision'])
            self.assertEqual(metadata['before_upload'],{'status':'WAITING','result':None})
            self.assertFalse(asyncio.run(review.capture_pending(session,SUITE,'instance',page,tmp)))
            session.images=[{'_id':'one','upload':'p1'},{'_id':'two','upload':'p2'}]
            self.assertFalse(asyncio.run(review.capture_pending(session,SUITE,'instance',page,tmp)))
            session.info['result']='FAILED'
            with self.assertRaises(ValueError):review.upload_image(session,SUITE,'instance','p1',PNG)
            self.assertEqual(len(session.posts),1)
            session.info['result']=None
            with self.assertRaises(ValueError):review.upload_image(session,SUITE,'instance','missing',PNG)
            self.assertEqual(len(session.posts),1)

    def test_report_keeps_suite_pass_counts_and_invalidates_unavailable_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'reviews';session=Session()
            review.record_review(session,SUITE,'instance','approved','Reviewer','Correct | screen\nverified',path)
            results=[('clavex-basic','Plan',[('module','REVIEW',SUITE+'/log-detail.html?log=instance')])]
            rows=review.collect_reviews(session,SUITE,results,path)
            self.assertEqual(rows[0]['state'],'approved')
            spec=importlib.util.spec_from_file_location('report',Path(__file__).with_name('update-conformance-md.py'))
            report=importlib.util.module_from_spec(spec);spec.loader.exec_module(report)
            md=report.render_md(results,'https://op.example',SUITE,datetime.now(timezone.utc),rows)
            self.assertIn('0%2F1%20tests%20passing',md)
            self.assertIn('| 1 | 0 | 1 | 0 | 0 | 0 | **0%** |',md)
            self.assertIn('approved',md);self.assertIn('&#124;',md)
            badge_spec=importlib.util.spec_from_file_location('badges',Path(__file__).with_name('update-badges-from-md.py'))
            badges=importlib.util.module_from_spec(badge_spec);badge_spec.loader.exec_module(badges)
            report_file=Path(tmp)/'CONFORMANCE.md';report_file.write_text(md)
            self.assertEqual(badges.parse_conformance_md(str(report_file)),{'clavex-basic':(0,0,1)})
            with patch.object(session,'get',side_effect=RuntimeError('offline')):
                self.assertEqual(review.collect_reviews(session,SUITE,results,path)[0]['state'],'unverified')
            self.assertEqual(review.collect_reviews(session,SUITE,[('plan','Plan',[('module','REVIEW',SUITE+'/log-detail.html?log=new')])],path),[])


class RunnerEvidenceTests(unittest.TestCase):
    def test_runner_uploads_current_login_screen_without_submitting_or_approving(self):
        import argparse
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        import threading
        spec=importlib.util.spec_from_file_location('evidence_runner',Path(__file__).with_name('run-tests.py'))
        runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        state={'opened':0,'submitted':0,'uploaded':False}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                state['opened']+=1
                self.send_response(200);self.end_headers()
                self.wfile.write(b'<html><body>Login required<input type="password"></body></html>')
            def do_POST(self):
                state['submitted']+=1
                self.send_response(400);self.end_headers()
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        auth_url=f'http://127.0.0.1:{server.server_port}/authorize'
        class FakeSession:
            def response(self,body):return types.SimpleNamespace(raise_for_status=lambda:None,json=lambda:body)
            def get(self,url,**kwargs):
                if url.endswith('/images'):
                    body=[{'_id':'entry','upload':'slot'}] if state['opened'] and not state['uploaded'] else []
                elif '/browser/' in url:body={'urls':[] if state['opened'] else [auth_url]}
                else:body={'status':'FINISHED' if state['uploaded'] else 'WAITING','result':'REVIEW' if state['uploaded'] else None}
                return self.response(body)
            def post(self,url,**kwargs):
                if '/images/' in url:
                    self_image=review.image_bytes(kwargs['data'])
                    assert self_image.startswith(b'\x89PNG')
                    state['uploaded']=True
                    return self.response({'_id':'entry','img':kwargs['data']})
                if '/visit' in url:return types.SimpleNamespace(raise_for_status=lambda:None)
                return self.response({'id':'local-evidence'})
        try:
            with tempfile.TemporaryDirectory() as tmp:
                args=argparse.Namespace(browser_behaviors={},suite_url=SUITE,headful=False,
                    browser_launch_args=['--no-sandbox'],timeout=20,email='test',password='test',
                    upload_screenshots=True,evidence_dir=tmp)
                result=asyncio.run(runner.run_module(plan_id='plan',module_name='module',module_variant={},sess=FakeSession(),args=args))
                self.assertEqual(result,'REVIEW')
                self.assertTrue(state['uploaded']);self.assertEqual(state['submitted'],0)
                self.assertEqual(len(list(Path(tmp).rglob('*.png'))),1)
                self.assertFalse((Path(tmp)/'manual-reviews.jsonl').exists())
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_status_report_retains_raw_counts_and_links_local_decisions(self):
        import argparse
        import contextlib
        import io
        spec=importlib.util.spec_from_file_location('status_runner',Path(__file__).with_name('run-tests.py'))
        runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        plans=[{'_id':'plan','config':{'alias':'example'},'modules':[{'testModule':'module','instances':['instance']}]}]
        rows=[{'alias':'example','module':'module','instance':'instance','suite_result':'REVIEW','state':'approved','reviewer':'Reviewer','note':'Checked','link':SUITE+'/log-detail.html?log=instance'}]
        with patch.object(runner,'_suite_get',return_value={'status':'FINISHED','result':'REVIEW'}),patch.object(runner,'collect_reviews',return_value=rows),patch.object(runner,'_update_conformance_md') as update,contextlib.redirect_stdout(io.StringIO()) as output:
            asyncio.run(runner.status_mode(Session(),argparse.Namespace(suite_url=SUITE),plans))
        self.assertIn('Manual approved',output.getvalue())
        self.assertEqual(update.call_args.args[0],[('example',[('module','REVIEW')])])
        self.assertEqual(update.call_args.args[1],rows)


if __name__ == '__main__':
    unittest.main()

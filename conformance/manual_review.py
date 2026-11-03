"""Local decisions preserve suite verdicts; image uploads use the official API."""
import base64
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

DEFAULT_REGISTRY = Path(__file__).resolve().parent / '.local/manual-reviews.jsonl'


def suite_identity(url):
    parts = urlsplit(url)
    if parts.scheme not in ('https', 'http') or not parts.netloc or parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError('Expected a suite URL without credentials, query or fragment')
    return url.rstrip('/')


def instance_path(instance):
    if not re.fullmatch(r'[A-Za-z0-9_-]+', instance):
        raise ValueError('Invalid instance ID')
    return instance


def api(session, suite, path, method='get', **kwargs):
    response = getattr(session, method)(suite_identity(suite) + path, timeout=30,
        verify=os.environ.get('SUITE_CA_FILE') or os.environ.get('SUITE_INSECURE') != '1', **kwargs)
    response.raise_for_status()
    return response.json()


def image_bytes(encoded):
    if not isinstance(encoded, str) or not encoded.startswith(('data:image/png;base64,', 'data:image/jpeg;base64,')):
        raise ValueError('Expected a PNG/JPEG data URI')
    data = base64.b64decode(encoded.split(',', 1)[1], validate=True)
    if len(data) > 10 * 1024 * 1024 or not data.startswith((b'\x89PNG\r\n\x1a\n', b'\xff\xd8\xff')):
        raise ValueError('Invalid or oversized PNG/JPEG evidence')
    return data


def evidence_snapshot(info, images):
    evidence = []
    pending = []
    for entry in images:
        if entry.get('upload'):
            pending.append(str(entry['upload']))
        if entry.get('img'):
            evidence.append({'entry': str(entry['_id']), 'sha256': hashlib.sha256(image_bytes(entry['img'])).hexdigest()})
    return {'module': info.get('testName'), 'plan_id': info.get('planId'),
        'status': info.get('status'), 'result': info.get('result'),
        'pending': sorted(pending), 'images': sorted(evidence, key=lambda e: e['entry'])}


def load_records(path=DEFAULT_REGISTRY):
    path = Path(path)
    if not path.exists():
        return []
    with path.open() as stream:
        fcntl.flock(stream, fcntl.LOCK_SH)
        records = [json.loads(line) for line in stream if line.strip()]
    for record in records:
        if record.get('schema') != 1 or record.get('decision') not in ('approved', 'rejected'):
            raise ValueError('Invalid manual review registry')
    return records


def record_review(session, suite, instance, decision, reviewer, note, path=DEFAULT_REGISTRY):
    if decision not in ('approved', 'rejected') or not reviewer.strip() or not note.strip():
        raise ValueError('Decision, reviewer and note are required')
    instance_path(instance)
    info = api(session, suite, '/api/info/' + instance)
    images = api(session, suite, '/api/log/' + instance + '/images')
    snapshot = evidence_snapshot(info, images)
    if not snapshot['module'] or not snapshot['plan_id']:
        raise ValueError('Instance must identify its module and plan')
    # Some screenshot modules retain WAITING after their image is filled and
    # expose REVIEW as their outcome. A local visual decision is valid here;
    # it does not claim execution finished or alter the upstream state.
    waiting_review = (snapshot['status'] == 'WAITING' and snapshot['result'] == 'REVIEW'
        and snapshot['images'] and not snapshot['pending'])
    if snapshot['status'] not in ('FINISHED', 'INTERRUPTED', 'SKIPPED') and not waiting_review:
        raise ValueError(f"Instance is {snapshot['status']} / {snapshot['result']}; review requires a stopped instance or WAITING / REVIEW with all screenshots uploaded")
    if decision == 'approved' and (snapshot['pending'] or not snapshot['images'] or snapshot['result'] in ('FAILED', 'SKIPPED') or snapshot['status'] == 'SKIPPED'):
        raise ValueError('Approval requires uploaded evidence, no empty placeholders, and no FAILED/SKIPPED verdict')
    record = {'schema': 1, 'suite': suite_identity(suite), 'instance': instance,
        'decision': decision, 'reviewer': reviewer.strip(), 'note': note.strip(),
        'reviewed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'snapshot': snapshot}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, 'a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(json.dumps(record, ensure_ascii=True) + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    return record


def review_state(records, suite, instance, info, images):
    latest = next((r for r in reversed(records) if r['suite'] == suite_identity(suite) and r['instance'] == instance), None)
    if not latest:
        return None
    return latest['decision'] if latest['snapshot'] == evidence_snapshot(info, images) else 'stale'


def collect_reviews(session, suite, results, path=DEFAULT_REGISTRY):
    records = load_records(path)
    rows = []
    for alias, _, modules in results:
        for module, result, link in modules:
            instance = link.rsplit('log=', 1)[-1] if 'log=' in link else None
            latest = next((r for r in reversed(records) if r['suite'] == suite_identity(suite) and r['instance'] == instance), None)
            if not latest:
                continue
            try:
                info = api(session, suite, '/api/info/' + instance_path(instance))
                images = api(session, suite, '/api/log/' + instance + '/images')
                state = review_state(records, suite, instance, info, images)
            except Exception:
                state = 'unverified'
            rows.append({'alias': alias, 'module': module, 'instance': instance, 'suite_result': result,
                'state': state, 'reviewer': latest['reviewer'], 'note': latest['note'], 'link': link})
    return rows


def render_reviews(rows):
    def cell(value):
        return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', ' ').replace('\r', ' ')
    lines = ['<!-- manual-review:start -->', '## Local manual verification', '',
        'Local operator decisions are separate from official suite verdicts. They do not increase Passed counts or badges.', '',
        ' | '.join(f'{state}: **{sum(row["state"] == state for row in rows)}**' for state in ('approved', 'rejected', 'stale', 'unverified')), '',
        '| Instance | Plan / module | Suite result | Manual decision | Reviewer | Note |',
        '|---|---|---|---|---|---|']
    for row in rows:
        instance = instance_path(row['instance'])
        link = suite_identity(row['link'].split('/log-detail.html?log=', 1)[0]) + '/log-detail.html?log=' + instance
        lines.append('| [' + instance + '](' + link + ') | ' + ' | '.join(cell(value) for value in (row['alias'] + ' / ' + row['module'], row['suite_result'], row['state'], row['reviewer'], row['note'])) + ' |')
    if not rows:
        lines += ['', 'No verified local decisions for the selected current instances.']
    lines += ['', 'Changed evidence/verdicts invalidate earlier approval (`stale`); unavailable evidence is `unverified`.', '<!-- manual-review:end -->']
    return '\n'.join(lines) + '\n'


def upload_image(session, suite, instance, placeholder, data):
    instance_path(instance)
    instance_path(placeholder)
    info = api(session, suite, '/api/info/' + instance)
    if info.get('result') in ('FAILED', 'SKIPPED') or info.get('status') == 'SKIPPED':
        raise ValueError('Refusing an upload that could overwrite a FAILED/SKIPPED suite verdict')
    images = api(session, suite, '/api/log/' + instance + '/images')
    if sum(entry.get('upload') == placeholder for entry in images) != 1:
        raise ValueError('Expected an existing, unfilled image placeholder for this instance')
    encoded = 'data:image/png;base64,' + base64.b64encode(data).decode('ascii')
    image_bytes(encoded)
    result = api(session, suite, f'/api/log/{instance}/images/{placeholder}', method='post',
        data=encoded, headers={'Content-Type': 'text/plain'})
    if not result or not result.get('img') or hashlib.sha256(image_bytes(result['img'])).digest() != hashlib.sha256(data).digest():
        raise ValueError('Suite did not confirm the uploaded image')
    return result


async def capture_pending(session, suite, instance, page, directory):
    """Attach an actual browser capture to one unambiguous pending placeholder.

    Never interprets the screen as success. Multiple simultaneous requests need
    explicit selection with review-test.sh --upload instead of guessing.
    """
    instance_path(instance)
    if not page.url.startswith(('https://', 'http://')):
        return False
    info = api(session, suite, '/api/info/' + instance)
    if info.get('result') in ('FAILED', 'SKIPPED') or info.get('status') == 'SKIPPED':
        return False
    images = api(session, suite, '/api/log/' + instance + '/images')
    pending = [entry for entry in images if entry.get('upload')]
    if len(pending) != 1:
        return False
    placeholder = pending[0]['upload']
    instance_path(placeholder)
    suite_hash = hashlib.sha256(suite_identity(suite).encode()).hexdigest()[:16]
    folder = Path(directory) / suite_hash / instance
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    filename = folder / (placeholder + '.png')
    data = await page.screenshot(full_page=True)
    fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    metadata = {'suite': suite_identity(suite), 'instance': instance, 'placeholder': placeholder,
        'screenshot': filename.name, 'sha256': hashlib.sha256(data).hexdigest(),
        'captured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'decision': None, 'before_upload': {'status': info.get('status'), 'result': info.get('result')}}
    fd = os.open(filename.with_suffix('.json'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(metadata, stream, indent=2)
    upload_image(session, suite, instance, placeholder, data)
    return True

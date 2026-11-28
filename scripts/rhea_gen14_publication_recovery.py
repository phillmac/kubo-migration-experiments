"""Lose a conditional PUT acknowledgement on the disposable IAM fixtures, then observe."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
import os

import rhea_gen14_rclone_rehearsal as r

p = r.p
CREATE = r.REMOTE.prefix + 'acceptance-lost-ack-create-20261127.sst'
MARKER = r.REMOTE.prefix + p.admin.MARKER
BODY = b''
LOST_ACK_EXIT = 75


def quarantine(journal):
    result = journal.read('result.json')
    p.require(result['result'] == 'PASS' and result['actual_rehearsal_proven'] is True,
              'completed native writer quarantine required')
    saved = journal.read('16-final-writer-proof.receipt.json')['result']
    host = r.NativeHost(r.HostPaths(r.STATE), r.REMOTE, expected_dirty={r.DIRTY: r.DIRTY_PAYLOAD})
    host.quarantined, host.manifest_sha = True, saved['cache_manifest_sha256']
    p.require(host.proof() == saved, 'writer quarantine differs from durable proof')
    return p.admin.iam.digest(saved)


def make_intent(case, baseline, plan_sha, proof):
    p.require(case in ('create', 'replace'), 'unknown conditional publication')
    key = CREATE if case == 'create' else MARKER
    prior = [row for row in baseline if row['key'] == key]
    if case == 'create':
        p.require(not prior, 'create-only fixture has preexisting history')
        condition = {'IfNoneMatch': '*'}
    else:
        latest = [row for row in prior if row['latest']]
        p.require(len(latest) == 1 and latest[0]['sha256'] != p.sha(BODY),
                  'replacement requires one distinguishable prior marker')
        condition = {'IfMatch': latest[0]['etag']}
    return dict(schema=1, scope='DISPOSABLE_BUCKET_ONLY', case=case, bucket=r.REMOTE.bucket,
                key=key, condition=condition, body_sha256=p.sha(BODY), body_bytes=len(BODY),
                credential_plan_sha256=plan_sha, quarantine_sha256=proof,
                baseline=baseline, baseline_sha256=p.admin.iam.digest(baseline))


def send_once(journal, cloud, case, plan_sha, proof, client_factory, *, crash=os._exit):
    path = 'lost-ack-' + case + '.intent.json'
    p.require(not journal.exists(path), 'durable intent exists; inspect without replay')
    cloud.no_uploads()
    baseline = cloud.history(extra_key=CREATE)
    intent = make_intent(case, baseline, plan_sha, proof)
    journal.write(path, intent)
    client = client_factory()
    try:
        response = r.live.ConditionalS3(client).put_object(**cloud.params(
            intent['key'], Body=BODY, **intent['condition']))
        r.response_ok(response)
        # End the entire process after server acceptance, before reading or
        # persisting the version. Recovery runs in a separate invocation.
        crash(LOST_ACK_EXIT)
        raise p.Refusal('simulated process exit unexpectedly returned')
    finally:
        client.close()


def observe(journal, cloud, case, plan_sha, proof):
    intent = journal.read('lost-ack-' + case + '.intent.json')
    baseline = intent['baseline']
    p.require(intent == make_intent(case, baseline, plan_sha, proof), 'durable intent binding differs')
    cloud.no_uploads()
    after = cloud.history(extra_key=CREATE)
    decision, version = r.publication_delta(baseline, after, intent['key'], BODY)
    if version is not None:
        current_body, current_version, current_etag = cloud.read(intent['key'])
        row = next(row for row in after if row['key'] == intent['key'] and row['version'] == version)
        p.require((current_body, current_version, current_etag) == (BODY, version, row['etag']),
                  'current object differs from version history')
    p.require(cloud.history(extra_key=CREATE) == after, 'protected history changed during observation')
    return dict(decision=decision, case=case, condition=next(iter(intent['condition'])),
                role='writer' if case == 'create' else 'publisher', scope=intent['scope'],
                before_versions=len(baseline), after_versions=len(after),
                before_sha256=intent['baseline_sha256'], after_sha256=p.admin.iam.digest(after),
                observed_version=version, intent_sha256=p.admin.iam.digest(intent),
                provider_writes_during_inspection=0, retry_allowed=False,
                checkpoint_certified=False, observed_at_utc=datetime.now(timezone.utc).isoformat())


def run(mode):
    p.require(os.getuid() == 0 and os.geteuid() == 0, 'root execution required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', HOME='/nonexistent', LC_ALL='C', AWS_EC2_METADATA_DISABLED='true')
    action, case = mode.split('-')
    p.require(action in ('lose', 'inspect') and case in ('create', 'replace'), 'unknown mode')
    with r.Journal() as journal:
        proof = quarantine(journal)
        if action == 'lose':
            writer, cloud, plan_sha = r.load_context()
            try:
                factory = cloud.publisher_factory if case == 'replace' else (
                    lambda: r.s3_client(writer['AccessKeyId'], writer['SecretAccessKey']))
                send_once(journal, cloud, case, plan_sha, proof, factory)
            finally:
                cloud.admin.close()
        with p.Journal() as old:
            binding, _ = r.managed.legacy_binding(old)
        plan_sha = p.admin.iam.digest(binding)
        cloud = r.Cloud(binding['identity']['account'], r.s3_client(*p.source_credentials()), None)
        try:
            result = observe(journal, cloud, case, plan_sha, proof)
            path = 'lost-ack-' + case + '.observed.json'
            if result['decision'] == 'EXPECTED_VERSION_OBSERVED' and not journal.exists(path):
                journal.write(path, result)
            return result
        finally:
            cloud.admin.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('lose-create', 'inspect-create', 'lose-replace', 'inspect-replace'))
    try:
        report = run(parser.parse_args().mode)
    except Exception as exc:
        report = dict(decision='REFUSED', retry_allowed=False, **r.live.error_details(exc))
        if type(exc) is p.Refusal:
            report['reason'] = str(exc)
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(0 if report['decision'] == 'EXPECTED_VERSION_OBSERVED' else 2)

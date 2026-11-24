#!/usr/bin/env python3
"""Root-only, fixed full-clone credentials for the bounded generation-14 trial.

Writer credentials are independent of the later exact publisher binding. Neither
role can change IAM, and the writer can never mutate protected marker families.
All mutations have durable intents; interrupted operations are never replayed.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import logging
import os
from pathlib import Path
import re
from urllib.parse import unquote

import rhea_gen14_create_iam_credentials as p
import rhea_gen14_recover_iam_policy as managed
import rhea_multi_sst_marker_iam as policies

STATE = Path('/root/.local/share/rhea-gen14-clone-credentials-20261125')
TRIAL = Path('/root/.local/share/rhea-gen14-two-sst-20261125')
LEGACY = Path('/root/.local/share/rhea-wasabi-lab-admin-20261101/full-clone-steps')
LEGACY_STATE_SHA = 'c1563e322c496ca479c26501ef3f8ae2b71091565ee8fa227e24b4292f2cd90c'
CHECKPOINT_SHA = '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774'
BUCKET = 'rhea-pebble-lab-20261101-39037c6f01'
PREFIX = 'rhea/pebbleds/'
USERS = {role: 'rhea-gen14-clone-20261125-' + role for role in ('writer', 'publisher')}
POLICY_NAMES = {role: user + '-policy' for role, user in USERS.items()}
DOMAIN = 'rhea-gen14-clone-credentials-v1'


def read_path(path):
    fd = p.directory(path.parent)
    try:
        return p.read_private(fd, path.name)
    finally:
        os.close(fd)


def anchored_checkpoint():
    raw = read_path(LEGACY / 'state.json')
    cert = read_path(LEGACY / 'checkpoints/000013-step.json')
    p.require(p.sha(raw) == LEGACY_STATE_SHA and p.sha(cert) == CHECKPOINT_SHA,
              'protected generation-13 anchor changed')
    state = json.loads(raw)
    p.require(state['generation'] == 13 and state['rewrites'] == 9 and state['pending'] is None
              and state['binding']['limits']['maximum_rewrites'] == 9,
              'legacy generation or rewrite budget changed')
    return json.loads(cert)


def publisher_keys():
    raw = read_path(TRIAL / 'publisher-plan.json')
    plan = policies.parse(raw)
    p.require(type(plan.get('schema')) is int and plan['schema'] == 1 and plan.get('bucket') == BUCKET
              and plan.get('prefix') == PREFIX and type(plan.get('generation')) is int and plan['generation'] == 14
              and plan.get('previous_checkpoint_sha256') == CHECKPOINT_SHA,
              'publisher plan scope differs')
    for name in ('closed_writer_sha256', 'before_proof_sha256', 'quarantine_sha256'):
        policies.hash_value(plan.get(name))
    rows = plan.get('markers')
    p.require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict,
              'this trial publishes exactly one manifest marker')
    row = rows[0]
    name = row.get('name')
    p.require(type(name) is str and re.fullmatch(r'marker\.manifest\.[0-9]{6,}\.MANIFEST-[0-9]{6,}', name)
              and int(name.split('.')[2]) > 16 and type(row.get('size')) is int and row['size'] == 0
              and row.get('sha256') == p.sha(b''), 'publisher marker is not a new empty manifest marker')
    return (name,), p.sha(raw)


def binding(account, role, checkpoint, publication=None):
    p.require(role in USERS and policies.BUCKET == BUCKET and policies.PREFIX == PREFIX,
              'fixed clone identity differs')
    names, plan_sha = ((checkpoint['manifest_marker'],), None) if role == 'writer' else publication
    # The pure builder's writer document is independent of publication names.
    bundle = policies.build_policies(policies.Bindings(account, USERS['writer'], USERS['publisher']), tuple(names))
    document = bundle.document(role)
    return dict(schema=1, domain=DOMAIN, role=role, account=account, user=USERS[role],
                bucket=BUCKET, prefix=PREFIX, endpoint=p.S3_ENDPOINT, region='ca-central-1',
                previous_checkpoint_sha256=CHECKPOINT_SHA, policy_name=POLICY_NAMES[role],
                policy_arn=f'arn:aws:iam::{account}:policy/{POLICY_NAMES[role]}',
                policy_document=document, policy_sha256=policies.digest(document),
                publication_keys=list(names) if role == 'publisher' else [],
                publication_plan_sha256=plan_sha)


class Journal(p.Journal):
    def __init__(self, role):
        p.require(role in USERS, 'unknown clone role')
        self.path = STATE / role

    def __enter__(self):
        self.fd, self.lock = p.directory(self.path, create=True, private=True), None
        try:
            try:
                self.lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
                os.fsync(self.lock)
                os.fsync(self.fd)
            except FileExistsError:
                self.lock = os.open('lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            p.checked_file(self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise


def policy_readback(iam, bound):
    value = iam.get_policy(PolicyArn=bound['policy_arn'])
    p.response_ok(value)
    row = value['Policy']
    p.require(row.get('Arn') == bound['policy_arn'] and row.get('PolicyName') == bound['policy_name']
              and row.get('Path') == '/' and type(row.get('PolicyId')) is str and row['PolicyId'],
              'clone managed policy identity differs')
    version = row.get('DefaultVersionId')
    p.require(type(version) is str and re.fullmatch(r'v[1-9][0-9]*', version), 'invalid policy version')
    value = iam.get_policy_version(PolicyArn=bound['policy_arn'], VersionId=version)
    p.response_ok(value)
    policy = value['PolicyVersion']
    p.require(policy.get('VersionId') == version and policy.get('IsDefaultVersion') is True,
              'default policy version differs')
    document = policy.get('Document')
    if type(document) is str:
        document = json.loads(unquote(document))
    p.require(policies.digest(managed.normalize_policy(document)) == bound['policy_sha256'],
              'clone policy readback differs')
    return dict(policy_id_sha256=p.sha(row['PolicyId'].encode()), version_id=version,
                policy_sha256=bound['policy_sha256'])


def require_absent(call, **params):
    try:
        call(**params)
    except Exception as exc:
        detail = managed.error_details(exc)
        if detail['error_code'] == 'NoSuchEntity' and detail['http_status'] == 404:
            return
        raise
    raise p.Refusal('new clone IAM identity already exists; adoption forbidden')


def verify_permissions(iam, journal, bound):
    """Check the exact recorded authority before creating or returning a key."""
    user = p.user_result(iam.get_user(UserName=bound['user']), bound['user'], bound['account'])
    p.require(user == journal.read('00.receipt.json')['result'], 'clone user identity changed')
    p.require(policy_readback(iam, bound) == journal.read('01.receipt.json')['result'], 'clone policy changed')
    p.require(journal.read('02.receipt.json')['result'] == dict(policy_arn=bound['policy_arn']),
              'clone attachment receipt differs')
    p.require(not managed.listing(iam, 'list_user_policies', 'PolicyNames', bound['user'])
              and not managed.listing(iam, 'list_groups_for_user', 'Groups', bound['user']),
              'unexpected clone inline policy or group')
    attached = managed.listing(iam, 'list_attached_user_policies', 'AttachedPolicies', bound['user'])
    p.require(attached == [dict(PolicyArn=bound['policy_arn'], PolicyName=bound['policy_name'])],
              'clone policy attachment differs')


def verify_role(iam, journal, bound):
    p.require(journal.read('binding.json') == bound, 'clone credential binding changed')
    previous = policies.digest(bound)
    for index, action in enumerate(('CreateUser', 'CreatePolicy', 'AttachUserPolicy', 'CreateAccessKey')):
        intent = journal.read(f'{index:02d}.intent.json')
        receipt = journal.read(f'{index:02d}.receipt.json')
        p.require(intent == dict(schema=1, action=action, binding_sha256=policies.digest(bound),
                  sequence=index, previous_sha256=previous), 'clone intent chain differs')
        p.require(type(receipt) is dict and set(receipt) == {'schema', 'intent_sha256', 'result'}
                  and receipt.get('schema') == 1 and receipt.get('intent_sha256') == policies.digest(intent)
                  and type(receipt.get('result')) is dict, 'clone receipt binding differs')
        previous = policies.digest(receipt)
    verify_permissions(iam, journal, bound)
    raw = journal.raw('credential.json')
    saved = policies.parse(raw)
    keys = p.key_metadata(iam, bound['user'])
    p.require(saved.get('binding_sha256') == policies.digest(bound) and saved.get('account') == bound['account']
              and saved.get('user') == bound['user'] and saved.get('role') == bound['role']
              and saved.get('endpoint') == p.S3_ENDPOINT and saved.get('region') == 'ca-central-1'
              and len(keys) == 1 and keys[0]['AccessKeyId'] == saved.get('AccessKeyId')
              and type(saved.get('SecretAccessKey')) is str and bool(saved['SecretAccessKey']),
              'clone credential metadata differs')
    p.require(journal.read('03.receipt.json')['result'] == dict(
              credential_sha256=p.sha(raw), key_id_sha256=p.sha(saved['AccessKeyId'].encode())),
              'clone saved key receipt differs')
    return dict(result='VERIFIED', role=bound['role'], user=bound['user'], policy_sha256=bound['policy_sha256'],
                binding_sha256=policies.digest(bound), credential_file=str(journal.path / 'credential.json'))


def provision(iam, journal, bound):
    if journal.exists('result.json'):
        return verify_role(iam, journal, bound)
    p.require(not journal.exists('binding.json') and set(os.listdir(journal.fd)) <= {'lock'},
              'clone IAM work requires inspection; pending mutations are never replayed')
    require_absent(iam.get_user, UserName=bound['user'])
    require_absent(iam.get_policy, PolicyArn=bound['policy_arn'])
    summary = iam.get_account_summary()
    p.response_ok(summary)
    quota = summary.get('SummaryMap', {})
    p.require(type(quota.get('PolicySizeQuota')) is int and len(policies.canonical(bound['policy_document']).decode().strip())
              <= quota['PolicySizeQuota'], 'managed policy size exceeds current quota')
    journal.write('binding.json', bound)
    previous = policies.digest(bound)
    for index, action in enumerate(('CreateUser', 'CreatePolicy', 'AttachUserPolicy', 'CreateAccessKey')):
        intent = dict(schema=1, action=action, binding_sha256=policies.digest(bound), sequence=index, previous_sha256=previous)
        journal.write(f'{index:02d}.intent.json', intent)
        if action == 'CreateUser':
            result = p.user_result(iam.create_user(UserName=bound['user']), bound['user'], bound['account'])
            p.require(p.user_result(iam.get_user(UserName=bound['user']), bound['user'], bound['account']) == result,
                      'new clone user readback differs')
        elif action == 'CreatePolicy':
            value = iam.create_policy(PolicyName=bound['policy_name'], Path='/',
                                      PolicyDocument=policies.canonical(bound['policy_document']).decode())
            p.response_ok(value)
            p.require(value.get('Policy', {}).get('Arn') == bound['policy_arn'], 'created policy ARN differs')
            result = policy_readback(iam, bound)
        elif action == 'AttachUserPolicy':
            p.response_ok(iam.attach_user_policy(UserName=bound['user'], PolicyArn=bound['policy_arn']))
            p.require(managed.listing(iam, 'list_attached_user_policies', 'AttachedPolicies', bound['user']) ==
                      [dict(PolicyArn=bound['policy_arn'], PolicyName=bound['policy_name'])], 'new attachment readback differs')
            result = dict(policy_arn=bound['policy_arn'])
        else:
            verify_permissions(iam, journal, bound)
            p.require(not p.key_metadata(iam, bound['user']), 'unrecorded clone access key')
            value = iam.create_access_key(UserName=bound['user'])
            p.response_ok(value)
            row = value.get('AccessKey', {})
            p.require(row.get('UserName') == bound['user'] and row.get('Status') == 'Active'
                      and type(row.get('AccessKeyId')) is str and re.fullmatch(r'[A-Za-z0-9]{16,128}', row['AccessKeyId'])
                      and type(row.get('SecretAccessKey')) is str and re.fullmatch(r'[!-~]{16,256}', row['SecretAccessKey']),
                      'created clone access key response differs')
            saved = dict(account=bound['account'], user=bound['user'], role=bound['role'], endpoint=p.S3_ENDPOINT,
                         region='ca-central-1', binding_sha256=policies.digest(bound),
                         AccessKeyId=row['AccessKeyId'], SecretAccessKey=row['SecretAccessKey'])
            credential_sha = journal.write('credential.json', saved)
            result = dict(credential_sha256=credential_sha, key_id_sha256=p.sha(row['AccessKeyId'].encode()))
        receipt = dict(schema=1, intent_sha256=policies.digest(intent), result=result)
        journal.write(f'{index:02d}.receipt.json', receipt)
        previous = policies.digest(receipt)
    result = verify_role(iam, journal, bound)
    journal.write('result.json', result)
    return result


def run(mode):
    p.require(os.getuid() == 0 and os.geteuid() == 0, 'root execution required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LC_ALL='C', HOME='/nonexistent', AWS_EC2_METADATA_DISABLED='true')
    if mode == 'status':
        result = {}
        for role in USERS:
            directory = STATE / role
            if directory.exists():
                with Journal(role) as journal:
                    result[role] = journal.read('result.json') if journal.exists('result.json') else dict(result='PENDING')
            else:
                result[role] = dict(result='NOT_STARTED')
        return dict(result='STATUS', credentials='NOT_ACCESSED', roles=result)
    checkpoint = anchored_checkpoint()
    iam = sts = None
    try:
        iam, sts = p.clients(*p.source_credentials())
        identity = p.identity(sts)
        with p.Journal() as old:
            source_binding, receipts, pending = old.load()
            p.require(source_binding is not None and identity == source_binding['identity'], 'source account changed')
        role = mode
        publication = publisher_keys() if role == 'publisher' else None
        bound = binding(identity['account'], role, checkpoint, publication)
        if role == 'publisher':
            p.require((STATE / 'writer').is_dir(), 'verified clone writer must exist before publisher')
            with Journal('writer') as writer:
                p.require(writer.exists('result.json'), 'verified clone writer must exist before publisher')
                verify_role(iam, writer, binding(identity['account'], 'writer', checkpoint))
        with Journal(role) as journal:
            return provision(iam, journal, bound)
    finally:
        for client in (iam, sts):
            if client is not None:
                client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('status', 'writer', 'publisher'))
    args = parser.parse_args(argv)
    try:
        result = run(args.mode)
    except Exception as exc:
        result = dict(result='REFUSED', **managed.error_details(exc))
        if isinstance(exc, policies.Refusal):
            result['reason'] = str(exc)
    print(json.dumps(result, sort_keys=True))
    return 2 if result['result'] == 'REFUSED' else 0


if __name__ == '__main__':
    raise SystemExit(main())

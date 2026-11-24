#!/usr/bin/env python3
"""Create the fixed managed policies and credentials; preserve the legacy journal.

Only policy/attachment outcomes with an existing bound intent can be reconciled.
An unconfirmed access-key request is never repeated. No production policy is edited.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import json
import logging
import os
from pathlib import Path
import re
from urllib.parse import unquote

import rhea_gen14_create_iam_credentials as p

STATE = Path('/root/.local/share/rhea-gen14-iam-managed-credentials-20261125')
ROLES = ('writer', 'publisher')
POLICY_NAMES = {r: p.admin.plan()['users'][r] + '-policy' for r in ROLES}
DOMAIN = 'rhea-gen14-managed-credentials-v1'
ERROR_CODES = frozenset(('AccessDenied', 'AccessDeniedException', 'NoSuchEntity',
    'EntityAlreadyExists', 'LimitExceeded', 'MalformedPolicyDocument', 'InvalidInput',
    'ServiceFailure', 'ServiceUnavailable', 'Throttling', 'ThrottlingException',
    'InvalidClientTokenId', 'SignatureDoesNotMatch', 'RequestExpired', 'RequestTimeout',
    'ExpiredToken', 'InvalidSignatureException', 'UnrecognizedClientException'))
ERROR_CLASSES = ERROR_CODES | {c + 'Exception' for c in ERROR_CODES} | frozenset((
    'ClientError', 'SDKError', 'Refusal', 'OSError', 'FileNotFoundError', 'PermissionError',
    'FileExistsError', 'BlockingIOError', 'TimeoutError', 'ConnectionError', 'TypeError',
    'ValueError', 'KeyError', 'AttributeError', 'ImportError', 'ModuleNotFoundError',
    'JSONDecodeError', 'UnicodeDecodeError', 'MissingSectionHeaderError', 'ParsingError',
    'DuplicateOptionError', 'DuplicateSectionError', 'EndpointConnectionError',
    'ConnectTimeoutError', 'ReadTimeoutError', 'ConnectionClosedError', 'SSLError',
    'HTTPClientError', 'ParamValidationError', 'NoCredentialsError', 'PartialCredentialsError'))


def error_details(exc):
    response = getattr(exc, 'response', {})
    response = response if type(response) is dict else {}
    error, meta = response.get('Error', {}), response.get('ResponseMetadata', {})
    code = error.get('Code') if type(error) is dict else None
    status = meta.get('HTTPStatusCode') if type(meta) is dict else None
    return dict(error_class=type(exc).__name__ if type(exc).__name__ in ERROR_CLASSES else 'Exception',
                error_code=code if type(code) is str and code in ERROR_CODES else None,
                http_status=status if type(status) is int and 100 <= status <= 599 else None)


class Trace:
    stage = 'validate_local_state'


class IAM:
    """Expose only fixed IAM methods; stage labels never contain provider text."""
    LABELS = dict(get_user='read_user', get_policy='read_managed_policy',
        get_policy_version='read_policy_version', create_policy='create_managed_policy',
        attach_user_policy='attach_managed_policy', list_attached_user_policies='list_attached_policies',
        list_user_policies='list_inline_policies', list_groups_for_user='list_groups',
        list_access_keys='list_access_keys', create_access_key='create_access_key',
        get_account_summary='read_account_summary')

    def __init__(self, client, trace):
        self.client, self.trace = client, trace

    def __getattr__(self, name):
        p.require(name in self.LABELS, 'unsupported IAM operation')
        def call(**kwargs):
            role = next((r for r in ROLES if kwargs.get('UserName') == p.admin.plan()['users'][r]
                         or kwargs.get('PolicyName') == POLICY_NAMES[r]
                         or str(kwargs.get('PolicyArn', '')).endswith('/' + POLICY_NAMES[r])), '')
            label = self.LABELS[name]
            self.trace.stage = label.replace('_', '_' + role + '_', 1) if role else label
            return getattr(self.client, name)(**kwargs)
        return call


def steps(binding):
    return tuple(dict(action=action, role=role, user=p.admin.plan()['users'][role],
                      policy_arn=f"arn:aws:iam::{binding['identity']['account']}:policy/{POLICY_NAMES[role]}",
                      policy_sha256=p.POLICY_SHAS[role])
                 for action in ('CreatePolicy', 'AttachUserPolicy', 'CreateAccessKey') for role in ROLES)


def legacy_binding(legacy):
    bound, receipts, pending = legacy.load()
    p.require(bound is not None and len(receipts) == 2 and pending,
              'legacy journal must retain exactly two completed users and pending writer inline policy')
    files = {name: p.sha(legacy.raw(name)) for name in sorted(os.listdir(legacy.fd)) if name != 'lock'}
    p.require(set(files) == {'binding.json', '00.intent.json', '00.receipt.json',
                            '01.intent.json', '01.receipt.json', '02.intent.json'},
              'unexpected legacy journal state')
    return dict(schema=1, domain=DOMAIN, original_plan_sha256=p.PLAN_SHA,
                identity=bound['identity'], legacy_files=files, policy_sha256=p.POLICY_SHAS,
                policy_names=POLICY_NAMES, endpoint=p.S3_ENDPOINT, region='ca-central-1',
                initial_policies_absent=True, initial_users_without_policies_groups_or_keys=True), receipts


class Journal(p.Journal):
    def __enter__(self):
        self.fd, self.lock = p.directory(STATE, create=True, private=True), None
        try:
            try:
                self.lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=self.fd)
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

    def load_managed(self, binding):
        names = set(os.listdir(self.fd))
        allowed = {'lock', 'binding.json', 'writer.json', 'publisher.json'} | {
            f'{i:02d}.{kind}.json' for i in range(6) for kind in ('intent', 'receipt')}
        p.require(names <= allowed, 'unexpected managed journal artifact')
        if 'binding.json' not in names:
            p.require(names <= {'lock'}, 'unbound managed journal artifacts')
            return [], None
        p.require(self.read('binding.json') == binding, 'managed journal or legacy binding differs')
        previous, receipts, pending, gap = p.admin.iam.digest(binding), [], None, False
        for i, step in enumerate(steps(binding)):
            intent_name, receipt_name = f'{i:02d}.intent.json', f'{i:02d}.receipt.json'
            if intent_name not in names:
                p.require(receipt_name not in names, 'managed receipt without intent')
                gap = True
                continue
            p.require(not gap and pending is None, 'out of order managed journal')
            expected = dict(schema=1, binding_sha256=p.admin.iam.digest(binding), sequence=i,
                            previous_receipt_sha256=previous, **step)
            p.require(self.read(intent_name) == expected, 'managed intent binding mismatch')
            if receipt_name not in names:
                pending = i
                continue
            receipt = self.read(receipt_name)
            p.require(set(receipt) == {'schema', 'intent_sha256', 'result', 'evidence'}
                      and receipt['schema'] == 1 and type(receipt['result']) is dict
                      and receipt['intent_sha256'] == p.admin.iam.digest(expected)
                      and receipt['evidence'] in ('response_and_readback', 'observed_after_interruption', 'key_saved'),
                      'invalid managed receipt')
            receipts.append(receipt)
            previous = p.admin.iam.digest(receipt)
        for role, i in (('writer', 4), ('publisher', 5)):
            if role + '.json' in names:
                fd = os.open(role + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
                try:
                    p.checked_file(fd)
                finally:
                    os.close(fd)
                p.require(f'{i:02d}.intent.json' in names, 'orphan managed credential file')
            p.require(len(receipts) <= i or role + '.json' in names, 'managed credential file missing')
        return receipts, pending


def listing(iam, method, field, user):
    value = getattr(iam, method)(UserName=user)
    p.response_ok(value)
    p.require(value.get('IsTruncated', False) is False and type(value.get(field)) is list,
              'incomplete IAM inventory')
    return value[field]


def policy(iam, step):
    try:
        value = iam.get_policy(PolicyArn=step['policy_arn'])
    except Exception as exc:
        detail = error_details(exc)
        if detail['error_code'] == 'NoSuchEntity' and detail['http_status'] == 404:
            return None
        raise
    p.response_ok(value)
    row = value.get('Policy', {})
    version = row.get('DefaultVersionId')
    p.require(row.get('Arn') == step['policy_arn'] and row.get('PolicyName') == POLICY_NAMES[step['role']]
              and row.get('Path') == '/' and type(row.get('PolicyId')) is str and bool(row['PolicyId'])
              and type(version) is str and re.fullmatch(r'v[1-9][0-9]*', version),
              'unexpected managed policy identity')
    value = iam.get_policy_version(PolicyArn=step['policy_arn'], VersionId=version)
    p.response_ok(value)
    row_version = value.get('PolicyVersion', {})
    p.require(row_version.get('VersionId') == version and row_version.get('IsDefaultVersion') is True,
              'unexpected managed policy version')
    document = row_version.get('Document')
    if type(document) is str:
        document = json.loads(unquote(document))
    p.require(p.sha(p.canonical(document)) == step['policy_sha256'], 'managed policy document differs')
    return dict(policy_id_sha256=p.sha(row['PolicyId'].encode()), version_id=version,
                policy_sha256=step['policy_sha256'])


def reconcile(journal, iam, binding, legacy_receipts, receipts, pending):
    """Read every user boundary and all recorded policy/key identities before writes."""
    actual = {}
    for r, role in enumerate(ROLES):
        step = steps(binding)[r]
        value = p.user_result(iam.get_user(UserName=step['user']), step['user'], binding['identity']['account'])
        p.require(value == legacy_receipts[r]['result'], 'legacy user identity differs')
        p.require(not listing(iam, 'list_user_policies', 'PolicyNames', step['user']), 'unexpected inline user policy')
        p.require(not listing(iam, 'list_groups_for_user', 'Groups', step['user']), 'unexpected user group')
        observed = policy(iam, step)
        if r < len(receipts):
            p.require(observed == receipts[r]['result'], 'managed policy receipt differs')
        elif pending != r:
            p.require(observed is None, 'unrecorded managed policy exists; adoption forbidden')
        actual[r] = observed
        attached = listing(iam, 'list_attached_user_policies', 'AttachedPolicies', step['user'])
        exact = [dict(PolicyArn=step['policy_arn'], PolicyName=POLICY_NAMES[role])]
        expected = exact if r + 2 < len(receipts) else []
        p.require(attached == expected or (pending == r + 2 and attached == exact),
                  'unexpected managed policy attachment')
        actual[r + 2] = dict(policy_arn=step['policy_arn'], policy_sha256=step['policy_sha256']) if attached else None
        keys = p.key_metadata(iam, step['user'])
        if r + 4 < len(receipts):
            raw = journal.raw(role + '.json')
            saved = p.admin.iam.parse(raw)
            p.require(saved.get('account') == binding['identity']['account'] and saved.get('user') == step['user']
                      and saved.get('role') == role and saved.get('endpoint') == p.S3_ENDPOINT
                      and saved.get('region') == 'ca-central-1'
                      and saved.get('plan_sha256') == p.admin.iam.digest(binding)
                      and type(saved.get('SecretAccessKey')) is str and bool(saved['SecretAccessKey'])
                      and len(keys) == 1 and keys[0]['AccessKeyId'] == saved.get('AccessKeyId'),
                      'managed credential or key inventory differs')
            actual[r + 4] = dict(key_id_sha256=p.sha(keys[0]['AccessKeyId'].encode()), credential_file_sha256=p.sha(raw))
        else:
            p.require(not keys, 'unrecorded access key exists; key requests cannot be retried')
    for i, receipt in enumerate(receipts):
        p.require(actual[i] == receipt['result'], 'managed receipt reconciliation failed')
    return actual


def quotas(iam, plan):
    value = iam.get_account_summary()
    p.response_ok(value)
    quotas = value.get('SummaryMap', {})
    p.require(type(quotas) is dict and type(quotas.get('PolicySizeQuota')) is int
              and type(quotas.get('AttachedPoliciesPerUserQuota')) is int, 'managed policy quota unavailable')
    sizes = {r: len(p.canonical(plan['policies'][r]['document']).decode().strip()) for r in ROLES}
    p.require(max(sizes.values()) <= quotas['PolicySizeQuota'] and quotas['AttachedPoliciesPerUserQuota'] >= 1,
              'reviewed policy exceeds managed policy quota')
    return dict(policy_sizes=sizes, managed_policy_size_quota=quotas['PolicySizeQuota'],
                inline_policy_size_quota=quotas.get('UserPolicySizeQuota'))


def receipt(journal, i, result, evidence):
    journal.write(f'{i:02d}.receipt.json', dict(schema=1,
        intent_sha256=p.admin.iam.digest(journal.read(f'{i:02d}.intent.json')), result=result, evidence=evidence))


def execute(journal, iam, binding, legacy_receipts, plan, receipts, trace):
    for i in range(len(receipts), 6):
        step = steps(binding)[i]
        if i >= 4:
            reconcile(journal, iam, binding, legacy_receipts, receipts, None)
        trace.stage = 'persist_' + step['role'] + '_intent'
        journal.write(f'{i:02d}.intent.json', dict(schema=1, binding_sha256=p.admin.iam.digest(binding),
            sequence=i, previous_receipt_sha256=p.admin.iam.digest(receipts[-1] if receipts else binding), **step))
        if i < 2:
            response = iam.create_policy(PolicyName=POLICY_NAMES[step['role']], Path='/',
                PolicyDocument=p.canonical(plan['policies'][step['role']]['document']).decode())
            p.response_ok(response)
            result = policy(iam, step)
            returned = response.get('Policy', {})
            p.require(result is not None and returned.get('Arn') == step['policy_arn']
                      and returned.get('PolicyName') == POLICY_NAMES[step['role']]
                      and type(returned.get('PolicyId')) is str
                      and p.sha(returned['PolicyId'].encode()) == result['policy_id_sha256']
                      and returned.get('DefaultVersionId') == result['version_id'], 'created policy identity differs')
        elif i < 4:
            p.response_ok(iam.attach_user_policy(UserName=step['user'], PolicyArn=step['policy_arn']))
            result = reconcile(journal, iam, binding, legacy_receipts, receipts, i)[i]
            p.require(result is not None, 'managed policy attachment unconfirmed')
        else:
            response = iam.create_access_key(UserName=step['user'])
            p.response_ok(response)
            key = response.get('AccessKey', {})
            p.require(key.get('UserName') == step['user'] and key.get('Status') == 'Active'
                      and type(key.get('AccessKeyId')) is str and re.fullmatch(r'[A-Za-z0-9]{16,128}', key['AccessKeyId'])
                      and type(key.get('SecretAccessKey')) is str and re.fullmatch(r'[!-~]{16,256}', key['SecretAccessKey']),
                      'unexpected managed access key response')
            trace.stage = 'persist_' + step['role'] + '_credential'
            digest = journal.write(step['role'] + '.json', dict(account=binding['identity']['account'],
                user=step['user'], role=step['role'], endpoint=p.S3_ENDPOINT, region='ca-central-1',
                plan_sha256=p.admin.iam.digest(binding), AccessKeyId=key['AccessKeyId'], SecretAccessKey=key['SecretAccessKey']))
            result = dict(key_id_sha256=p.sha(key['AccessKeyId'].encode()), credential_file_sha256=digest)
        trace.stage = 'persist_' + step['role'] + '_receipt'
        receipt(journal, i, result, 'key_saved' if i >= 4 else 'response_and_readback')
        receipts.append(journal.read(f'{i:02d}.receipt.json'))


def run(mode, trace=None):
    trace = trace or Trace()
    p.require(os.getuid() == 0 and os.geteuid() == 0, 'root execution required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LC_ALL='C', HOME='/nonexistent', AWS_EC2_METADATA_DISABLED='true')
    plan = p.reviewed_plan()
    p.require(p.STATE.exists(), 'legacy journal missing')
    with ExitStack() as stack:
        legacy = stack.enter_context(p.Journal())
        binding, legacy_receipts = legacy_binding(legacy)
        journal = stack.enter_context(Journal()) if STATE.exists() or mode == 'recover' else None
        receipts, pending = journal.load_managed(binding) if journal else ([], None)
        if mode == 'status':
            return dict(result='LOCAL_STATUS', completed_actions=len(receipts), pending=pending,
                        credentials='NOT_ACCESSED', remote_verified=False)
        p.require(pending is None or pending < 4, 'pending access-key request: no retry; manual key reconciliation required')
        if mode == 'verify':
            p.require(len(receipts) == 6 and pending is None, 'verification requires all six completed actions')
        trace.stage = 'read_production_source'
        source = p.source_credentials()
        trace.stage = 'initialize_clients'
        raw_iam, sts = p.clients(*source)
        for client in (raw_iam, sts):
            def close(c=client):
                try:
                    c.close()
                except Exception:
                    pass
            stack.callback(close)
        iam = IAM(raw_iam, trace)
        trace.stage = 'identify_account'
        p.require(p.identity(sts) == binding['identity'], 'account identity differs from legacy journal')
        limits = quotas(iam, plan)
        observed = reconcile(journal, iam, binding, legacy_receipts, receipts, pending)
        if mode == 'inspect':
            return dict(result='INSPECTED', completed_actions=len(receipts), pending=pending,
                        pending_outcome_verified=pending is not None and observed.get(pending) is not None,
                        **limits)
        if mode == 'recover':
            trace.stage = 'persist_managed_binding'
            if not journal.exists('binding.json'):
                journal.write('binding.json', binding)
            journal.sync_completed()
            if pending is not None:
                p.require(observed.get(pending) is not None, 'pending managed policy outcome absent; no mutation retry')
                receipt(journal, pending, observed[pending], 'observed_after_interruption')
                receipts, pending = journal.load_managed(binding)
                reconcile(journal, iam, binding, legacy_receipts, receipts, pending)
            execute(journal, iam, binding, legacy_receipts, plan, receipts, trace)
        receipts, pending = journal.load_managed(binding)
        p.require(len(receipts) == 6 and pending is None, 'managed credential creation incomplete')
        reconcile(journal, iam, binding, legacy_receipts, receipts, pending)
        p.require(legacy_binding(legacy)[0] == binding, 'legacy journal changed during operation')
        return dict(result='COMPLETE' if mode == 'recover' else 'VERIFIED', completed_actions=6,
                    credential_files=[str(STATE / (r + '.json')) for r in ROLES],
                    plan_sha256=p.admin.iam.digest(binding), legacy_journal_unchanged=True,
                    actual_s3_enforcement_proven=False)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('status', 'inspect', 'recover', 'verify'))
    args, trace = parser.parse_args(argv), Trace()
    try:
        result = run(args.mode, trace)
    except Exception as exc:
        result = dict(result='REFUSED', stage=trace.stage, **error_details(exc))
        if type(exc) is p.Refusal:
            result['reason'] = str(exc)
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

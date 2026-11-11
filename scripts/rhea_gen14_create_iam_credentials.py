#!/usr/bin/env python3
"""User-operated root Wasabi IAM provisioner. Never invoked live by CI.

Only the fixed reviewed plan is supported. Pending intents are permanent stops;
there is deliberately no retry, adopt, repair, delete, or journal-reset command.
"""
from __future__ import annotations

import argparse
import configparser
import fcntl
import json
import logging
import os
from pathlib import Path
import re
import stat
from urllib.parse import unquote

import rhea_gen14_iam_admin_acceptance as admin

PLAN_SHA = 'eccbf72cab597f0733265f11ce3d7cce12be5b7bc7d1d03acd825e7967225764'
POLICY_SHAS = {
    'writer': 'b828fad32852d15e813a1f6b300093924e4c743f7e9b111c0dc938d0c7d24d23',
    'publisher': '4cdfa9fe6077be6ec3d37fc82e0c0b3bdd104c2ed5ef24cc6a66bede4ceb8415',
}
SOURCE = Path('/root/.config/rclone/rclone.conf')
STATE = Path('/root/.local/share/rhea-gen14-iam-credentials-20261111')
SECTION = 'wasabi-ca-central-1'
S3_ENDPOINT = 'https://s3.ca-central-1.wasabisys.com'
OWNER = 0
Refusal = admin.Refusal
require = admin.iam.require
canonical = admin.iam.canonical
sha = admin.iam.sha


def reviewed_plan():
    p = admin.plan()
    require(admin.iam.digest(p) == PLAN_SHA, 'reviewed plan hash mismatch')
    for role, expected in POLICY_SHAS.items():
        require(sha(canonical(p['policies'][role]['document'])) == expected
                == p['policies'][role]['sha256'], 'reviewed policy hash mismatch')
    return p


def directory(path, *, create=False, private=False):
    """Open each absolute path component without symlinks; retain a directory fd."""
    require(path.is_absolute() and '..' not in path.parts, 'unsafe absolute path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid == OWNER and not stat.S_IMODE(info.st_mode) & 0o022,
                    'unsafe directory owner or mode')
        if private:
            require(stat.S_IMODE(os.fstat(fd).st_mode) == 0o700, 'private directory must be 0700')
        return fd
    except BaseException:
        os.close(fd)
        raise


def checked_file(fd):
    info = os.fstat(fd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == OWNER and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == 0o600, 'file must be private root-owned 0600')
    require(info.st_size <= 1024 * 1024, 'oversized private file')


def read_private(parent, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        checked_file(fd)
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, 'oversized private file')
        return raw
    finally:
        os.close(fd)


def source_credentials():
    """Only this exact production file/section; never search SDK credential sources."""
    fd = directory(SOURCE.parent)
    try:
        raw = read_private(fd, SOURCE.name)
    finally:
        os.close(fd)
    config = configparser.ConfigParser(interpolation=None)
    config.read_string(raw.decode('utf-8'))
    require(config.has_section(SECTION), 'required rclone section missing')
    # Defaults must not silently supply credentials or endpoint.
    require(not config.defaults(), 'rclone DEFAULT entries are unsupported')
    section = config[SECTION]
    require(section.get('type') == 's3'
            and section.get('provider', 'Wasabi') == 'Wasabi'
            and section.get('endpoint') in (S3_ENDPOINT, S3_ENDPOINT.removeprefix('https://'))
            and section.get('env_auth', 'false').lower() == 'false'
            and not section.get('session_token', '').strip(), 'invalid production rclone source')
    key, secret = section.get('access_key_id', ''), section.get('secret_access_key', '')
    require(re.fullmatch(r'[A-Za-z0-9]{16,128}', key) is not None
            and re.fullmatch(r'[!-~]{16,256}', secret) is not None, 'invalid source credential format')
    return key, secret


def clients(key, secret):
    # Suppress all SDK/HTTP logging before importing SDK code. No exception bodies
    # are printed by the entrypoint. No environment credentials/proxies or profiles.
    logging.disable(logging.CRITICAL)
    import boto3
    from botocore.config import Config
    config = Config(retries={'total_max_attempts': 1, 'mode': 'standard'},
                    connect_timeout=5, read_timeout=10, signature_version='v4', proxies={})
    session = boto3.Session(aws_access_key_id=key, aws_secret_access_key=secret,
                            aws_session_token=None, region_name='us-east-1')
    kwargs = dict(aws_access_key_id=key, aws_secret_access_key=secret,
                  aws_session_token=None, region_name='us-east-1', config=config)
    return (session.client('iam', endpoint_url='https://iam.wasabisys.com', **kwargs),
            session.client('sts', endpoint_url='https://sts.wasabisys.com', **kwargs))


def response_ok(value):
    require(type(value) is dict and type(value.get('ResponseMetadata')) is dict
            and value['ResponseMetadata'].get('HTTPStatusCode') == 200
            and value['ResponseMetadata'].get('RetryAttempts', 0) == 0,
            'unexpected provider response')


def identity(sts):
    value = sts.get_caller_identity()
    response_ok(value)
    account, arn, uid = (value.get(k) for k in ('Account', 'Arn', 'UserId'))
    require(type(account) is str and re.fullmatch(r'[0-9]{12}', account)
            and type(arn) is str and re.fullmatch(
                r'arn:aws:iam::' + account + r':(?:root|user/[A-Za-z0-9_+=,.@/\-]+)', arn)
            and type(uid) is str and bool(uid), 'invalid STS account or identity')
    return dict(account=account, arn=arn, user_id_sha256=sha(uid.encode()))


class Journal:
    def __enter__(self):
        self.fd = directory(STATE, create=True, private=True)
        self.lock = None
        try:
            try:
                self.lock = os.open('lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                    0o600, dir_fd=self.fd)
                os.fsync(self.lock)
                os.fsync(self.fd)
            except FileExistsError:
                self.lock = os.open('lock', os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                                    dir_fd=self.fd)
            checked_file(self.lock)
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.lock is not None:
            os.close(self.lock)
        os.close(self.fd)

    def exists(self, name):
        return name in os.listdir(self.fd)

    def raw(self, name):
        return read_private(self.fd, name)

    def read(self, name):
        return admin.iam.parse(self.raw(name))

    def write(self, name, value):
        # Never replace or truncate an artifact, even if a prior write was partial.
        raw = canonical(value)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.fd)
        try:
            checked_file(fd)
            with os.fdopen(fd, 'wb', closefd=False) as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
            os.fsync(self.fd)
        return sha(raw)

    def sync_completed(self):
        for name in os.listdir(self.fd):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
            try:
                checked_file(fd)
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(self.fd)

    def load(self):
        allowed = {'lock', 'binding.json', 'writer.json', 'publisher.json'} | {
            f'{i:02d}.{kind}.json' for i in range(6) for kind in ('intent', 'receipt')}
        require(set(os.listdir(self.fd)) <= allowed, 'unexpected journal artifact')
        if not self.exists('binding.json'):
            require(set(os.listdir(self.fd)) <= {'lock'}, 'unbound journal artifacts')
            return None, [], False
        binding = self.read('binding.json')
        require(set(binding) == {'schema', 'plan_sha256', 'identity'} and binding['schema'] == 1
                and binding['plan_sha256'] == PLAN_SHA, 'invalid journal binding')
        who = binding['identity']
        require(type(who) is dict and set(who) == {'account', 'arn', 'user_id_sha256'}
                and re.fullmatch(r'[0-9]{12}', who['account'])
                and admin.iam.HEX.fullmatch(who['user_id_sha256']), 'invalid identity binding')
        previous = admin.iam.digest(binding)
        receipts, pending, gap = [], False, False
        for i, step in enumerate(admin._steps()):
            intent_name, receipt_name = f'{i:02d}.intent.json', f'{i:02d}.receipt.json'
            if not self.exists(intent_name):
                require(not self.exists(receipt_name), 'receipt without intent')
                gap = True
                continue
            require(not gap and not pending, 'out of order journal')
            intent = dict(schema=1, plan_sha256=PLAN_SHA, identity=who,
                          sequence=i, previous_receipt_sha256=previous, **step)
            require(self.read(intent_name) == intent, 'intent binding mismatch')
            if not self.exists(receipt_name):
                pending = True
                continue
            receipt = self.read(receipt_name)
            require(set(receipt) == {'schema', 'intent_sha256', 'result'}
                    and receipt['schema'] == 1
                    and receipt['intent_sha256'] == admin.iam.digest(intent), 'invalid receipt binding')
            result = receipt['result']
            require(type(result) is dict, 'invalid receipt result')
            if step['action'] == 'CreateUser':
                require(set(result) == {'user_id_sha256'}
                        and admin.iam.HEX.fullmatch(result['user_id_sha256']), 'invalid user receipt')
            elif step['action'] == 'PutUserPolicy':
                require(result == {'policy_sha256': POLICY_SHAS[step['role']]}, 'invalid policy receipt')
            else:
                require(set(result) == {'key_id_sha256', 'credential_file_sha256'}
                        and all(type(v) is str and admin.iam.HEX.fullmatch(v) for v in result.values()),
                        'invalid credential receipt')
            receipts.append(receipt)
            previous = admin.iam.digest(receipt)
        for role in ('writer', 'publisher'):
            if self.exists(role + '.json'):
                # Even safe status checks metadata, but never reads secret content.
                fd = os.open(role + '.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=self.fd)
                try:
                    checked_file(fd)
                finally:
                    os.close(fd)
                key_index = 4 if role == 'writer' else 5
                require(self.exists(f'{key_index:02d}.intent.json'), 'orphan credential file')
        for i in range(4, len(receipts)):
            require(self.exists(('writer' if i == 4 else 'publisher') + '.json'),
                    'completed credential file missing')
        return binding, receipts, pending


def missing_user(iam, user):
    try:
        iam.get_user(UserName=user)
    except Exception as exc:
        value = getattr(exc, 'response', {})
        require(type(value) is dict and value.get('Error', {}).get('Code') == 'NoSuchEntity'
                and value.get('ResponseMetadata', {}).get('HTTPStatusCode') == 404,
                'user absence or read capability unconfirmed')
        return
    raise Refusal('fixed user already exists; adoption forbidden')


def user_result(value, user, account):
    response_ok(value)
    row = value.get('User', {})
    require(row.get('UserName') == user and row.get('Path') == '/'
            and row.get('Arn') == f'arn:aws:iam::{account}:user/{user}'
            and type(row.get('UserId')) is str and bool(row['UserId']), 'unexpected IAM user identity')
    return dict(user_id_sha256=sha(row['UserId'].encode()))


def policy_result(value, step):
    response_ok(value)
    require(value.get('UserName') == step['user'] and value.get('PolicyName') == admin.POLICY_NAME,
            'unexpected policy identity')
    document = value.get('PolicyDocument')
    if type(document) is str:
        document = json.loads(unquote(document))
    require(sha(canonical(document)) == POLICY_SHAS[step['role']], 'remote policy hash mismatch')
    return dict(policy_sha256=POLICY_SHAS[step['role']])


def key_metadata(iam, user):
    value = iam.list_access_keys(UserName=user)
    response_ok(value)
    rows = value.get('AccessKeyMetadata')
    require(value.get('IsTruncated', False) is False and type(rows) is list, 'incomplete key listing')
    for row in rows:
        require(row.get('UserName') == user and row.get('Status') == 'Active'
                and type(row.get('AccessKeyId')) is str and bool(row['AccessKeyId']),
                'unexpected access key metadata')
    return rows


def reconcile(journal, iam, binding, receipts):
    """Compare remote identities, policy bytes and exact key inventory; no adoption."""
    account = binding['identity']['account']
    for i, receipt in enumerate(receipts):
        step, expected = admin._steps()[i], receipt['result']
        if step['action'] == 'CreateUser':
            actual = user_result(iam.get_user(UserName=step['user']), step['user'], account)
        elif step['action'] == 'PutUserPolicy':
            actual = policy_result(iam.get_user_policy(UserName=step['user'],
                                                       PolicyName=admin.POLICY_NAME), step)
        else:
            raw = journal.raw(step['role'] + '.json')
            saved = admin.iam.parse(raw)
            require(saved.get('account') == account and saved.get('user') == step['user']
                    and saved.get('endpoint') == S3_ENDPOINT and saved.get('plan_sha256') == PLAN_SHA
                    and saved.get('role') == step['role'] and saved.get('region') == 'ca-central-1'
                    and type(saved.get('SecretAccessKey')) is str and bool(saved['SecretAccessKey']),
                    'credential metadata mismatch')
            rows = key_metadata(iam, step['user'])
            require(len(rows) == 1 and rows[0]['AccessKeyId'] == saved.get('AccessKeyId'),
                    'remote key inventory mismatch')
            actual = dict(key_id_sha256=sha(rows[0]['AccessKeyId'].encode()),
                          credential_file_sha256=sha(raw))
        require(actual == expected, 'completed receipt reconciliation failed')
    # Check uncreated users remain absent, and created users have no unrecorded keys.
    for i, role in enumerate(('writer', 'publisher')):
        user = admin.plan()['users'][role]
        if len(receipts) <= i:
            missing_user(iam, user)
        elif len(receipts) <= 4 + i:
            require(not key_metadata(iam, user), 'unrecorded access key exists')


def execute(journal, iam, who, p, receipts):
    previous = admin.iam.digest(receipts[-1]) if receipts else admin.iam.digest(journal.read('binding.json'))
    for i in range(len(receipts), 6):
        step = admin._steps()[i]
        intent = dict(schema=1, plan_sha256=PLAN_SHA, identity=who, sequence=i,
                      previous_receipt_sha256=previous, **step)
        intent_sha = journal.write(f'{i:02d}.intent.json', intent)
        # Every exception from here leaves an immutable pending intent. Never retry.
        action, user, role = step['action'], step['user'], step['role']
        if action == 'CreateUser':
            result = user_result(iam.create_user(UserName=user), user, who['account'])
        elif action == 'PutUserPolicy':
            response_ok(iam.put_user_policy(UserName=user, PolicyName=admin.POLICY_NAME,
                                           PolicyDocument=canonical(p['policies'][role]['document']).decode()))
            result = policy_result(iam.get_user_policy(UserName=user, PolicyName=admin.POLICY_NAME), step)
        else:
            value = iam.create_access_key(UserName=user)
            response_ok(value)
            key = value.get('AccessKey', {})
            require(key.get('UserName') == user and key.get('Status') == 'Active'
                    and type(key.get('AccessKeyId')) is str
                    and re.fullmatch(r'[A-Za-z0-9]{16,128}', key['AccessKeyId'])
                    and type(key.get('SecretAccessKey')) is str
                    and re.fullmatch(r'[!-~]{16,256}', key['SecretAccessKey']), 'unexpected access key response')
            # The secret is persisted before a sanitized receipt or any next call.
            file_sha = journal.write(role + '.json', dict(
                account=who['account'], user=user, role=role, endpoint=S3_ENDPOINT,
                region='ca-central-1', plan_sha256=PLAN_SHA,
                AccessKeyId=key['AccessKeyId'], SecretAccessKey=key['SecretAccessKey']))
            result = dict(key_id_sha256=sha(key['AccessKeyId'].encode()), credential_file_sha256=file_sha)
        previous = journal.write(f'{i:02d}.receipt.json',
                                 dict(schema=1, intent_sha256=intent_sha, result=result))


def run(mode):
    require(os.getuid() == 0 and os.geteuid() == 0, 'root execution required before credential access')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    # The direct entrypoint has the same environment isolation as the wrapper.
    # HOME cannot lead the SDK to another credential/config file.
    os.environ.clear()
    os.environ.update(PATH='/usr/bin:/bin', LC_ALL='C', HOME='/nonexistent',
                      AWS_EC2_METADATA_DISABLED='true')
    p = reviewed_plan()
    with Journal() as journal:
        binding, receipts, pending = journal.load()
        if mode == 'status':
            return dict(result='LOCAL_STATUS', completed_actions=len(receipts), pending=pending,
                        credentials='NOT_ACCESSED', remote_verified=False, plan_sha256=PLAN_SHA)
        require(not pending, 'pending intent: manual reconciliation required; no retries')
        if mode == 'verify':
            require(binding is not None, 'no existing account binding to verify')
        iam, sts = clients(*source_credentials())
        try:
            who = identity(sts)
            if binding is not None:
                require(binding['identity'] == who, 'STS identity differs from journal account binding')
            else:
                binding = dict(schema=1, plan_sha256=PLAN_SHA, identity=who)
            # Validate all read capabilities required to reconcile existing work.
            for method in ('get_user', 'get_user_policy', 'list_access_keys', 'create_user',
                           'put_user_policy', 'create_access_key'):
                require(callable(getattr(iam, method, None)), 'required IAM capability unavailable')
            reconcile(journal, iam, binding, receipts)
            if mode == 'provision':
                if not journal.exists('binding.json'):
                    journal.write('binding.json', binding)
                journal.sync_completed()
                execute(journal, iam, who, p, receipts)
            return dict(result='COMPLETE' if mode == 'provision' else 'VERIFIED',
                        completed_actions=6 if mode == 'provision' else len(receipts),
                        credential_files=[str(STATE / (r + '.json')) for r in ('writer', 'publisher')
                                          if journal.exists(r + '.json')],
                        plan_sha256=PLAN_SHA, actual_s3_enforcement_proven=False)
        finally:
            iam.close()
            sts.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('status', 'provision', 'verify'))
    args = parser.parse_args(argv)
    try:
        result = run(args.mode)
    except Exception as exc:
        # Includes configparser, OS and SDK exceptions: none may disclose source
        # lines, request bodies, credentials, raw response dictionaries or paths.
        print(json.dumps(dict(result='REFUSED', reason=str(exc) if type(exc) is Refusal else
                              'source, journal or IAM operation failed; inspect local journal filenames; '
                              'pending actions require manual reconciliation',
                              remote_revocation_proven=False)))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

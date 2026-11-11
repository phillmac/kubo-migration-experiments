"""Offline fakes only: every live boundary is replaced, including under root CI."""
from contextlib import redirect_stdout
import io
import json
import logging
import os
from pathlib import Path
import socket
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_create_iam_credentials as p

ACCOUNT = '123456789012'
META = {'HTTPStatusCode': 200, 'RetryAttempts': 0}
SECRET = 'OFFLINE-SECRET-CANARY-NEVER-PRINT'
KEY = 'OFFLINEACCESSKEY00001'


class SDKError(Exception):
    def __init__(self, code='AccessDenied', status=403):
        super().__init__(SECRET)
        self.response = {'Error': {'Code': code, 'Message': SECRET},
                         'ResponseMetadata': {'HTTPStatusCode': status}}


class FakeSTS:
    def __init__(self):
        self.value = dict(Account=ACCOUNT, Arn=f'arn:aws:iam::{ACCOUNT}:root', UserId=ACCOUNT,
                          ResponseMetadata=META)

    def get_caller_identity(self):
        return self.value.copy()

    def close(self):
        pass


class FakeIAM:
    def __init__(self, state):
        self.state = state
        self.users, self.policies, self.keys = {}, {}, {}
        self.mutations = []
        self.fail_at = None
        self.failure = SDKError
        self.bad_response = False
        self.policy_override = None

    def mutate(self, action, user):
        i = len(self.mutations)
        # Prove intent is durable and previous receipt exists BEFORE each request.
        intent = json.loads((self.state / f'{i:02d}.intent.json').read_text())
        assert intent['action'] == action and intent['user'] == user
        if i:
            assert (self.state / f'{i-1:02d}.receipt.json').exists()
        self.mutations.append((action, user))
        if i == self.fail_at:
            raise self.failure()

    def create_user(self, UserName):
        self.mutate('CreateUser', UserName)
        if UserName in self.users:
            raise SDKError('EntityAlreadyExists', 409)
        row = dict(UserName=UserName, Path='/', Arn=f'arn:aws:iam::{ACCOUNT}:user/{UserName}',
                   UserId='offline-id-' + UserName)
        self.users[UserName] = row
        return dict(ResponseMetadata=META, User={} if self.bad_response else row.copy())

    def get_user(self, UserName):
        if UserName not in self.users:
            raise SDKError('NoSuchEntity', 404)
        return dict(ResponseMetadata=META, User=self.users[UserName].copy())

    def put_user_policy(self, UserName, PolicyName, PolicyDocument):
        self.mutate('PutUserPolicy', UserName)
        assert PolicyName == p.admin.POLICY_NAME
        document = json.loads(PolicyDocument)
        assert p.sha(p.canonical(document)) in p.POLICY_SHAS.values()
        self.policies[UserName] = document
        return dict(ResponseMetadata={} if self.bad_response else META)

    def get_user_policy(self, UserName, PolicyName):
        document = self.policies[UserName] if self.policy_override is None else self.policy_override
        return dict(ResponseMetadata=META, UserName=UserName, PolicyName=PolicyName,
                    PolicyDocument=quote(json.dumps(document)))

    def create_access_key(self, UserName):
        self.mutate('CreateAccessKey', UserName)
        row = dict(UserName=UserName, Status='Active', AccessKeyId=KEY + str(len(self.keys)),
                   SecretAccessKey=SECRET)
        self.keys[UserName] = [row]
        return dict(ResponseMetadata={} if self.bad_response else META, AccessKey=row.copy())

    def list_access_keys(self, UserName):
        return dict(ResponseMetadata=META, IsTruncated=False,
                    AccessKeyMetadata=[{k: v for k, v in row.items() if k != 'SecretAccessKey'}
                                       for row in self.keys.get(UserName, [])])

    def close(self):
        pass


class ProvisionerTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ))
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)
        self.addCleanup(logging.disable, logging.root.manager.disable)
        self.temp = tempfile.TemporaryDirectory(prefix='iam-FAKE-only-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / 'state'
        self.source = self.base / 'rclone-FAKE.conf'
        self.source.write_text('[wasabi-ca-central-1]\ntype = s3\nprovider = Wasabi\n'
                               'endpoint = s3.ca-central-1.wasabisys.com\n'
                               'access_key_id = OFFLINESOURCEKEY00001\n'
                               'secret_access_key = OFFLINE-SOURCE-CANARY-ONLY\n')
        self.source.chmod(0o600)
        self.iam, self.sts = FakeIAM(self.state), FakeSTS()
        # Explicit isolated filesystem seam: never use /root or real SDK, even as root.
        def fake_directory(path, *, create=False, private=False):
            assert path in (self.state, self.base)
            if create:
                path.mkdir(mode=0o700, exist_ok=True)
            info = path.stat()
            if private:
                p.require(stat.S_IMODE(info.st_mode) == 0o700, 'private directory must be 0700')
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for target, value in [('STATE', self.state), ('SOURCE', self.source),
                              ('OWNER', os.getuid()), ('directory', fake_directory)]:
            self.enterContext(patch.object(p, target, value))
        self.enterContext(patch.object(p.os, 'getuid', return_value=0))
        self.enterContext(patch.object(p.os, 'geteuid', return_value=0))
        self.client_factory = self.enterContext(patch.object(p, 'clients', return_value=(self.iam, self.sts)))
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('NETWORK FORBIDDEN')))
        self.enterContext(patch.object(socket, 'create_connection', side_effect=AssertionError('NETWORK FORBIDDEN')))

    def run_main(self, mode='provision'):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = p.main([mode])
        output = stdout.getvalue()
        for canary in (SECRET, KEY, 'OFFLINE-SOURCE-CANARY', 'OFFLINESOURCEKEY'):
            self.assertNotIn(canary, output)
        return result, json.loads(output)

    def test_success_six_ordered_actions_and_rerun_read_only(self):
        code, value = self.run_main()
        self.assertEqual(code, 0)
        self.assertEqual(value['result'], 'COMPLETE')
        self.assertEqual(self.iam.mutations, [(s['action'], s['user']) for s in p.admin._steps()])
        self.assertEqual(len(value['credential_files']), 2)
        for role in ('writer', 'publisher'):
            file = self.state / (role + '.json')
            saved = json.loads(file.read_text())
            self.assertEqual(saved['SecretAccessKey'], SECRET)
            self.assertEqual(saved['endpoint'], p.S3_ENDPOINT)
            self.assertEqual(saved['account'], ACCOUNT)
        for file in self.state.iterdir():
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            if file.name not in ('writer.json', 'publisher.json'):
                self.assertNotIn(SECRET, file.read_text())
                self.assertNotIn(KEY, file.read_text())
        before = {f.name: f.read_bytes() for f in self.state.iterdir()}
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.run_main('verify')[0], 0)
        self.assertEqual(len(self.iam.mutations), 6)
        self.assertEqual(before, {f.name: f.read_bytes() for f in self.state.iterdir()})

    def test_failure_each_action_leaves_pending_and_never_retries(self):
        for stage in range(6):
            with self.subTest(stage=stage):
                self.iam.fail_at = stage
                self.assertEqual(self.run_main()[0], 2)
                self.assertTrue((self.state / f'{stage:02d}.intent.json').exists())
                self.assertFalse((self.state / f'{stage:02d}.receipt.json').exists())
                self.assertEqual(self.run_main()[0], 2)
                self.assertEqual(len(self.iam.mutations), stage + 1)
                self.assertTrue(self.run_main('status')[1]['pending'])
                self.reset_fixture()

    def reset_fixture(self):
        import shutil
        shutil.rmtree(self.state)
        self.iam = FakeIAM(self.state)
        self.client_factory.return_value = (self.iam, self.sts)

    def test_timeout_each_action_never_retries(self):
        for stage in range(6):
            with self.subTest(stage=stage):
                self.iam.fail_at, self.iam.failure = stage, TimeoutError
                self.assertEqual(self.run_main()[0], 2)
                self.assertEqual(self.run_main()[0], 2)
                self.assertEqual(len(self.iam.mutations), stage + 1)
                self.reset_fixture()

    def test_unexpected_response_stops_without_receipt(self):
        self.iam.bad_response = True
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 1)

    def test_crash_before_receipt_each_action_is_not_adopted(self):
        original = p.Journal.write
        for stage in range(6):
            with self.subTest(stage=stage):
                def interrupted(journal, name, value):
                    if name == f'{stage:02d}.receipt.json':
                        raise OSError(SECRET)
                    return original(journal, name, value)
                with patch.object(p.Journal, 'write', interrupted):
                    self.assertEqual(self.run_main()[0], 2)
                self.assertEqual(self.run_main()[0], 2)
                self.assertEqual(len(self.iam.mutations), stage + 1)
                self.reset_fixture()

    def test_key_saving_failure_leaves_pending_without_reissue(self):
        original = p.Journal.write
        def broken(journal, name, value):
            if name == 'writer.json':
                raise OSError(SECRET)
            return original(journal, name, value)
        with patch.object(p.Journal, 'write', broken):
            self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 5)
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 5)
        self.assertFalse((self.state / '04.receipt.json').exists())

    def test_partial_intent_and_partial_receipt_fail_closed(self):
        self.iam.fail_at = 0
        self.run_main()
        for name in ('00.intent.json', '00.receipt.json'):
            (self.state / name).write_text('{')
            self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 1)

    def test_missing_or_changed_receipts_no_mutation(self):
        self.run_main()
        receipt = self.state / '02.receipt.json'
        original = receipt.read_text()
        value = json.loads(original)
        value['intent_sha256'] = '0' * 64
        receipt.write_bytes(p.canonical(value))
        self.assertEqual(self.run_main()[0], 2)
        receipt.write_text(original)
        (self.state / 'writer.json').unlink()
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 6)

    def test_root_refused_before_config_or_clients(self):
        with patch.object(p.os, 'geteuid', return_value=1000), patch.object(p, 'source_credentials') as source:
            self.assertEqual(self.run_main()[0], 2)
            source.assert_not_called()
        self.client_factory.assert_not_called()
        self.assertFalse(self.state.exists())

    def test_local_status_never_reads_credentials(self):
        with patch.object(p, 'source_credentials', side_effect=AssertionError('SOURCE READ')):
            self.assertEqual(self.run_main('status')[0], 0)
        self.client_factory.assert_not_called()

    def test_invalid_sts_identity_before_mutations(self):
        for field, value in [('Account', 'bad'), ('Arn', 'arn:aws:iam::999999999999:root'),
                             ('Arn', f'arn:aws:sts::{ACCOUNT}:assumed-role/admin/session'), ('UserId', '')]:
            original = self.sts.value[field]
            self.sts.value[field] = value
            self.assertEqual(self.run_main()[0], 2)
            self.assertFalse(self.iam.mutations)
            self.sts.value[field] = original

    def test_changed_bound_account_refused(self):
        self.run_main()
        self.sts.value.update(Account='999999999999', Arn='arn:aws:iam::999999999999:root')
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 6)

    def test_direct_root_entrypoint_clears_environment_before_source(self):
        os.environ.update(AWS_ACCESS_KEY_ID='ENV-CANARY', AWS_PROFILE='other',
                          AWS_CONFIG_FILE='/untrusted/config', HOME='/untrusted')
        original = p.source_credentials
        def check_environment():
            self.assertNotIn('AWS_ACCESS_KEY_ID', os.environ)
            self.assertNotIn('AWS_PROFILE', os.environ)
            self.assertNotIn('AWS_CONFIG_FILE', os.environ)
            self.assertEqual(os.environ['HOME'], '/nonexistent')
            return original()
        with patch.object(p, 'source_credentials', check_environment):
            self.assertEqual(self.run_main()[0], 0)

    def test_invalid_source_no_sdk(self):
        original = self.source.read_text()
        for content in ('[other]\n', original.replace('s3.ca-central-1.wasabisys.com', 'evil.invalid'),
                        original.replace('OFFLINESOURCEKEY00001', ''),
                        original + 'env_auth = true\n', original + 'session_token = token\n',
                        original + '[DEFAULT]\nsecret_access_key = hidden\n',
                        original.replace('type = s3', 'type = http')):
            with self.subTest(content=content[:10]):
                self.source.write_text(content)
                self.assertEqual(self.run_main()[0], 2)
                self.client_factory.assert_not_called()
        self.assertFalse(self.iam.mutations)

    def test_configparser_interpolation_disabled(self):
        text = self.source.read_text().replace('OFFLINE-SOURCE-CANARY-ONLY', 'OFFLINE%literal%secret')
        self.source.write_text(text)
        self.assertEqual(p.source_credentials()[1], 'OFFLINE%literal%secret')

    def test_source_symlink_hardlink_and_mode_refused(self):
        self.source.chmod(0o644)
        self.assertEqual(self.run_main()[0], 2)
        self.source.chmod(0o600)
        other = self.base / 'source-link'
        os.link(self.source, other)
        self.assertEqual(self.run_main()[0], 2)
        other.unlink()
        self.source.rename(other)
        self.source.symlink_to(other)
        self.assertEqual(self.run_main()[0], 2)
        self.client_factory.assert_not_called()

    def test_user_collision_no_adoption(self):
        self.iam.users[p.admin.PUBLISHER] = {}
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_read_capability_denied_no_mutation(self):
        self.iam.get_user = Mock(side_effect=SDKError())
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_wrong_local_policy_hash_no_source_read(self):
        with patch.dict(p.POLICY_SHAS, writer='0' * 64):
            self.assertEqual(self.run_main()[0], 2)
        self.client_factory.assert_not_called()

    def test_wrong_remote_policy_hash_before_keys(self):
        self.iam.policy_override = {}
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 3)
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.keys)

    def test_reconciliation_failure_never_advances(self):
        self.run_main()
        self.iam.users[p.admin.WRITER]['UserId'] = 'external-replacement'
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 6)

    def test_resume_completed_prefix_reconciles_before_advancing(self):
        original = p.Journal.write
        def stop_before_intent(journal, name, value):
            if name == '03.intent.json':
                raise OSError('offline simulated stop before request')
            return original(journal, name, value)
        with patch.object(p.Journal, 'write', stop_before_intent):
            self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 3)
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(len(self.iam.mutations), 6)

    def test_foreign_key_inventory_blocks_resume(self):
        original = p.Journal.write
        def stop(journal, name, value):
            if name == '04.intent.json':
                raise OSError('stop')
            return original(journal, name, value)
        with patch.object(p.Journal, 'write', stop):
            self.run_main()
        self.iam.keys[p.admin.WRITER] = [dict(UserName=p.admin.WRITER, Status='Active', AccessKeyId=KEY)]
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 4)

    def test_status_does_not_read_saved_secret_files(self):
        self.run_main()
        original = p.Journal.raw
        def public_only(journal, name):
            self.assertNotIn(name, ('writer.json', 'publisher.json'))
            return original(journal, name)
        with patch.object(p.Journal, 'raw', public_only), patch.object(
                p, 'source_credentials', side_effect=AssertionError('credential source opened')):
            self.assertEqual(self.run_main('status')[0], 0)

    def test_pending_stops_before_source_or_clients(self):
        self.iam.fail_at = 4
        self.run_main()
        before = self.client_factory.call_count
        with patch.object(p, 'source_credentials', side_effect=AssertionError('source after pending')):
            self.assertEqual(self.run_main()[0], 2)
            self.assertEqual(self.run_main('verify')[0], 2)
        self.assertEqual(self.client_factory.call_count, before)

    def test_no_arbitrary_cli_arguments_or_disabled_modes(self):
        for args in (['provision', '--user', 'other'], ['cleanup'], ['lockout']):
            with redirect_stdout(io.StringIO()), patch('sys.stderr', new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as error:
                    p.main(args)
                self.assertEqual(error.exception.code, 2)
        self.client_factory.assert_not_called()

    def test_private_key_file_integrity_and_extra_remote_keys_refused(self):
        self.run_main()
        file = self.state / 'writer.json'
        raw = file.read_bytes()
        saved = json.loads(raw)
        saved['SecretAccessKey'] = 'CHANGED-FAKE-SECRET-CANARY'
        file.write_bytes(p.canonical(saved))
        self.assertEqual(self.run_main()[0], 2)
        file.write_bytes(raw)
        self.iam.keys[p.admin.WRITER].append(dict(self.iam.keys[p.admin.WRITER][0]))
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 6)

    def test_store_exclusive_permissions_flock_and_no_overwrite(self):
        with p.Journal() as journal:
            journal.write('binding.json', {'public': 'fixture'})
            with self.assertRaises(FileExistsError):
                journal.write('binding.json', {'public': 'overwrite'})
            with self.assertRaises(BlockingIOError):
                with p.Journal():
                    self.fail('second lock acquired')
            (self.state / 'binding.json').chmod(0o640)
            with self.assertRaises(p.Refusal):
                journal.read('binding.json')
        self.state.chmod(0o750)
        self.assertEqual(self.run_main()[0], 2)

    def test_store_wrong_owner_refused(self):
        self.run_main('status')
        with patch.object(p, 'OWNER', -1):
            self.assertEqual(self.run_main()[0], 2)
        self.client_factory.assert_not_called()

    def test_fsync_failure_before_request_never_calls_iam(self):
        self.run_main('status')
        with patch.object(p.os, 'fsync', side_effect=OSError(SECRET)):
            self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)


class ClientFactoryTests(unittest.TestCase):
    def test_fake_boto3_and_botocore_fixed_endpoints_and_no_retries(self):
        self.addCleanup(logging.disable, logging.root.manager.disable)
        # Never import actual boto3; validate SDK wiring with synthetic modules.
        fake_session, config = Mock(), Mock()
        session_factory = Mock(return_value=fake_session)
        fake_boto = types.SimpleNamespace(Session=session_factory)
        fake_config = types.SimpleNamespace(Config=config)
        with patch.dict(sys.modules, {'boto3': fake_boto, 'botocore': types.ModuleType('botocore'),
                                      'botocore.config': fake_config}):
            p.clients(KEY, SECRET)
        self.assertEqual(config.call_args.kwargs['retries']['total_max_attempts'], 1)
        self.assertEqual(config.call_args.kwargs['connect_timeout'], 5)
        self.assertEqual(config.call_args.kwargs['read_timeout'], 10)
        self.assertEqual(config.call_args.kwargs['proxies'], {})
        calls = fake_session.client.call_args_list
        self.assertEqual([c.args[0] for c in calls], ['iam', 'sts'])
        self.assertEqual([c.kwargs['endpoint_url'] for c in calls],
                         ['https://iam.wasabisys.com', 'https://sts.wasabisys.com'])
        self.assertTrue(all(c.kwargs['region_name'] == 'us-east-1' for c in calls))
        self.assertTrue(all(c.kwargs['aws_secret_access_key'] == SECRET for c in calls))


if __name__ == '__main__':
    unittest.main()

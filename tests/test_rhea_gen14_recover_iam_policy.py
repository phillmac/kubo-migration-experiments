"""Managed-policy recovery against isolated fakes; real network is forbidden."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import unittest
from unittest.mock import patch
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_create_iam_credentials as p
import rhea_gen14_recover_iam_policy as r
import test_rhea_gen14_create_iam_credentials as legacy_fixture
from test_rhea_gen14_create_iam_credentials import (
    ACCOUNT, KEY, META, SECRET, FakeIAM, SDKError,
)


class ManagedIAM(FakeIAM):
    """Stateful provider fake: errors carry a secret canary for redaction checks."""

    def __init__(self, legacy_state, recovery_state, users):
        super().__init__(legacy_state)
        self.recovery_state = recovery_state
        self.users = copy.deepcopy(users)
        self.managed = {}
        self.attached = {user: [] for user in users}
        self.inline_names = {user: [] for user in users}
        self.groups = {user: [] for user in users}
        self.fail_before = None
        self.fail_after = None
        self.failure = SDKError
        self.policy_version_override = None
        self.collapse_singletons = False
        self.attachment_readback_empty = False
        self.list_truncated = None
        self.quotas = dict(UserPolicySizeQuota=2048, PolicySizeQuota=5120,
                           AttachedPoliciesPerUserQuota=10)

    def mutate(self, action, target):
        index = len(self.mutations)
        # Each requested mutation must have a durable new-journal intent first.
        intent = self.recovery_state / f'{index:02d}.intent.json'
        assert intent.is_file(), ('mutation without durable intent', action)
        if index:
            assert (self.recovery_state / f'{index - 1:02d}.receipt.json').is_file()
        self.mutations.append((action, target))
        if index == self.fail_before:
            raise self.failure()

    def after_mutation(self):
        if len(self.mutations) - 1 == self.fail_after:
            raise self.failure()

    def create_user(self, **kwargs):
        raise AssertionError('recovery must not recreate either existing user')

    def put_user_policy(self, **kwargs):
        raise AssertionError('recovery must not resubmit oversized inline policies')

    def get_user_policy(self, UserName, PolicyName):
        if UserName not in self.policies:
            raise SDKError('NoSuchEntity', 404)
        return dict(ResponseMetadata=META, UserName=UserName, PolicyName=PolicyName,
                    PolicyDocument=self.policies[UserName])

    def get_account_summary(self):
        return dict(ResponseMetadata=META, SummaryMap=self.quotas.copy())

    def get_policy(self, PolicyArn):
        if PolicyArn not in self.managed:
            raise SDKError('NoSuchEntity', 404)
        return dict(ResponseMetadata=META,
                    Policy=copy.deepcopy(self.managed[PolicyArn]['metadata']))

    def create_policy(self, PolicyName, PolicyDocument, Path='/', **kwargs):
        self.mutate('CreatePolicy', PolicyName)
        arn = f'arn:aws:iam::{ACCOUNT}:policy/{PolicyName}'
        if arn in self.managed:
            raise SDKError('EntityAlreadyExists', 409)
        document = json.loads(PolicyDocument)
        assert p.sha(p.canonical(document)) in p.POLICY_SHAS.values()
        metadata = dict(PolicyName=PolicyName, Arn=arn, Path=Path,
                        PolicyId='offline-policy-' + PolicyName,
                        DefaultVersionId='v1', AttachmentCount=0, IsAttachable=True)
        self.managed[arn] = dict(metadata=metadata, document=document)
        self.after_mutation()
        return dict(ResponseMetadata=META, Policy=metadata.copy())

    def get_policy_version(self, PolicyArn, VersionId):
        if PolicyArn not in self.managed:
            raise SDKError('NoSuchEntity', 404)
        row = self.managed[PolicyArn]
        document = (row['document'] if self.policy_version_override is None
                    else self.policy_version_override)
        if self.collapse_singletons:
            document = self.provider_scalar_form(document)
        return dict(ResponseMetadata=META, PolicyVersion=dict(
            VersionId=VersionId, IsDefaultVersion=True,
            Document=quote(json.dumps(document))))

    @staticmethod
    def provider_scalar_form(document):
        """Represent the concrete singleton collapsing observed from Wasabi."""
        result = copy.deepcopy(document)
        for statement in result.get('Statement', []):
            for field in ('Action', 'NotAction', 'Resource', 'NotResource'):
                values = statement.get(field)
                if isinstance(values, list) and len(values) == 1:
                    statement[field] = values[0]
            for operator in ('StringLike', 'StringNotLike'):
                condition = statement.get('Condition', {}).get(operator, {})
                values = condition.get('s3:prefix')
                if isinstance(values, list) and len(values) == 1:
                    condition['s3:prefix'] = values[0]
        return result

    def attach_user_policy(self, UserName, PolicyArn):
        self.mutate('AttachUserPolicy', UserName)
        if PolicyArn not in self.managed:
            raise SDKError('NoSuchEntity', 404)
        if PolicyArn not in self.attached[UserName]:
            self.attached[UserName].append(PolicyArn)
            self.managed[PolicyArn]['metadata']['AttachmentCount'] += 1
        self.after_mutation()
        return dict(ResponseMetadata=META)

    def list_attached_user_policies(self, UserName, **kwargs):
        rows = [dict(PolicyArn=arn, PolicyName=arn.rsplit('/', 1)[-1])
                for arn in self.attached[UserName]]
        if self.attachment_readback_empty:
            rows = []
        return dict(ResponseMetadata=META, AttachedPolicies=rows,
                    IsTruncated=self.list_truncated == 'attached')

    def list_user_policies(self, UserName, **kwargs):
        return dict(ResponseMetadata=META,
                    PolicyNames=list(self.inline_names[UserName]),
                    IsTruncated=self.list_truncated == 'inline')

    def list_groups_for_user(self, UserName, **kwargs):
        return dict(ResponseMetadata=META, Groups=list(self.groups[UserName]),
                    IsTruncated=self.list_truncated == 'groups')

    def create_access_key(self, UserName):
        # Both exact reviewed policy documents must be attached before any key.
        for role, user in p.admin.plan()['users'].items():
            arn = f'arn:aws:iam::{ACCOUNT}:policy/{r.POLICY_NAMES[role]}'
            assert self.attached[user] == [arn], 'key requested before both attachments'
            assert p.sha(p.canonical(self.managed[arn]['document'])) == p.POLICY_SHAS[role]
        self.mutate('CreateAccessKey', UserName)
        assert not self.keys.get(UserName), 'unrecorded or duplicate key creation'
        row = dict(UserName=UserName, Status='Active',
                   AccessKeyId=KEY + str(len(self.keys)), SecretAccessKey=SECRET)
        self.keys[UserName] = [row]
        self.after_mutation()
        return dict(ResponseMetadata=META, AccessKey=row.copy())


class ManagedRecoveryTests(unittest.TestCase):
    def setUp(self):
        # Reuse the isolated filesystem/source/SDK fixtures, not their test cases.
        legacy_fixture.ProvisionerTests.setUp(self)
        self.recovery = self.base / 'managed-state'
        self.enterContext(patch.object(r, 'STATE', self.recovery))

        def fake_directory(path, *, create=False, private=False):
            assert path in (self.state, self.base, self.recovery), path
            if create:
                path.mkdir(mode=0o700, exist_ok=True)
            info = path.stat()
            if private:
                p.require(stat.S_IMODE(info.st_mode) == 0o700,
                          'private directory must be 0700')
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)

        self.enterContext(patch.object(p, 'directory', fake_directory))
        self.iam.fail_at = 2
        with redirect_stdout(io.StringIO()):
            self.assertEqual(p.main(['provision']), 2)
        self.seed_users = copy.deepcopy(self.iam.users)
        self.legacy_before = self.snapshot(self.state)
        self.reset_managed()

    @staticmethod
    def snapshot(directory):
        if not directory.exists():
            return {}
        return {f.name: f.read_bytes() for f in directory.iterdir() if f.is_file()}

    def reset_managed(self):
        if self.recovery.exists():
            shutil.rmtree(self.recovery)
        self.iam = ManagedIAM(self.state, self.recovery, self.seed_users)
        self.client_factory.return_value = (self.iam, self.sts)

    def run_main(self, mode='recover'):
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = r.main([mode])
        output = stdout.getvalue()
        for canary in (SECRET, KEY, 'OFFLINE-SOURCE-CANARY', 'OFFLINESOURCEKEY'):
            self.assertNotIn(canary, output)
        return code, json.loads(output)

    def test_success_preserves_legacy_and_uses_exact_policies_before_keys(self):
        code, result = self.run_main()
        self.assertEqual(code, 0, result)
        self.assertEqual(len(self.iam.mutations), 6)
        self.assertEqual([a for a, _ in self.iam.mutations],
                         ['CreatePolicy'] * 2 + ['AttachUserPolicy'] * 2 + ['CreateAccessKey'] * 2)
        self.assertEqual(self.snapshot(self.state), self.legacy_before)
        self.assertFalse((self.state / '02.receipt.json').exists())
        for role in ('writer', 'publisher'):
            credential = self.recovery / (role + '.json')
            self.assertEqual(json.loads(credential.read_text())['SecretAccessKey'], SECRET)
            self.assertEqual(stat.S_IMODE(credential.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.recovery.stat().st_mode), 0o700)
        for artifact in self.recovery.iterdir():
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            if artifact.name not in ('writer.json', 'publisher.json'):
                self.assertNotIn(SECRET, artifact.read_text())
                self.assertNotIn(KEY, artifact.read_text())

    def test_provider_scalar_forms_for_both_roles_match_original_documents(self):
        self.iam.collapse_singletons = True
        code, result = self.run_main()
        self.assertEqual(code, 0, result)
        self.assertEqual(len(self.iam.mutations), 6)
        self.assertEqual(self.run_main('verify')[0], 0)
        for role in ('writer', 'publisher'):
            expected = p.reviewed_plan()['policies'][role]['document']
            wire = self.iam.provider_scalar_form(expected)
            before = copy.deepcopy(wire)
            restored = r.normalize_policy(wire)
            self.assertEqual(restored, expected)
            self.assertEqual(p.sha(p.canonical(restored)), p.POLICY_SHAS[role])
            self.assertEqual(wire, before, 'normalizer mutated provider input')

    def test_interrupted_writer_creation_resumes_with_provider_scalar_readback(self):
        self.iam.collapse_singletons = True
        self.iam.fail_after = 0
        self.iam.failure = TimeoutError
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.managed), 1)
        self.assertFalse((self.recovery / '00.receipt.json').exists())
        code, result = self.run_main()
        self.assertEqual(code, 0, result)
        self.assertEqual(len(self.iam.mutations), 6)
        self.assertEqual(sum(action == 'CreatePolicy' for action, _ in self.iam.mutations), 2)
        self.assertEqual(self.snapshot(self.state), self.legacy_before)

    def test_scalar_normalization_rejects_permission_or_other_document_changes(self):
        for change in ('scalar_action', 'extra_action', 'extra_resource', 'prefix',
                       'null_condition', 'unknown_field', 'reordered_statements'):
            with self.subTest(change=change):
                document = self.iam.provider_scalar_form(
                    p.reviewed_plan()['policies']['writer']['document'])
                if change == 'scalar_action':
                    document['Statement'][0]['Action'] = 's3:PutObject'
                elif change == 'extra_action':
                    document['Statement'][0]['Action'] = ['s3:*', 'iam:*']
                elif change == 'extra_resource':
                    row = next(row for row in document['Statement'] if 'Resource' in row)
                    value = row['Resource']
                    row['Resource'] = (value if isinstance(value, list) else [value]) + ['arn:aws:s3:::other/*']
                elif change == 'prefix':
                    row = next(row for row in document['Statement'] if 'StringLike' in row.get('Condition', {}))
                    row['Condition']['StringLike']['s3:prefix'] = 'outside/*'
                elif change == 'null_condition':
                    row = next(row for row in document['Statement'] if 'Null' in row.get('Condition', {}))
                    row['Condition']['Null']['s3:prefix'] = 'false'
                elif change == 'unknown_field':
                    document['Statement'][0]['Unexpected'] = 'ignored-by-bad-normalizers'
                else:
                    document['Statement'].reverse()
                self.iam.policy_version_override = document
                code, result = self.run_main()
                self.assertEqual(code, 2, result)
                self.assertFalse(self.iam.keys)
                self.assertFalse(any(self.iam.attached.values()))
                self.reset_managed()

    def test_completed_rerun_and_inspect_do_not_issue_new_keys(self):
        self.assertEqual(self.run_main()[0], 0)
        before = self.snapshot(self.recovery)
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(self.run_main('inspect')[0], 0)
        self.assertEqual(self.run_main('verify')[0], 0)
        self.assertEqual(len(self.iam.mutations), 6)
        self.assertEqual(self.snapshot(self.recovery), before)
        self.assertEqual(self.snapshot(self.state), self.legacy_before)

    def test_inspect_initial_state_makes_no_mutations(self):
        code, result = self.run_main('inspect')
        self.assertEqual(code, 0, result)
        self.assertFalse(self.iam.mutations)
        self.assertEqual(self.snapshot(self.state), self.legacy_before)

    def test_status_never_opens_credentials_or_iam(self):
        with patch.object(p, 'source_credentials', side_effect=AssertionError('SOURCE FORBIDDEN')):
            with patch.object(p, 'clients', side_effect=AssertionError('SDK FORBIDDEN')):
                code, result = self.run_main('status')
        self.assertEqual(code, 0, result)
        self.assertFalse(self.iam.mutations)
        self.assertEqual(self.snapshot(self.state), self.legacy_before)

    def test_verify_does_not_claim_completion_for_unstarted_recovery(self):
        code, result = self.run_main('verify')
        self.assertEqual(code, 2, result)
        self.assertFalse(self.iam.mutations)

    def test_wrong_account_cannot_mutate(self):
        self.sts.value['Account'] = '210987654321'
        self.sts.value['Arn'] = 'arn:aws:iam::210987654321:root'
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_unknown_provider_error_fields_do_not_echo_secret(self):
        self.iam.fail_before = 0
        self.iam.failure = lambda: SDKError(SECRET, 403)
        code, result = self.run_main()
        self.assertEqual(code, 2)
        self.assertIsNone(result['error_code'])
        self.assertEqual(result['http_status'], 403)

    def test_changed_existing_user_identity_cannot_mutate(self):
        user = p.admin.plan()['users']['writer']
        self.iam.users[user]['UserId'] = 'different-principal'
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_existing_inline_policy_group_attachment_or_key_is_not_adopted(self):
        user = p.admin.plan()['users']['writer']
        scenarios = ('inline', 'group', 'attached', 'key')
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                if scenario == 'inline':
                    self.iam.inline_names[user] = ['unexpected-policy']
                elif scenario == 'group':
                    self.iam.groups[user] = [dict(GroupName='unexpected-group')]
                elif scenario == 'attached':
                    self.iam.attached[user] = [f'arn:aws:iam::{ACCOUNT}:policy/unexpected']
                else:
                    self.iam.keys[user] = [dict(UserName=user, Status='Active',
                                               AccessKeyId=KEY, SecretAccessKey=SECRET)]
                self.assertEqual(self.run_main()[0], 2)
                self.assertFalse(self.iam.mutations)
                self.reset_managed()

    def test_truncated_inventories_cannot_authorize_recovery(self):
        for listing in ('inline', 'groups', 'attached'):
            with self.subTest(listing=listing):
                self.iam.list_truncated = listing
                self.assertEqual(self.run_main()[0], 2)
                self.assertFalse(self.iam.mutations)
                self.reset_managed()

    def test_existing_managed_policy_name_collision_is_not_adopted(self):
        name = r.POLICY_NAMES['writer']
        arn = f'arn:aws:iam::{ACCOUNT}:policy/{name}'
        self.iam.managed[arn] = dict(metadata=dict(
            PolicyName=name, Arn=arn, Path='/', PolicyId='preexisting',
            DefaultVersionId='v1', IsAttachable=True, AttachmentCount=0),
            document=p.reviewed_plan()['policies']['writer']['document'])
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_inadequate_managed_size_quota_stops_before_mutation(self):
        self.iam.quotas['PolicySizeQuota'] = 2048
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_failure_at_each_new_mutation_does_not_retry(self):
        for action in range(6):
            with self.subTest(action=action):
                self.iam.fail_before = action
                code, result = self.run_main()
                self.assertEqual(code, 2, result)
                count = len(self.iam.mutations)
                self.assertEqual(count, action + 1)
                self.assertEqual(self.run_main()[0], 2)
                self.assertEqual(len(self.iam.mutations), count)
                self.assertEqual(self.snapshot(self.state), self.legacy_before)
                self.reset_managed()

    def test_lost_key_response_never_reissues_or_prints_secret(self):
        self.iam.fail_after = 4
        self.iam.failure = TimeoutError
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.keys), 1)
        self.assertFalse((self.recovery / 'writer.json').exists())
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 5)
        self.assertEqual(len(self.iam.keys), 1)

    def test_pending_policy_and_attachment_resolve_from_exact_remote_evidence(self):
        for action in (0, 1, 2, 3):
            with self.subTest(action=action):
                self.iam.fail_after = action
                self.iam.failure = TimeoutError
                self.assertEqual(self.run_main()[0], 2)
                before = list(self.iam.mutations)
                code, result = self.run_main()
                self.assertEqual(code, 0, result)
                self.assertEqual(self.iam.mutations[:len(before)], before)
                self.assertEqual(len(self.iam.mutations), 6)
                self.assertEqual(self.snapshot(self.state), self.legacy_before)
                self.reset_managed()

    def test_completed_prefix_resumes_without_recreating_policies(self):
        write = r.Journal.write

        def stop_before_next_intent(journal, name, value):
            if name == '02.intent.json':
                raise OSError(SECRET)
            return write(journal, name, value)

        with patch.object(r.Journal, 'write', stop_before_next_intent):
            self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 2)
        code, result = self.run_main()
        self.assertEqual(code, 0, result)
        self.assertEqual(len(self.iam.mutations), 6)

    def test_secret_save_failure_never_reissues_key(self):
        write = r.Journal.write

        def fail_secret_save(journal, name, value):
            if name == 'writer.json':
                raise OSError(SECRET)
            return write(journal, name, value)

        with patch.object(r.Journal, 'write', fail_secret_save):
            self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.keys), 1)
        self.assertFalse((self.recovery / 'writer.json').exists())
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 5)

    def test_remote_document_mismatch_blocks_keys(self):
        self.iam.policy_version_override = {'Version': '2012-10-17', 'Statement': []}
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.keys)
        self.assertNotIn('CreateAccessKey', [action for action, _ in self.iam.mutations])

    def test_attachment_readback_mismatch_blocks_keys(self):
        self.iam.attachment_readback_empty = True
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.keys)

    def test_old_journal_changed_after_binding_blocks_resume(self):
        self.iam.fail_before = 0
        self.assertEqual(self.run_main()[0], 2)
        target = self.state / '00.receipt.json'
        value = json.loads(target.read_text())
        value['result']['user_id_sha256'] = '0' * 64
        target.write_bytes(p.canonical(value))
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 1)

    def test_old_pending_key_state_is_not_accepted(self):
        # A later legacy intent changes the accepted state; it must never be skipped.
        (self.state / '04.intent.json').write_text('{}')
        (self.state / '04.intent.json').chmod(0o600)
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)


if __name__ == '__main__':
    unittest.main()

"""Credential issuance against isolated IAM/filesystem fakes; network is forbidden."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import stat
import sys
import unittest
from unittest.mock import patch
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_clone_credentials as c
import test_rhea_gen14_create_iam_credentials as f
from test_rhea_gen14_recover_iam_policy import ManagedIAM

CHECKPOINT = {'manifest_marker': 'marker.manifest.000016.MANIFEST-000111'}
MARKER = 'marker.manifest.000017.MANIFEST-000123'


def publication_plan():
    return dict(schema=1, bucket=c.BUCKET, prefix=c.PREFIX, generation=14,
                previous_checkpoint_sha256=c.CHECKPOINT_SHA,
                closed_writer_sha256='1' * 64, before_proof_sha256='2' * 64,
                quarantine_sha256='3' * 64,
                markers=[dict(name=MARKER, size=0, sha256=c.p.sha(b''))])


class CloneIAM(f.FakeIAM):
    def __init__(self, state):
        super().__init__(state)
        self.managed, self.attached, self.groups, self.inline_names = {}, {}, {}, {}
        self.fail_before = self.fail_after = None
        self.after = lambda *args: None
        self.scalar_form, self.encoded_document = False, True
        self.quota = 5120
        self.version_override = None
        self.version_is_default = True
        self.truncated = None

    def mutate(self, action, user):
        role = next(role for role, value in c.USERS.items() if value == user)
        index = sum(target == user for _, target in self.mutations)
        directory = self.state / role
        bound = json.loads((directory / 'binding.json').read_text())
        intent_path = directory / f'{index:02d}.intent.json'
        intent = json.loads(intent_path.read_text())
        assert intent['action'] == action and intent['binding_sha256'] == c.policies.digest(bound)
        assert intent['sequence'] == index
        assert stat.S_IMODE(intent_path.stat().st_mode) == 0o600
        previous = bound if index == 0 else json.loads((directory / f'{index - 1:02d}.receipt.json').read_text())
        assert intent['previous_sha256'] == c.policies.digest(previous)
        self.mutations.append((action, user))
        if action == self.fail_before:
            raise TimeoutError(f.SECRET)

    def complete(self, action, user):
        self.after(action, user)
        if action == self.fail_after:
            raise TimeoutError(f.SECRET)

    def create_user(self, UserName):
        self.mutate('CreateUser', UserName)
        if UserName in self.users:
            raise f.SDKError('EntityAlreadyExists', 409)
        row = dict(UserName=UserName, Path='/', Arn=f'arn:aws:iam::{f.ACCOUNT}:user/{UserName}',
                   UserId='offline-clone-id-' + UserName)
        self.users[UserName] = row
        self.attached[UserName], self.groups[UserName], self.inline_names[UserName] = [], [], []
        self.complete('CreateUser', UserName)
        return dict(ResponseMetadata=f.META, User=row.copy())

    def get_account_summary(self):
        return dict(ResponseMetadata=f.META, SummaryMap=dict(PolicySizeQuota=self.quota))

    def get_policy(self, PolicyArn):
        if PolicyArn not in self.managed:
            raise f.SDKError('NoSuchEntity', 404)
        return dict(ResponseMetadata=f.META, Policy=copy.deepcopy(self.managed[PolicyArn]['metadata']))

    def create_policy(self, PolicyName, Path, PolicyDocument):
        role = next(role for role, name in c.POLICY_NAMES.items() if name == PolicyName)
        user = c.USERS[role]
        self.mutate('CreatePolicy', user)
        arn = f'arn:aws:iam::{f.ACCOUNT}:policy/{PolicyName}'
        if arn in self.managed:
            raise f.SDKError('EntityAlreadyExists', 409)
        metadata = dict(Arn=arn, PolicyName=PolicyName, Path=Path,
                        PolicyId='offline-clone-policy-' + role, DefaultVersionId='v1')
        self.managed[arn] = dict(metadata=metadata, document=json.loads(PolicyDocument))
        self.complete('CreatePolicy', user)
        return dict(ResponseMetadata=f.META, Policy=metadata.copy())

    def get_policy_version(self, PolicyArn, VersionId):
        document = copy.deepcopy(self.managed[PolicyArn]['document'])
        if self.scalar_form:
            document = ManagedIAM.provider_scalar_form(document)
        if self.encoded_document:
            document = quote(json.dumps(document))
        return dict(ResponseMetadata=f.META, PolicyVersion=dict(
            VersionId=self.version_override or VersionId,
            IsDefaultVersion=self.version_is_default, Document=document))

    def attach_user_policy(self, UserName, PolicyArn):
        self.mutate('AttachUserPolicy', UserName)
        self.attached[UserName].append(PolicyArn)
        self.complete('AttachUserPolicy', UserName)
        return dict(ResponseMetadata=f.META)

    def list_attached_user_policies(self, UserName):
        rows = [dict(PolicyArn=arn, PolicyName=arn.rsplit('/', 1)[-1]) for arn in self.attached[UserName]]
        return dict(ResponseMetadata=f.META, IsTruncated=self.truncated == 'attached', AttachedPolicies=rows)

    def list_user_policies(self, UserName):
        return dict(ResponseMetadata=f.META, IsTruncated=self.truncated == 'inline',
                    PolicyNames=list(self.inline_names[UserName]))

    def list_groups_for_user(self, UserName):
        return dict(ResponseMetadata=f.META, IsTruncated=self.truncated == 'groups',
                    Groups=list(self.groups[UserName]))

    def create_access_key(self, UserName):
        self.mutate('CreateAccessKey', UserName)
        assert not self.keys.get(UserName), 'an existing key was silently adopted'
        row = dict(UserName=UserName, Status='Active', AccessKeyId=f.KEY + str(len(self.keys)),
                   SecretAccessKey=f.SECRET)
        self.keys[UserName] = [row]
        self.complete('CreateAccessKey', UserName)
        return dict(ResponseMetadata=f.META, AccessKey=row.copy())


class CloneCredentialTests(unittest.TestCase):
    def setUp(self):
        f.ProvisionerTests.setUp(self)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(c.p.main(['provision']), 0)
        self.old_state = {file.name: file.read_bytes() for file in self.state.iterdir()}
        self.clone = self.base / 'clone'
        self.trial = self.base / 'trial'
        self.trial.mkdir(mode=0o700)
        self.enterContext(patch.object(c, 'STATE', self.clone))
        self.enterContext(patch.object(c, 'TRIAL', self.trial))
        self.checkpoint = self.enterContext(patch.object(c, 'anchored_checkpoint', return_value=copy.deepcopy(CHECKPOINT)))
        def directory(path, *, create=False, private=False):
            assert path == self.base or self.base in path.parents, ('real filesystem access', path)
            if create:
                path.mkdir(mode=0o700, parents=True, exist_ok=True)
            if private:
                c.p.require(stat.S_IMODE(path.stat().st_mode) == 0o700, 'private directory must be 0700')
            return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.enterContext(patch.object(c.p, 'directory', directory))
        self.iam = CloneIAM(self.clone)
        self.client_factory.return_value = (self.iam, self.sts)

    def run_main(self, role='writer'):
        output = io.StringIO()
        with redirect_stdout(output):
            code = c.main([role])
        for secret in (f.SECRET, f.KEY, 'OFFLINE-SOURCE-CANARY', 'OFFLINESOURCEKEY'):
            self.assertNotIn(secret, output.getvalue())
        return code, json.loads(output.getvalue())

    def save_plan(self, plan=None):
        path = self.trial / 'publisher-plan.json'
        path.write_bytes(c.policies.canonical(plan or publication_plan()))
        path.chmod(0o600)
        return path

    def bound(self, role='writer'):
        return json.loads((self.clone / role / 'binding.json').read_bytes())

    def test_writer_creation_has_durable_intents_and_does_not_need_publisher_plan(self):
        with patch.object(c, 'publisher_keys', side_effect=AssertionError('writer read publisher plan')):
            code, result = self.run_main()
        self.assertEqual(code, 0, result)
        self.assertEqual(result['result'], 'VERIFIED')
        self.assertEqual([action for action, _ in self.iam.mutations],
                         ['CreateUser', 'CreatePolicy', 'AttachUserPolicy', 'CreateAccessKey'])
        self.assertFalse((self.clone / 'publisher').exists())
        for file in (self.clone / 'writer').iterdir():
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
            if file.name != 'credential.json':
                self.assertNotIn(f.SECRET, file.read_text())
                self.assertNotIn(f.KEY, file.read_text())
        before = {file.name: file.read_bytes() for file in (self.clone / 'writer').iterdir()}
        self.assertEqual(self.run_main()[0], 0)
        self.assertEqual(len(self.iam.mutations), 4)
        self.assertEqual(before, {file.name: file.read_bytes() for file in (self.clone / 'writer').iterdir()})
        self.assertEqual(self.old_state, {file.name: file.read_bytes() for file in self.state.iterdir()})

    def test_writer_policy_is_independent_of_publication_marker_and_plan(self):
        left = c.binding(f.ACCOUNT, 'writer', CHECKPOINT)
        right = c.binding(f.ACCOUNT, 'writer', dict(manifest_marker=MARKER))
        self.assertEqual(left, right)
        self.assertEqual(left['publication_keys'], [])
        self.assertIsNone(left['publication_plan_sha256'])

    def test_publisher_requires_writer_and_only_one_empty_marker(self):
        self.save_plan()
        code, value = self.run_main('publisher')
        self.assertEqual(code, 2, value)
        self.assertIn('writer must exist', value['reason'])
        self.assertFalse(self.iam.mutations)
        self.assertEqual(self.run_main()[0], 0)
        code, value = self.run_main('publisher')
        self.assertEqual(code, 0, value)
        bound = self.bound('publisher')
        self.assertEqual(bound['publication_keys'], [MARKER])
        allow = next(row for row in bound['policy_document']['Statement'] if row['Sid'] == 'ExactPublicationOnly')
        self.assertEqual(allow['Resource'], [f'arn:aws:s3:::{c.BUCKET}/{c.PREFIX}{MARKER}'])
        self.assertEqual(len(self.iam.mutations), 8)

    def test_invalid_publisher_plans_are_rejected_without_iam_mutations(self):
        cases = []
        for name in ('CURRENT', 'marker.manifest', 'marker.format-version.000017.013',
                     'marker.manifest.000016.MANIFEST-000123', c.PREFIX + MARKER, '../' + MARKER):
            plan = publication_plan()
            plan['markers'][0]['name'] = name
            cases.append(plan)
        for field, value in (('size', 1), ('size', False), ('sha256', '0' * 64)):
            plan = publication_plan()
            plan['markers'][0][field] = value
            cases.append(plan)
        for field, value in (('bucket', 'production'), ('prefix', 'another/'), ('generation', 13),
                             ('schema', True), ('closed_writer_sha256', 'invalid'),
                             ('before_proof_sha256', None), ('quarantine_sha256', 'no'),
                             ('previous_checkpoint_sha256', '4' * 64)):
            plan = publication_plan()
            plan[field] = value
            cases.append(plan)
        for markers in ([], [publication_plan()['markers'][0]] * 2):
            plan = publication_plan()
            plan['markers'] = markers
            cases.append(plan)
        for plan in cases:
            with self.subTest(plan=plan):
                self.save_plan(plan)
                self.assertEqual(self.run_main('publisher')[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_scalar_policy_readback_and_parsed_document_are_accepted_exactly(self):
        self.iam.scalar_form = True
        self.assertEqual(self.run_main()[0], 0)
        self.iam.encoded_document = False
        self.assertEqual(self.run_main()[0], 0)
        self.save_plan()
        self.assertEqual(self.run_main('publisher')[0], 0)

    def test_nondefault_or_changed_version_is_rejected_before_key_creation(self):
        self.iam.version_is_default = False
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual([a for a, _ in self.iam.mutations], ['CreateUser', 'CreatePolicy'])
        self.assertFalse(self.iam.keys)

    def test_extra_permissions_are_rejected_before_key_creation(self):
        def after(action, user):
            if action == 'AttachUserPolicy':
                self.iam.groups[user].append(dict(GroupName='unexpected-admin-group'))
        self.iam.after = after
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual([a for a, _ in self.iam.mutations], ['CreateUser', 'CreatePolicy', 'AttachUserPolicy'])
        self.assertFalse(self.iam.keys)

    def test_policy_drift_after_attachment_is_rejected_before_key_creation(self):
        def after(action, user):
            if action == 'AttachUserPolicy':
                arn = self.iam.attached[user][0]
                self.iam.managed[arn]['document']['Statement'][0]['Effect'] = 'Allow'
        self.iam.after = after
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.keys)

    def test_existing_key_is_rejected_before_new_key_creation(self):
        def after(action, user):
            if action == 'AttachUserPolicy':
                self.iam.keys[user] = [dict(UserName=user, Status='Active', AccessKeyId=f.KEY + 'unexpected')]
        self.iam.after = after
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 3)

    def test_live_verification_rejects_extra_policies_groups_and_keys(self):
        self.assertEqual(self.run_main()[0], 0)
        user = c.USERS['writer']
        cases = (('inline_names', 'unreviewed'), ('groups', dict(GroupName='admin')),
                 ('attached', f'arn:aws:iam::{f.ACCOUNT}:policy/extra'),
                 ('keys', dict(UserName=user, Status='Active', AccessKeyId=f.KEY + 'extra')))
        for attribute, item in cases:
            with self.subTest(attribute=attribute):
                rows = getattr(self.iam, attribute)[user]
                rows.append(item)
                self.assertEqual(self.run_main()[0], 2)
                rows.pop()
        self.assertEqual(len(self.iam.mutations), 4)

    def test_writer_drift_prevents_publisher_creation(self):
        self.assertEqual(self.run_main()[0], 0)
        self.save_plan()
        self.iam.inline_names[c.USERS['writer']].append('unexpected')
        self.assertEqual(self.run_main('publisher')[0], 2)
        self.assertEqual(len(self.iam.mutations), 4)
        self.assertFalse((self.clone / 'publisher').exists())

    def test_unknown_key_response_is_never_replayed_or_adopted(self):
        self.iam.fail_after = 'CreateAccessKey'
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.keys[c.USERS['writer']]), 1)
        self.assertFalse((self.clone / 'writer' / 'credential.json').exists())
        self.assertFalse((self.clone / 'writer' / '03.receipt.json').exists())
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 4)
        self.assertEqual(self.run_main('status')[1]['roles']['writer']['result'], 'PENDING')

    def test_key_persistence_failure_is_never_replayed(self):
        write = c.Journal.write
        def fail(journal, name, value):
            if name == 'credential.json':
                raise OSError(f.SECRET)
            return write(journal, name, value)
        with patch.object(c.Journal, 'write', fail):
            self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 4)

    def test_unknown_user_response_is_never_replayed_or_adopted(self):
        self.iam.fail_after = 'CreateUser'
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 1)

    def test_attachment_receipt_payload_is_checked_even_with_rebuilt_chain(self):
        self.assertEqual(self.run_main()[0], 0)
        directory = self.clone / 'writer'
        receipt = json.loads((directory / '02.receipt.json').read_bytes())
        receipt['result']['policy_arn'] = f'arn:aws:iam::{f.ACCOUNT}:policy/unreviewed'
        (directory / '02.receipt.json').write_bytes(c.policies.canonical(receipt))
        intent = json.loads((directory / '03.intent.json').read_bytes())
        intent['previous_sha256'] = c.policies.digest(receipt)
        (directory / '03.intent.json').write_bytes(c.policies.canonical(intent))
        receipt = json.loads((directory / '03.receipt.json').read_bytes())
        receipt['intent_sha256'] = c.policies.digest(intent)
        (directory / '03.receipt.json').write_bytes(c.policies.canonical(receipt))
        code, result = self.run_main()
        self.assertEqual(code, 2)
        self.assertIn('attachment receipt differs', result['reason'])
        self.assertEqual(len(self.iam.mutations), 4)

    def test_malformed_receipt_schema_is_rejected(self):
        self.assertEqual(self.run_main()[0], 0)
        path = self.clone / 'writer' / '03.receipt.json'
        receipt = json.loads(path.read_bytes())
        receipt['schema'] = 999
        path.write_bytes(c.policies.canonical(receipt))
        self.assertEqual(self.run_main()[0], 2)
        self.assertEqual(len(self.iam.mutations), 4)

    def test_changed_source_account_is_rejected_without_creating_clone_journal(self):
        self.sts.value.update(Account='999999999999', Arn='arn:aws:iam::999999999999:root', UserId='999999999999')
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)
        self.assertFalse(self.clone.exists())

    def test_existing_user_is_not_adopted(self):
        user = c.USERS['writer']
        self.iam.users[user] = dict(UserName=user)
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_insufficient_quota_refuses_before_mutation(self):
        self.iam.quota = 100
        self.assertEqual(self.run_main()[0], 2)
        self.assertFalse(self.iam.mutations)

    def test_status_never_loads_credentials_or_contacts_provider(self):
        with patch.object(c.p, 'source_credentials', side_effect=AssertionError('credential access')), \
             patch.object(c.p, 'clients', side_effect=AssertionError('provider access')):
            code, result = self.run_main('status')
        self.assertEqual(code, 0)
        self.assertEqual(result['credentials'], 'NOT_ACCESSED')


class LegacyAnchorTests(unittest.TestCase):
    def test_changed_legacy_or_checkpoint_bytes_are_rejected(self):
        state = c.policies.canonical(dict(generation=13, rewrites=9, pending=None,
                                         binding=dict(limits=dict(maximum_rewrites=9))))
        checkpoint = c.policies.canonical(CHECKPOINT)
        def read(path):
            return checkpoint if path.name == '000013-step.json' else state
        with patch.object(c, 'read_path', side_effect=read), \
             patch.object(c, 'LEGACY_STATE_SHA', c.p.sha(state)), \
             patch.object(c, 'CHECKPOINT_SHA', c.p.sha(checkpoint)):
            self.assertEqual(c.anchored_checkpoint(), CHECKPOINT)
            for name in ('LEGACY_STATE_SHA', 'CHECKPOINT_SHA'):
                with self.subTest(name=name), patch.object(c, name, '0' * 64), self.assertRaises(c.p.Refusal):
                    c.anchored_checkpoint()


if __name__ == '__main__':
    unittest.main()

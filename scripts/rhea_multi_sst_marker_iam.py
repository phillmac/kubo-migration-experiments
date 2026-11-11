#!/usr/bin/env python3
"""Offline IAM documents, read-only DI acceptance, and a PURE release model.

No SDK, credential discovery, installer, signer, S3/IAM mutation, root controller,
or deployment authorization. Identity policies have no Principal element. All
injected identities/keys/evidence are OFFLINE inputs, never production anchors.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from fnmatch import fnmatchcase
import hashlib
import json
import re
from typing import Protocol

import rhea_multi_sst_signed_admission as admission

BUCKET = 'rhea-pebble-lab-20261101-39037c6f01'
PREFIX = 'rhea/pebbleds/'
BUCKET_ARN = 'arn:aws:s3:::' + BUCKET
OBJECT_ARN = BUCKET_ARN + '/' + PREFIX
PUBLICATION = ('marker.manifest', 'marker.manifest.*',
               'marker.format-version', 'marker.format-version.*', 'CURRENT')
PROTECTED = tuple(OBJECT_ARN + name for name in PUBLICATION)
HEX = re.compile(r'[0-9a-f]{64}\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_+=,.@-]{0,63}\Z')
MARKER = re.compile(r'marker\.(?:manifest\.[0-9]{6,}\.MANIFEST-[0-9]{6,}'
                    r'|format-version\.[0-9]{6,}\.[0-9]{3})\Z')
DOMAIN = 'rhea-gen14-marker-iam-v1'
PRODUCTION_TRUST_SHA256 = None  # Never provisionable through caller input/env.
SUPPORTED_CONDITION_KEYS = frozenset({'s3:prefix'})  # Only keys this builder uses.


class Refusal(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def digest(value):
    return sha(canonical(value))


def hash_value(value):
    require(type(value) is str and HEX.fullmatch(value), 'invalid SHA256')
    return value


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 256 * 1024, 'invalid canonical record')
    try:
        value = json.loads(raw)
        require(type(value) is dict and canonical(value) == raw, 'noncanonical/duplicate JSON')
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise Refusal('invalid JSON record') from exc


@dataclass(frozen=True)
class Bindings:
    """Approved names are injected ONLY into the pure offline builder."""
    account: str
    writer: str
    publisher: str

    def __post_init__(self):
        require(type(self.account) is str and re.fullmatch(r'[0-9]{12}', self.account),
                'exact 12 digit account required')
        require(all(type(n) is str and NAME.fullmatch(n) for n in (self.writer, self.publisher))
                and self.writer != self.publisher, 'distinct exact IAM usernames required')

    def arn(self, role):
        require(role in ('writer', 'publisher'), 'unknown role')
        return f'arn:aws:iam::{self.account}:user/{getattr(self, role)}'


@dataclass(frozen=True)
class Policies:
    bindings: Bindings
    keys: tuple[str, ...]
    current_change_sha256: str | None
    writer_raw: bytes
    publisher_raw: bytes

    @property
    def binding(self):
        return dict(domain=DOMAIN, bucket=BUCKET, prefix=PREFIX,
                    account=self.bindings.account, writer=self.bindings.arn('writer'),
                    publisher=self.bindings.arn('publisher'), keys=list(self.keys),
                    current_change_sha256=self.current_change_sha256,
                    writer_sha256=sha(self.writer_raw), publisher_sha256=sha(self.publisher_raw))

    @property
    def sha256(self):
        return digest(self.binding)

    def document(self, role):
        require(role in ('writer', 'publisher'), 'unknown role')
        return parse(getattr(self, role + '_raw'))


def statement(sid, effect, *, actions=None, not_actions=None, resources=None,
              not_resources=None, condition=None):
    result = dict(Sid=sid, Effect=effect)
    for key, value in (('Action', actions), ('NotAction', not_actions),
                       ('Resource', resources), ('NotResource', not_resources), ('Condition', condition)):
        if value is not None:
            result[key] = sorted(value) if type(value) in (list, tuple) else value
    return result


def build_policies(bindings: Bindings, publication_keys: tuple[str, ...], *,
                   current_change_sha256=None) -> Policies:
    """Deterministic identity policies; no caller-selectable bucket/resources.

    CURRENT may be represented offline only with the hash of a separately signed
    change artifact. This is not signature verification or deployment approval.
    The gen14 N2 release model below disallows changed CURRENT altogether.
    """
    require(type(bindings) is Bindings, 'immutable exact bindings required')
    bindings.__post_init__()
    require(type(publication_keys) is tuple and 0 < len(publication_keys) <= 16
            and all(type(k) is str for k in publication_keys)
            and len(set(publication_keys)) == len(publication_keys), 'exact unique marker tuple required')
    keys = tuple(sorted(publication_keys))
    require(all(MARKER.fullmatch(k) or k == 'CURRENT' for k in keys), 'invalid publication key')
    if 'CURRENT' in keys:
        hash_value(current_change_sha256)
    else:
        require(current_change_sha256 is None, 'unexpected CURRENT change artifact')
    writes = [OBJECT_ARN + k for k in keys]
    object_actions = ['s3:GetObject', 's3:GetObjectVersion', 's3:PutObject']
    lists = ['s3:ListBucket', 's3:ListBucketVersions']
    bucket_reads = ['s3:GetBucketVersioning', 's3:GetBucketLocation']
    documents = []
    for role in ('writer', 'publisher'):
        writer = role == 'writer'
        objects = [OBJECT_ARN + '*'] if writer else list(PROTECTED)
        actions = object_actions + (['s3:DeleteObject', 's3:AbortMultipartUpload',
                                     's3:ListMultipartUploadParts'] if writer else [])
        prefixes = [PREFIX + '*'] if writer else [PREFIX + k for k in PUBLICATION]
        # These are identity-attached policies. Wasabi's IAM support list does
        # not include aws:PrincipalArn; attachment binds the identity, not an
        # undocumented condition. Signer verification belongs in the sidecar.
        rows = [
            statement('NoLateralResources', 'Deny', actions=['s3:*'],
                      not_resources=[BUCKET_ARN, *objects]),
            statement('NoOtherAPIs', 'Deny', not_actions=[*actions, *lists, *bucket_reads,
                                                       'sts:GetCallerIdentity'], resources=['*']),
            statement('NoUnscopedListing', 'Deny', actions=lists, resources=[BUCKET_ARN],
                      condition={'StringNotLike': {'s3:prefix': prefixes}}),
            statement('NoMissingListingPrefix', 'Deny', actions=lists, resources=[BUCKET_ARN],
                      condition={'Null': {'s3:prefix': 'true'}}),
            statement('ReadBucket', 'Allow', actions=bucket_reads, resources=[BUCKET_ARN]),
            statement('ListScopedVersions', 'Allow', actions=lists, resources=[BUCKET_ARN],
                      condition={'StringLike': {'s3:prefix': prefixes}}),
        ]
        if writer:
            rows.extend([
                statement('DataOperations', 'Allow', actions=actions, resources=objects),
                statement('NeverPublishOrRemoveMarkers', 'Deny',
                          actions=['s3:PutObject', 's3:DeleteObject', 's3:DeleteObjectVersion',
                                   's3:AbortMultipartUpload'], resources=PROTECTED),
            ])
        else:
            rows.extend([
                statement('ReadMarkerVersions', 'Allow', actions=['s3:GetObject', 's3:GetObjectVersion'],
                          resources=objects),
                statement('ExactPublicationOnly', 'Allow', actions=['s3:PutObject'],
                          resources=writes),
                statement('NoOtherPublication', 'Deny', actions=['s3:PutObject'], not_resources=writes),
            ])
        require(all(key in SUPPORTED_CONDITION_KEYS for row in rows
                    for terms in row.get('Condition', {}).values() for key in terms),
                'unsupported policy condition key')
        documents.append(canonical(dict(Version='2012-10-17', Statement=rows)))
    return Policies(bindings, keys, current_change_sha256, *documents)


def validate_bundle(policies):
    require(type(policies) is Policies, 'immutable policies required')
    expected = build_policies(policies.bindings, policies.keys,
                              current_change_sha256=policies.current_change_sha256)
    require(policies == expected, 'policy bytes/hash changed')


def _matches(patterns, value):
    if type(patterns) is str:
        patterns = [patterns]
    return any(fnmatchcase(value, p) for p in patterns)


def _condition(condition, context):
    for operator, terms in condition.items():
        require(operator in ('StringEquals', 'StringNotEquals', 'StringLike', 'StringNotLike', 'Null'),
                'unsupported local condition')
        for key, expected in terms.items():
            actual = context.get(key)
            if operator == 'Null':
                result = (actual is None) == (expected == 'true')
            else:
                values = expected if type(expected) is list else [expected]
                match = actual is not None and any(
                    fnmatchcase(actual, v) if 'Like' in operator else actual == v for v in values)
                result = not match if operator.startswith('StringNot') else match
            if not result:
                return False
    return True


def simulate(document, action, resource, context, *, inherited_allow=False):
    """Bounded local evaluator for THESE generated policies, never live proof."""
    allowed = inherited_allow
    for row in document['Statement']:
        require(not (set(row) - {'Sid', 'Effect', 'Action', 'NotAction', 'Resource', 'NotResource', 'Condition'}),
                'unsupported local statement')
        applies = (_matches(row['Action'], action) if 'Action' in row
                   else not _matches(row['NotAction'], action))
        applies &= (_matches(row['Resource'], resource) if 'Resource' in row
                    else not _matches(row['NotResource'], resource))
        if applies and _condition(row.get('Condition', {}), context):
            if row['Effect'] == 'Deny':
                return 'DENY'
            allowed = True
    return 'ALLOW' if allowed else 'DENY'


# S3 operation names are NEVER invented IAM actions. Copy/MPU destination
# authorization uses PutObject, even when a request contains a source/version.
DESTINATION_ACTIONS = {
    'PutObject': 's3:PutObject', 'CopyObject': 's3:PutObject',
    'CreateMultipartUpload': 's3:PutObject', 'UploadPart': 's3:PutObject',
    'UploadPartCopy': 's3:PutObject', 'CompleteMultipartUpload': 's3:PutObject',
    'DeleteObject': 's3:DeleteObject', 'DeleteObjectVersion': 's3:DeleteObjectVersion',
}


@dataclass(frozen=True)
class Case:
    case_id: str
    role: str
    operation: str
    action: str
    resource: str
    context: tuple[tuple[str, str], ...]
    expected: str

    @property
    def sha256(self):
        return digest(vars(self))


def acceptance_cases(policies):
    validate_bundle(policies)
    cases = []

    def add(role, operation, action, resource, expected, *, prefix=None):
        context = {}
        if prefix is not None:
            context['s3:prefix'] = prefix
        cases.append(Case(f'case-{len(cases):04d}', role, operation, action, resource,
                          tuple(sorted(context.items())), expected))

    # Representatives cover bare names, both marker families, historical CURRENT,
    # and the exact proposed keys; policy syntax pins wildcard scope separately.
    names = sorted(set(policies.keys) | {'marker.manifest', 'marker.manifest.000017.MANIFEST-000123',
                   'marker.format-version', 'marker.format-version.000012.013', 'CURRENT'})
    for name in names:
        for operation, action in DESTINATION_ACTIONS.items():
            add('writer', operation, action, OBJECT_ARN + name, 'DENY')
            add('publisher', operation, action, OBJECT_ARN + name,
                'ALLOW' if action == 's3:PutObject' and name in policies.keys else 'DENY')
        for role in ('writer', 'publisher'):
            for action in ('s3:GetObject', 's3:GetObjectVersion'):
                add(role, action, action, OBJECT_ARN + name, 'ALLOW')
    for role in ('writer', 'publisher'):
        for action in ('s3:GetObject', 's3:GetObjectVersion', 's3:PutObject', 's3:DeleteObject',
                       's3:DeleteObjectVersion', 's3:AbortMultipartUpload', 's3:ListMultipartUploadParts'):
            add(role, action, action, OBJECT_ARN + '000123.sst',
                'ALLOW' if role == 'writer' and action != 's3:DeleteObjectVersion' else 'DENY')
        for resource in ('arn:aws:s3:::unrelated-bucket/rhea/pebbleds/000123.sst',
                         BUCKET_ARN + '/other-project/000123.sst', BUCKET_ARN + '/rhea/pebbleds-evil/x'):
            for action in ('s3:GetObject', 's3:PutObject', 's3:DeleteObjectVersion'):
                add(role, action, action, resource, 'DENY')
        for action in ('s3:PutBucketPolicy', 's3:DeleteBucketPolicy', 's3:PutBucketVersioning',
                       's3:PutLifecycleConfiguration', 's3:GetBucketPolicy', 's3:DeleteBucket'):
            add(role, action, action, BUCKET_ARN, 'DENY')
        for action in ('iam:CreateUser', 'iam:CreateAccessKey', 'iam:PutUserPolicy',
                       'iam:AttachUserPolicy', 'iam:CreatePolicyVersion', 'sts:AssumeRole'):
            add(role, action, action, '*', 'DENY')
        for action in ('s3:ListBucket', 's3:ListBucketVersions'):
            for prefix in (None, '', 'rhea/', 'other-project/', PREFIX, PREFIX + '000123.sst',
                           PREFIX + 'marker.manifest.', PREFIX + 'CURRENT'):
                allowed = prefix is not None and prefix.startswith(PREFIX) and (
                    role == 'writer' or any(fnmatchcase(prefix, PREFIX + p) for p in PUBLICATION))
                add(role, action, action, BUCKET_ARN, 'ALLOW' if allowed else 'DENY', prefix=prefix)
        add(role, 'GetBucketVersioning', 's3:GetBucketVersioning', BUCKET_ARN, 'ALLOW')
    return tuple(cases)


def wasabi_validate_request(policy_raw, action, resource):
    """Exact documented IAM query fields, not AWS Access Analyzer's API.

    A supplied transport signs as the tested principal, uses a bounded timeout
    and POST form encoding (required above 8000 chars). There is no documented
    arbitrary-context parameter: do not invent one or substitute conditions.
    """
    parse(policy_raw)
    require(type(action) is str and re.fullmatch(r'(?:s3|iam|sts):[A-Za-z]+', action),
            'invalid evaluator action')
    require(type(resource) is str and (resource == '*' or resource.startswith('arn:aws:')),
            'invalid evaluator resource')
    return dict(Action='ValidatePolicy', Version='2010-05-08', PolicyDocument=policy_raw.decode(),
                IsPrincipal='true', UseAction=action, UseResource=resource, UseService=action.split(':')[0])


@dataclass(frozen=True)
class WasabiValidatePolicyDI:
    """Read-only bridge from exact query requests to strict normalized decisions.

    Endpoints expose evaluate_read_only(request, expected_context=...). They are
    injected, already authenticated transports plus reviewed response decoders;
    no transport, signing key, client, or raw XML schema is invented here.
    A decoder must retain decision/request/context/signer evidence. It MUST fail
    if a condition's evaluation cannot be established (notably s3:prefix), or if
    propagation is unproven. ValidatePolicy itself does not prove propagation.
    Never send expected_context as an undocumented Wasabi query parameter.
    """
    writer: object
    publisher: object
    bindings: Bindings

    def validate_policy(self, **request):
        role = next((role for role in ('writer', 'publisher')
                     if request['PrincipalArn'] == self.bindings.arn(role)), None)
        require(role is not None, 'unbound evaluator signer')
        raw = request['PolicyDocument'].encode()
        require(sha(raw) == request['PolicySha256'], 'evaluator policy hash mismatch')
        rows = []
        for case in request['Cases']:
            require(set(case['context']) <= SUPPORTED_CONDITION_KEYS,
                    'unsupported evaluator condition context')
            query = wasabi_validate_request(raw, case['action'], case['resource'])
            result = getattr(self, role).evaluate_read_only(query, expected_context=dict(case['context']))
            require(type(result) is dict and result.get('Decision') in ('ALLOW', 'DENY')
                    and result.get('RequestSha256') == digest(query)
                    and result.get('PrincipalArn') == request['PrincipalArn']
                    and result.get('EvaluatedContext') == case['context']
                    and result.get('Propagation') == 'CONFIRMED'
                    and result.get('Source') == 'WASABI_VALIDATE_POLICY',
                    'unknown/omitted decision, context, signer, or independent propagation evidence')
            rows.append(dict(case_id=case['case_id'], request_sha256=case['request_sha256'],
                             decision=result['Decision']))
        return dict(Status='COMPLETE', Semantics='SUPPLIED_IDENTITY_POLICY_DECISIONS',
                    Propagation='CONFIRMED', PolicySha256=request['PolicySha256'],
                    PrincipalArn=request['PrincipalArn'], Decisions=rows)


class ReadOnlyIAM(Protocol):
    """Adapter contract, NOT a claim about Wasabi's raw wire response schema.

    validate_policy normalizes per-request decisions from a documented, reviewed
    ValidatePolicy-style evaluator. Syntax-only success is UNSUPPORTED. It must
    establish actual signer and condition context. Inherited-policy precedence
    is tested separately by the bounded simulator; this is a supplied-policy API.
    No fallback to the local simulator. No adapter/client is created here.
    """
    def validate_policy(self, **request) -> dict: ...


class ReadOnlySTS(Protocol):
    def get_caller_identity(self) -> dict: ...


class ReadOnlyS3(Protocol):
    def get_bucket_versioning(self, **request) -> dict: ...


@dataclass(frozen=True)
class EvaluationReport:
    status: str
    policy_sha256: str
    cases_sha256: str
    decisions: int
    evidence_raw: bytes
    reason: str
    actual_enforcement_proven: bool = False
    deployment_authorized: bool = False


def validate_read_only(policies, *, writer_sts, publisher_sts, iam, s3):
    """One attempt per read; fail closed on errors/unknown/omitted/uncertain.

    Success means POLICY_EVALUATOR_SIMULATED, never pre-open enforcement. Uses
    exact expected-owner conditional S3 parameters; no list/write/probe requests.
    The adapter must enforce a bounded timeout. No retry occurs in this module.
    """
    evidence, cases = [], ()
    try:
        validate_bundle(policies)
        cases = acceptance_cases(policies)
        for role, sts in (('writer', writer_sts), ('publisher', publisher_sts)):
            identity = sts.get_caller_identity()
            require(type(identity) is dict and identity.get('Account') == policies.bindings.account
                    and identity.get('Arn') == policies.bindings.arn(role)
                    and type(identity.get('UserId')) is str and identity['UserId'], 'STS identity mismatch')
            evidence.append(dict(kind='GetCallerIdentity', role=role, identity=identity))
        params = dict(Bucket=BUCKET, ExpectedBucketOwner=policies.bindings.account)
        before = s3.get_bucket_versioning(**params)
        require(type(before) is dict and before.get('Status') == 'Enabled', 'versioning not Enabled')
        evidence.append(dict(kind='GetBucketVersioningBefore', parameters=params, response=before))
        for role in ('writer', 'publisher'):
            selected = tuple(c for c in cases if c.role == role)
            requests = [dict(case_id=c.case_id, request_sha256=c.sha256, operation=c.operation,
                             action=c.action, resource=c.resource, context=dict(c.context)) for c in selected]
            request = dict(PolicyDocument=getattr(policies, role + '_raw').decode(),
                           PolicySha256=sha(getattr(policies, role + '_raw')),
                           PrincipalArn=policies.bindings.arn(role), Cases=requests)
            response = iam.validate_policy(**request)
            require(type(response) is dict and response.get('Status') == 'COMPLETE'
                    and response.get('Semantics') == 'SUPPLIED_IDENTITY_POLICY_DECISIONS'
                    and response.get('Propagation') == 'CONFIRMED'
                    and response.get('PolicySha256') == request['PolicySha256']
                    and response.get('PrincipalArn') == request['PrincipalArn'],
                    'IAM unsupported, ambiguous, stale policy, or propagation uncertain')
            rows = response.get('Decisions')
            require(type(rows) is list and len(rows) == len(selected), 'omitted IAM decisions')
            indexed = {}
            for row in rows:
                require(type(row) is dict and set(row) == {'case_id', 'request_sha256', 'decision'}
                        and type(row['case_id']) is str and row['case_id'] not in indexed,
                        'duplicate/malformed IAM decision')
                indexed[row['case_id']] = row
            for case in selected:
                row = indexed.get(case.case_id)
                require(row is not None and row['request_sha256'] == case.sha256
                        and row['decision'] == case.expected, 'unexpected IAM decision')
            evidence.append(response)
        after = s3.get_bucket_versioning(**params)
        require(type(after) is dict and after.get('Status') == 'Enabled'
                and after.get('MFADelete') == before.get('MFADelete'),
                'versioning changed during evaluation')
        evidence.append(dict(kind='GetBucketVersioningAfter', parameters=params, response=after))
        return EvaluationReport('POLICY_EVALUATOR_SIMULATED', policies.sha256,
                                digest([vars(c) for c in cases]), len(cases), canonical(evidence), '')
    except Exception as exc:
        # Do not leak adapter exception bodies (possibly request headers/tokens).
        reason = str(exc) if type(exc) is Refusal else type(exc).__name__
        return EvaluationReport('REFUSED', policies.sha256 if type(policies) is Policies else '',
                                digest([vars(c) for c in cases]), 0, canonical(evidence), reason)


@dataclass(frozen=True)
class SignedRecord:
    raw: bytes
    signature: bytes


@dataclass(frozen=True)
class OfflineTrust:
    """Independent OFFLINE verifier pins; these cannot enable any live API.

    No signer/key generation exists. Real use needs separately installed fixed
    names, policy hashes, public verification anchors and durable anti-replay.
    """
    authorization_public: bytes
    authorization_sha256: str
    witness_public: bytes
    witness_sha256: str

    def verify(self, record, *, witness=False):
        require(type(record) is SignedRecord and type(record.signature) is bytes
                and len(record.signature) == 64, 'detached signature required')
        public = self.witness_public if witness else self.authorization_public
        pin = self.witness_sha256 if witness else self.authorization_sha256
        hash_value(pin)
        require(type(public) is bytes and sha(public) == pin
                and self.authorization_sha256 != self.witness_sha256,
                'independent immutable verification pins required')
        try:
            admission.verify_detached(record.raw, record.signature, public, key_sha256=pin,
                                      domain=admission.DEPLOYMENT_DOMAIN)
        except admission.Refusal as exc:
            raise Refusal('external signature rejected') from exc
        return parse(record.raw)


def _integer(value):
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class ReleaseModel:
    """PURE evidence transitions, NOT a controller or durable replay ledger.

    All receipts are independently witness-signed and bound to one policy,
    batch, epoch and timeline. Caller-fabricated instances grant no capability.
    Writer denial is never removed. Publisher release is modeled once only.
    """
    policies: Policies
    trust: OfflineTrust
    authorization: SignedRecord
    epoch: str
    batch_sha256: str
    phase: str
    last_time: int
    expires: int
    used_epochs: tuple[str, ...]
    proof_ids: tuple[str, ...]
    chain_sha256: str
    publication_raw: bytes = b''

    @classmethod
    def start(cls, policies, trust, authorization, preopen, *, used_epochs=(), now):
        validate_bundle(policies)
        require(type(trust) is OfflineTrust and type(used_epochs) is tuple
                and all(type(e) is str for e in used_epochs), 'immutable offline trust/epoch ledger required')
        claims = trust.verify(authorization)
        require(set(claims) == {'domain', 'kind', 'policy', 'epoch', 'batch_sha256', 'issued', 'expires',
                                'generation', 'cap', 'pending', 'current_sha256', 'maximum_units'},
                'authorization schema mismatch')
        require(claims['domain'] == DOMAIN and claims['kind'] == 'external-authorization'
                and claims['policy'] == policies.binding and claims['generation'] == 13
                and type(claims['generation']) is int and claims['cap'] == 9 and type(claims['cap']) is int
                and claims['pending'] is None and claims['maximum_units'] == 2
                and type(claims['maximum_units']) is int
                and claims['current_sha256'] == sha(b'MANIFEST-000000\n')
                and 'CURRENT' not in policies.keys, 'wrong policy or N2/gen13 anchor')
        hash_value(claims['batch_sha256'])
        hash_value(claims['epoch'])
        require(claims['epoch'] not in used_epochs, 'reused epoch')
        require(all(_integer(v) for v in (now, claims['issued'], claims['expires']))
                and claims['issued'] <= now < claims['expires'] <= claims['issued'] + 900,
                'expired/future authorization')
        model = cls(policies, trust, authorization, claims['epoch'], claims['batch_sha256'],
                    'AUTHORIZED', claims['issued'], claims['expires'], (*used_epochs, claims['epoch']),
                    (), sha(authorization.raw))
        return model._accept(preopen, 'preopen-denial', 'PREOPEN_DENIED', now=now)

    def _accept(self, record, kind, phase, *, now):
        validate_bundle(self.policies)
        # Reverify authorization, not a mutable caller-supplied policy hash.
        auth = self.trust.verify(self.authorization)
        require(auth['policy'] == self.policies.binding and auth['epoch'] == self.epoch
                and auth['batch_sha256'] == self.batch_sha256, 'authorization binding changed')
        receipt = self.trust.verify(record, witness=True)
        require(set(receipt) == {'domain', 'kind', 'epoch', 'policy_sha256', 'batch_sha256',
                                'proof_id', 'observed', 'previous_sha256', 'details'}, 'receipt schema mismatch')
        require(receipt['domain'] == DOMAIN and receipt['kind'] == kind and receipt['epoch'] == self.epoch
                and receipt['policy_sha256'] == self.policies.sha256
                and receipt['batch_sha256'] == self.batch_sha256
                and receipt['previous_sha256'] == self.chain_sha256, 'receipt binding/chain mismatch')
        proof = hash_value(receipt['proof_id'])
        require(proof not in self.proof_ids, 'reused proof ID')
        require(all(_integer(v) for v in (now, receipt['observed']))
                and self.last_time < receipt['observed'] <= now < self.expires,
                'out-of-order/expired receipt')
        d = receipt['details']
        require(type(d) is dict, 'receipt details missing')
        if kind == 'preopen-denial':
            require(set(d) == {'writer_opened', 'writer_marker_decision', 'publisher_released',
                              'propagation', 'enforcement', 'cases_sha256', 'versioning', 'bucket', 'prefix'}
                    and type(d['writer_opened']) is type(d['publisher_released']) is bool
                    and d == dict(writer_opened=False, writer_marker_decision='DENY', publisher_released=False,
                                  propagation='CONFIRMED', enforcement='ACTUAL_ENFORCEMENT_PROVEN',
                                  cases_sha256=digest([vars(c) for c in acceptance_cases(self.policies)]),
                                  versioning='Enabled', bucket=BUCKET, prefix=PREFIX),
                    'PRE-OPEN actual denial/independent propagation proof missing')
        elif kind == 'first-four-worker-proof':
            require(set(d) == {'workers', 'complete', 'version_history', 'writer_closed',
                              'rc_markers_validated', 'dirty_markers', 'queued_markers', 'uploading_markers',
                              'writer_mount_stopped', 'cache_disposition_sha256', 's3_proof_sha256',
                              'rc_proof_sha256', 'publication_sha256'}
                    and type(d['workers']) is int and d['workers'] == 4
                    and all(d[k] is True for k in ('complete', 'version_history', 'writer_closed',
                                                   'rc_markers_validated', 'writer_mount_stopped'))
                    and all(type(d[k]) is int and d[k] == 0 for k in
                            ('dirty_markers', 'queued_markers', 'uploading_markers')),
                    'four-worker proof/RC validation/safe dirty cache disposition missing')
            for key in ('cache_disposition_sha256', 's3_proof_sha256', 'rc_proof_sha256', 'publication_sha256'):
                hash_value(d[key])
        elif kind == 'publisher-propagation':
            require(d == dict(status='CONFIRMED', enforcement='ACTUAL_ENFORCEMENT_PROVEN',
                              writer_marker_decision='DENY', publisher_exact_keys='ALLOW',
                              publisher_other_keys='DENY', intent_sha256=self.chain_sha256),
                    'unknown IAM transition or independent publisher propagation proof missing')
        elif kind == 'release-result':
            require(set(d) == {'status', 'version_receipts_sha256', 'publication_sha256'}
                    and d['status'] == 'CONFIRMED'
                    and d['publication_sha256'] == sha(self.publication_raw),
                    'unknown/failed release; preserve evidence, no retry')
            hash_value(d['version_receipts_sha256'])
        else:
            raise Refusal('unknown receipt kind')
        return replace(self, phase=phase, last_time=receipt['observed'],
                       proof_ids=(*self.proof_ids, proof), chain_sha256=sha(record.raw))

    def first_proof(self, record, *, now):
        require(self.phase == 'PREOPEN_DENIED', 'first proof requires pre-open denial')
        result = self._accept(record, 'first-four-worker-proof', 'DATA_PROVEN_CACHE_SAFE', now=now)
        return replace(result, publication_raw=canonical(parse(record.raw)['details']['publication_sha256']))

    def release_intent(self, publication, *, now):
        """One-shot PURE pending intent. No API call, retry, or policy removal.

        publication is exact conditional per-key PUT intent with bytes hashes;
        its digest must already be in the independent first-proof receipt.
        """
        require(self.phase == 'DATA_PROVEN_CACHE_SAFE' and _integer(now)
                and self.last_time < now < self.expires, 'release before proof or duplicate intent')
        require(type(publication) is tuple and len(publication) == len(self.policies.keys),
                'immutable exact conditional publication required')
        rows = []
        for item in publication:
            require(type(item) is tuple and len(item) == 5, 'invalid publication row')
            key, content_sha256, size, condition, value = item
            require(key in self.policies.keys and _integer(size)
                    and ((condition == 'IfNoneMatch' and value == '*')
                         or (condition == 'IfMatch' and type(value) is str
                             and re.fullmatch(r'"[0-9a-f]{32}(?:-[1-9][0-9]*)?"', value))),
                    'missing exact conditional PUT parameters')
            hash_value(content_sha256)
            rows.append(dict(Bucket=BUCKET, ExpectedBucketOwner=self.policies.bindings.account,
                             Key=PREFIX + key, SHA256=content_sha256, Size=size, **{condition: value}))
        require(sorted(item[0] for item in publication) == list(self.policies.keys), 'duplicate/missing key')
        raw = canonical({'puts': sorted(rows, key=lambda x: x['Key'])})
        require(json.loads(self.publication_raw) == sha(raw), 'publication differs from first proof')
        intent = dict(domain=DOMAIN, kind='pending-marker-release-intent', epoch=self.epoch,
                      policy_sha256=self.policies.sha256, batch_sha256=self.batch_sha256,
                      previous_sha256=self.chain_sha256, publication_sha256=sha(raw), issued=now)
        return replace(self, phase='PENDING_RELEASE', last_time=now,
                       chain_sha256=digest(intent), publication_raw=raw)

    def propagation(self, record, *, now):
        require(self.phase == 'PENDING_RELEASE', 'separate pending release intent required')
        return self._accept(record, 'publisher-propagation', 'RELEASE_READY', now=now)

    def release_once(self, *, now):
        require(self.phase == 'RELEASE_READY' and _integer(now)
                and self.last_time < now < self.expires, 'release requires fresh independent propagation')
        return replace(self, phase='RELEASE_ATTEMPTED', last_time=now)

    def result(self, record, *, now):
        require(self.phase == 'RELEASE_ATTEMPTED', 'one-shot release attempt missing')
        return self._accept(record, 'release-result', 'RELEASE_RECORDED', now=now)


def status():
    return dict(status='OFFLINE_ONLY', live_mutation=False, deployment_authorized=False,
                actual_enforcement_proven=False, production_trust_provisioned=False)


def main():
    print(json.dumps(status(), sort_keys=True))
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

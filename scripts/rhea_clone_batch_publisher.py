"""Move this runner's dedicated publisher between exact, independently verified manifest names."""
import json
from urllib.parse import unquote

import rhea_gen14_clone_credentials as iam
import rhea_gen14_checkpoint_prepare as prep

host, c, require = prep.host, prep.c, prep.require
USER = 'rhea-clone-batch-publisher-20261127'
POLICY = USER+'-policy'


class Journal(iam.Journal):
    def __init__(self, root):
        self.path = root/'publisher'


def binding(account, plan):
    policies = iam.policies
    marker = plan['marker']
    require(prep.proof.markers.MANIFEST.fullmatch(marker) and plan['bucket']==iam.BUCKET
            and plan['prefix']==iam.PREFIX and plan['generation']>=15, 'wrong publisher target')
    doc = policies.build_policies(policies.Bindings(account,iam.USERS['writer'],USER),(marker,)).document('publisher')
    return dict(schema=1,domain='rhea-checkpoint-exact-publisher-v1',role='publisher',account=account,user=USER,
                bucket=iam.BUCKET,prefix=iam.PREFIX,endpoint=iam.p.S3_ENDPOINT,region='ca-central-1',
                previous_checkpoint_sha256=plan['previous_checkpoint_sha256'],policy_name=POLICY,
                policy_arn=f'arn:aws:iam::{account}:policy/{POLICY}',policy_document=doc,
                policy_sha256=policies.digest(doc),publication_keys=[marker],publication_plan_sha256=c.digest(plan))


def check_principal(api, journal, origin):
    result=iam.p.user_result(api.get_user(UserName=USER),USER,origin['account'])
    require(result==journal.read('00.receipt.json')['result'],'publisher principal changed')
    attached=iam.managed.listing(api,'list_attached_user_policies','AttachedPolicies',USER)
    require(attached==[dict(PolicyName=POLICY,PolicyArn=origin['policy_arn'])]
            and not iam.managed.listing(api,'list_user_policies','PolicyNames',USER)
            and not iam.managed.listing(api,'list_groups_for_user','Groups',USER),'publisher authorities differ')
    raw=journal.raw('credential.json')
    credential=iam.policies.parse(raw)
    keys=iam.p.key_metadata(api,USER)
    require(credential['binding_sha256']==c.digest(origin) and credential['account']==origin['account']
            and credential['user']==USER and credential['role']=='publisher' and len(keys)==1
            and keys[0]['AccessKeyId']==credential['AccessKeyId']
            and journal.read('03.receipt.json')['result']['credential_sha256']==c.raw_sha(raw),
            'publisher credential identity differs')
    return credential


def default_policy(api, bound, journal):
    policy=api.get_policy(PolicyArn=bound['policy_arn'])['Policy']
    require(policy['Arn']==bound['policy_arn'] and policy['PolicyName']==POLICY and policy['Path']=='/'
            and c.raw_sha(policy['PolicyId'].encode())==journal.read('01.receipt.json')['result']['policy_id_sha256']
            and policy['AttachmentCount']==1, 'publisher policy identity differs')
    result=api.get_policy_version(PolicyArn=bound['policy_arn'],VersionId=policy['DefaultVersionId'])['PolicyVersion']
    require(result['IsDefaultVersion'] is True and result['VersionId']==policy['DefaultVersionId'], 'default version differs')
    doc=result['Document']
    if isinstance(doc,str):
        doc=json.loads(unquote(doc))
    return result['VersionId'],iam.policies.digest(iam.managed.normalize_policy(doc))


def credentials(root, state, plan):
    """A recorded transition reconciles by exact policy hash after an interrupted IAM response."""
    api,sts=iam.p.clients(*iam.p.source_credentials())
    try:
        account=iam.p.identity(sts)['account']
        bound=binding(account,plan)
        with Journal(root) as journal:
            if not journal.exists('result.json'):
                require(plan['generation']==15,'publisher origin missing')
                iam.provision(api,journal,bound)
            origin=journal.read('binding.json')
            require(origin==binding(account,host.read(root/'000015/publisher-plan.json')), 'publisher origin differs')
            credential=check_principal(api,journal,origin)
            version,actual=default_policy(api,bound,journal)
            if plan['generation']==15:
                require(bound==origin and actual==bound['policy_sha256'], 'initial publisher policy differs')
            else:
                prior_state=root/f"{plan['generation']-1:06d}"
                previous=host.read(prior_state/'publisher-version.json')
                transition=dict(from_version=previous['version'],from_sha256=previous['sha256'],
                                to_sha256=bound['policy_sha256'],plan_sha256=c.digest(plan))
                if not (state/'publisher-transition.json').exists():
                    require((version,actual)==(previous['version'],previous['sha256']), 'unexpected prior publisher authority')
                    host.put(state/'publisher-transition.json',transition)
                require(host.read(state/'publisher-transition.json')==transition, 'pending policy transition differs')
                if actual!=bound['policy_sha256']:
                    require((version,actual)==(previous['version'],previous['sha256']), 'unrecognized publisher policy')
                    rows=api.list_policy_versions(PolicyArn=bound['policy_arn'])
                    require(not rows.get('IsTruncated') and all(r['IsDefaultVersion']==(r['VersionId']==version)
                            for r in rows['Versions']), 'ambiguous publisher versions')
                    if len(rows['Versions'])>=5:
                        # Only an archived, non-default version of this dedicated policy can be retired.
                        retired=min((r for r in rows['Versions'] if not r['IsDefaultVersion']),
                                    key=lambda r:r['CreateDate'])
                        rid=retired['VersionId']
                        old=host.read(journal.path/('issued-'+rid+'.json'))
                        require(old['version']==rid and old['policy_arn']==bound['policy_arn'], 'unowned old policy version')
                        got=api.get_policy_version(PolicyArn=bound['policy_arn'],VersionId=rid)['PolicyVersion']
                        doc=got['Document']
                        if isinstance(doc,str):
                            doc=json.loads(unquote(doc))
                        require(not got['IsDefaultVersion'] and got['VersionId']==rid and
                                iam.policies.digest(iam.managed.normalize_policy(doc))==old['sha256'],
                                'archived publisher version differs')
                        prep.save(state/'publisher-retired-version.json',old)
                        api.delete_policy_version(PolicyArn=bound['policy_arn'],VersionId=rid)
                    api.create_policy_version(PolicyArn=bound['policy_arn'],
                        PolicyDocument=json.dumps(bound['policy_document'],separators=(',',':')),SetAsDefault=True)
            version,actual=default_policy(api,bound,journal)
            require(actual==bound['policy_sha256'],'exact new publication policy not effective')
            record=dict(version=version,sha256=actual,policy_arn=bound['policy_arn'],marker=plan['marker'],
                        generation=plan['generation'])
            prep.save(journal.path/('issued-'+version+'.json'), record)
            prep.save(state/'publisher-version.json', record)
            return credential,account
    finally:
        api.close()
        sts.close()

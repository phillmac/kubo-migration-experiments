import contextlib
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'scripts'))
import rhea_clone_batch_runner as runner
import run_rhea_clone_batch as launcher

bulk,host,c=runner.bulk,runner.host,runner.c


class RetainedSuccessors(unittest.TestCase):
    def setUp(self):
        self.fmt='marker.format-version.000012.013'
        self.old='marker.manifest.000016.MANIFEST-47475342'
        self.active='marker.manifest.000017.MANIFEST-47475346'
        self.new='marker.manifest.000018.MANIFEST-47475352'
        self.pin=lambda v:dict(version_id=v,etag='"empty"',size=0,sha256=bulk.markers.EMPTY_SHA)
        self.rows=[bulk.markers.latest_row(name,self.pin(str(i))) for i,name in enumerate((self.fmt,self.old,self.active))]
        self.cert=dict(remote_metadata={self.fmt:self.pin('0'),self.active:self.pin('2')},
                       retained_remote_metadata={self.old:self.pin('1')},manifest_marker=self.active,format_marker=self.fmt,
                       manifest_view=dict(active=self.active,retained=[self.old],format=self.fmt),
                       marker_history_sha256=c.digest(self.rows))

    def test_preserves_multiple_retained_markers_and_rejects_replacement(self):
        self.assertEqual(bulk.marker_view(self.cert,self.rows,self.rows,self.new),self.cert['manifest_view'])
        added=bulk.markers.latest_row(self.new,self.pin('3'))
        fresh=[*self.rows,added]
        self.assertEqual(bulk.marker_view(self.cert,self.rows,fresh,self.new,self.pin('3'))['retained'],[self.old,self.active])
        for changed in (fresh[1:], [dict(self.rows[0],version_id='other'),*fresh[1:]]):
            with self.assertRaises(RuntimeError):
                bulk.marker_view(self.cert,self.rows,changed,self.new,self.pin('3'))
        with self.assertRaises(RuntimeError):
            bulk.marker_view(self.cert,self.rows,self.rows,self.old)

    def test_large_retained_set_does_not_consume_the_active_manifest_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            active={'CURRENT':b'MANIFEST-000000\n'}
            pins={n:dict(size=len(b),sha256=c.raw_sha(b)) for n,b in active.items()}
            retained={f'OPTIONS-{n:06d}':self.pin(str(n)) for n in range(80)}
            cert=dict(remote_metadata=pins,retained_remote_metadata=retained)
            for n in retained:
                (folder/n).touch()
            (folder/'CURRENT').write_bytes(active['CURRENT'])
            self.assertEqual(bulk.logical_metadata(folder,cert),active)
            (folder/'OPTIONS-000050').unlink()
            with self.assertRaises(RuntimeError):
                bulk.logical_metadata(folder,cert)


class JournalTests(unittest.TestCase):
    def test_generation14_anchor_and_head_compare_and_swap(self):
        first=REPO/'docs/evidence/rhea-batch2-000014-certificate-20261127.json'
        with tempfile.TemporaryDirectory() as tmp, patch.object(runner,'ROOT',Path(tmp)), \
                patch.object(runner,'ANCHOR_FILE',first),patch.object(host,'read',lambda p:c.parse(p.read_bytes())):
            parent,cert=runner.read_head()
            self.assertEqual(parent['sha256'],bulk.ANCHOR)
            successor=dict(cert,schema=bulk.SCHEMA,scope=bulk.SCOPE,generation=15,batch_checkpoint_count=2,
                           physical_rewrite_total=18,anchor_checkpoint_sha256=bulk.ANCHOR,
                           previous_checkpoint_sha256=bulk.ANCHOR,limits=bulk.LIMITS,
                           sst_lineage=dict(cert['sst_lineage'],rewrite_operations=18))
            row=dict(generation=15,sha256=c.digest(successor),previous_checkpoint_sha256=bulk.ANCHOR,certified_rewrites=18)
            state=Path(tmp)/'000015';state.mkdir()
            (state/'checkpoint.json').write_bytes(c.canonical(successor))
            (state/'completed.json').write_bytes(c.canonical(row))
            with self.assertRaises(RuntimeError):
                runner.commit_head(dict(parent,sha256='0'*64),row)
            self.assertFalse((Path(tmp)/'HEAD.json').exists())
            runner.commit_head(parent,row)
            runner.commit_head(parent,row)
            self.assertEqual(runner.read_head(),(row,successor))
            (state/'checkpoint.json').write_bytes(c.canonical(dict(successor,marked_after=0)))
            with self.assertRaises(RuntimeError):
                runner.read_head()

    def test_first_successor_signer_is_bound_to_exact_plan_and_byte_limits(self):
        head=dict(generation=14,sha256=bulk.ANCHOR)
        plan=json.loads((REPO/'docs/evidence/rhea-gen14-live-checkpoint-20261127.json').read_bytes())['next_read_only_picker']
        binding=dict(scope=bulk.SCOPE,target=launcher.TARGET,anchor_sha256=bulk.ANCHOR,generation=15,
                     previous_checkpoint_sha256=bulk.ANCHOR,release_sha256='r',worker_sha256='w',limits=bulk.LIMITS,
                     request=dict(maximum_units=8,before=dict(format='013',marked=93684),initial_plan_sha256=plan['plan_sha256']),
                     first_inputs=plan['inputs'],production=dict(queue=0,uploadsInProgress=0,erroredFiles=0))
        launcher.validate(binding,head,15,'r','w')
        for bad in (dict(binding,limits=dict(bulk.LIMITS,input_bytes=2**40)),dict(binding,previous_checkpoint_sha256='bad'),
                    dict(binding,request=dict(binding['request'],initial_plan_sha256='other'))):
            with self.assertRaises(RuntimeError):
                launcher.validate(bad,head,15,'r','w')


class PublisherTests(unittest.TestCase):
    def test_next_policy_is_exact_and_resume_reuses_the_same_version(self):
        mod=runner.publisher
        account='123456789012'
        plans={g:dict(marker=f'marker.manifest.{g+2:06d}.MANIFEST-{47475350+g}',
                      generation=g,previous_checkpoint_sha256=str(g)*32,bucket=runner.iam.BUCKET,
                      prefix=runner.iam.PREFIX) for g in (15,16)}
        a,b=[mod.binding(account,plans[g]) for g in (15,16)]
        self.assertNotEqual(a['policy_sha256'],b['policy_sha256'])
        exact=next(row for row in b['policy_document']['Statement'] if row['Sid']=='ExactPublicationOnly')
        self.assertEqual(exact['Resource'],[runner.iam.policies.OBJECT_ARN+plans[16]['marker']])
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            prev=root/'000015'; prev.mkdir()
            state=root/'000016'; state.mkdir()
            journal=Mock(path=root/'publisher');journal.path.mkdir()
            journal.exists.return_value=True
            journal.read.return_value=a
            api,sts=Mock(),Mock()
            api.list_policy_versions.return_value={'Versions':[{'VersionId':'v1','IsDefaultVersion':True}]}
            default=['v1',a['policy_sha256']]
            def promote(**kwargs):
                self.assertEqual(json.loads(kwargs['PolicyDocument']),b['policy_document'])
                self.assertTrue(kwargs['SetAsDefault'])
                default[:]=['v2',b['policy_sha256']]
            api.create_policy_version.side_effect=promote
            def save(path,value):
                if path.exists():
                    self.assertEqual(c.parse(path.read_bytes()),value)
                else:
                    path.write_bytes(c.canonical(value))
            save(prev/'publisher-version.json',dict(version='v1',sha256=a['policy_sha256']))
            save(prev/'publisher-plan.json',plans[15])
            with patch.object(mod,'Journal',side_effect=lambda _:contextlib.nullcontext(journal)), \
                 patch.object(mod.iam.p,'clients',return_value=(api,sts)),patch.object(mod.iam.p,'source_credentials',return_value=('a','b')), \
                 patch.object(mod.iam.p,'identity',return_value=dict(account=account)),patch.object(mod,'check_principal',return_value={}), \
                 patch.object(mod,'default_policy',side_effect=lambda *args:tuple(default)), \
                 patch.object(mod.prep,'save',save),patch.object(host,'put',save),patch.object(host,'read',lambda p:c.parse(p.read_bytes())):
                self.assertEqual(mod.credentials(root,state,plans[16]),({},account))
                self.assertEqual(mod.credentials(root,state,plans[16]),({},account))
            api.create_policy_version.assert_called_once()
            api.delete_policy_version.assert_not_called()

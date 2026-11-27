import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import rhea_gen14_live_checkpoint as live

p = live.proof
c = live.c


class BaselineTests(unittest.TestCase):
    def test_only_the_exact_added_keys_may_vary(self):
        row = dict(VersionId='v1', ETag='"first"', Size=42)
        latest = {'original':row}
        deleted = {'retired':dict(VersionId='t1')}
        expected = p.baseline_digest(latest,deleted,set())
        added = dict(latest,new=dict(row,VersionId='v2'))
        self.assertEqual(p.baseline_digest(added,deleted,{'new'}),expected)
        for changed,tombs in ((dict(added,original=dict(row,VersionId='v3')),deleted),
                              (dict(added,other=row),deleted),(added,{})):
            self.assertNotEqual(p.baseline_digest(changed,tombs,{'new'}),expected)
        with self.assertRaises(RuntimeError):
            p.baseline_digest(latest,deleted,{'new'})

    def test_future_writer_sees_only_certified_logical_metadata(self):
        def pin(b):
            return dict(size=len(b),sha256=c.raw_sha(b))
        old='marker.manifest.000016.MANIFEST-47475342'
        new='marker.manifest.000017.MANIFEST-47475351'
        cert=dict(remote_metadata={new:pin(b''),'CURRENT':pin(b'old\n')},
                  retained_remote_metadata={old:pin(b'')},manifest_marker=new,
                  manifest_view=dict(active=new,retained=[old]))
        raw={old:b'',new:b'','CURRENT':b'old\n'}
        self.assertEqual(p.writer_metadata(cert,raw),{new:b'','CURRENT':b'old\n'})
        for invalid in ({**raw,'unbound':b''},{**raw,old:b'replaced'},{new:b'','CURRENT':b'old\n'}):
            with self.assertRaises(RuntimeError):
                p.writer_metadata(cert,invalid)


class VersionedStore:
    def __init__(self):
        self.versions = []
        self.puts = 0
    def list_object_versions(self,**args):
        return dict(Versions=self.versions)
    def put_object(self,**args):
        assert args['IfNoneMatch']=='*' and args['Body'].read()==b'table'
        self.puts+=1
        self.versions.append(dict(Key=args['Key'],VersionId='v1',ETag='"etag"',IsLatest=True,Size=5))
        return dict(VersionId='v1',ResponseMetadata=dict(HTTPStatusCode=200))


class ExactPutTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.source=self.folder/'000123.sst'
        self.source.write_bytes(b'table')
        self.expected=dict(size=5,sha256=hashlib.sha256(b'table').hexdigest())
        self.s3=VersionedStore()

    def send(self):
        with patch.object(live,'STATE',self.folder),patch.object(live.host,'read',lambda f:c.parse(f.read_bytes())), \
             patch.object(live.host,'put',lambda f,o:f.write_bytes(c.canonical(o))), \
             patch.object(p.p,'_hash_new_sst',lambda admin,name,row,e:dict(e,version_id=row['VersionId'],etag=row['ETag'])):
            return live.conditional_upload(self.s3,self.s3,'owner','writer',self.source,self.expected)

    def test_recovery_reads_the_exact_version_without_another_put(self):
        first=self.send()
        (self.folder/'put-000123.sst.receipt.json').unlink()
        self.assertEqual(self.send(),first)
        self.assertEqual(self.s3.puts,1)
        self.s3.versions.append(dict(self.s3.versions[0],VersionId='v2'))
        with self.assertRaises(RuntimeError):
            self.send()
        self.assertEqual(self.s3.puts,1)

    def test_existing_key_and_ambiguous_empty_intent_both_stop(self):
        self.s3.versions.append(dict(Key=live.iam.PREFIX+self.source.name,VersionId='v0',IsLatest=True))
        with self.assertRaises(RuntimeError):
            self.send()
        self.assertFalse((self.folder/'put-000123.sst.intent.json').exists())
        self.s3.versions.clear()
        (self.folder/'put-000123.sst.intent.json').write_bytes(c.canonical(dict(role='writer',
            bucket=live.iam.BUCKET,name=self.source.name,**self.expected)))
        with self.assertRaises(RuntimeError):
            self.send()
        self.assertEqual(self.s3.puts,0)

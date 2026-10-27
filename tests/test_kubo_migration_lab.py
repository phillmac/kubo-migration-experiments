import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'kubo_migration_lab.py'
spec = importlib.util.spec_from_file_location('kubo_lab', str(SCRIPT))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.lab = Path(self.tmp.name)
        self.repo = self.lab / 'seed'
        self.repo.mkdir()
    def config(self, spec):
        (self.repo / 'config').write_text(json.dumps({'Datastore': {'Spec': spec}}))
    def test_loopback_only(self):
        m.require_isolation('header\nheader\n lo: 0 0 0\n')
    def test_host_network_refused(self):
        with self.assertRaises(m.Refusal):
            m.require_isolation('header\nheader\n lo: 0\n eth0: 0\n')
    def test_missing_network_evidence_refused(self):
        with self.assertRaises(m.Refusal): m.require_isolation('')
    def test_regular_binary_digest(self):
        p = self.lab / 'bin'; p.write_bytes(b'fixture'); p.chmod(0o700)
        self.assertEqual(m.verify_binary(p, hashlib.sha256(b'fixture').hexdigest()), p)
    def test_wrong_digest_refused(self):
        p = self.lab / 'bin'; p.write_bytes(b'fixture'); p.chmod(0o700)
        with self.assertRaises(m.Refusal): m.verify_binary(p, '0'*64)
    def test_symlink_binary_refused(self):
        p = self.lab / 'bin'; p.symlink_to('/bin/true')
        with self.assertRaises(m.Refusal): m.verify_binary(p, '0'*64)
    def test_local_pebble_allowed(self):
        self.config({'type':'pebbleds','path':'pebbleds'})
        m.guard_repo(self.lab, self.repo)
    def test_absolute_datastore_refused(self):
        self.config({'type':'pebbleds','path':'/outside/existing-repo'})
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab, self.repo)
    def test_parent_datastore_refused(self):
        self.config({'type':'measure','child':{'type':'pebbleds','path':'../live'}})
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab, self.repo)
    def test_api_redirection_refused(self):
        (self.repo / 'api').write_text('/unix/outside.socket')
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab, self.repo)
    def test_repo_symlink_refused(self):
        alias=self.lab/'alias'; alias.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab, alias)
    def test_external_repo_refused(self):
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab, self.lab.parent)
    def test_internal_symlink_refused(self):
        (self.repo/'escape').symlink_to('/tmp')
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab, self.repo)
    def test_hardlink_refused(self):
        p=self.lab/'external'; p.write_bytes(b'original'); os.link(p,self.repo/'linked')
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab,self.repo)
    def test_remote_datastore_refused(self):
        self.config({'type':'s3','path':'remote'})
        with self.assertRaises(m.Refusal): m.guard_repo(self.lab,self.repo)
    def test_non_scratch_base_refused(self):
        with self.assertRaises(m.Refusal): m.Lab(self.lab)
    def test_mutation_detected_by_hash(self):
        p=self.repo/'test'; p.write_bytes(b'a'); old=m.tree_hashes(self.repo)
        p.write_bytes(b'b'); self.assertNotEqual(old,m.tree_hashes(self.repo))

if __name__ == '__main__': unittest.main()

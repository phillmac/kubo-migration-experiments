import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

spec = importlib.util.spec_from_file_location('schema_lab', Path(__file__).resolve().parents[1] / 'scripts' / 'kubo_migration_lab.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class SchemaMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'fixture'
        self.repo.mkdir()
        (self.repo / 'version').write_text('16\n')
        self.before = {'Identity': {'PeerID': 'synthetic', 'PrivKey': 'not-a-key'},
                       'Datastore': {'Spec': {'type': 'pebbleds', 'path': 'pebbleds'}},
                       'Provider': {'Enabled': False}}
        (self.repo / 'config').write_text(json.dumps(self.before))
        (self.repo / 'datastore_spec').write_text('{"type":"pebbleds","path":"pebbleds"}')
        self.calls = []
    def lab(self, version='18', mutate=None):
        def run(binary, repo, *args):
            self.calls.append(args)
            config = json.loads((repo / 'config').read_text())
            config['Provide'] = config.pop('Provider')
            if mutate: mutate(config)
            (repo / 'config').write_text(json.dumps(config))
            (repo / 'version').write_text(version+'\n')
            return 0, b'synthetic migration complete\n'
        return SimpleNamespace(root=self.root, run=run)
    def test_explicit_migration_preserves_identity_and_datastore(self):
        result = m.migrate_schema(self.lab(), Path('/unused'), self.repo)
        self.assertEqual(self.calls, [('repo', 'migrate', '--to=18')])
        self.assertTrue(result['identity_preserved'])
        self.assertEqual(result['changed_config_sections'], ['Provide', 'Provider'])
        self.assertEqual(result['to'], '18')
    def test_wrong_start_version_never_invokes_migrator(self):
        (self.repo / 'version').write_text('17\n')
        with self.assertRaises(m.Refusal): m.migrate_schema(self.lab(), Path('/unused'), self.repo)
        self.assertEqual(self.calls, [])
    def test_wrong_end_version_refused(self):
        with self.assertRaises(m.Refusal): m.migrate_schema(self.lab(version='17'), Path('/unused'), self.repo)
    def test_identity_change_refused(self):
        def change(c): c['Identity']['PeerID'] = 'different'
        with self.assertRaises(m.Refusal): m.migrate_schema(self.lab(mutate=change), Path('/unused'), self.repo)
    def test_datastore_change_refused(self):
        def change(c): c['Datastore']['Spec']['path'] = 'other-local'
        with self.assertRaises(m.Refusal): m.migrate_schema(self.lab(mutate=change), Path('/unused'), self.repo)
    def test_disk_spec_change_refused(self):
        def change(c): (self.repo / 'datastore_spec').write_text('changed')
        with self.assertRaises(m.Refusal): m.migrate_schema(self.lab(mutate=change), Path('/unused'), self.repo)

if __name__ == '__main__': unittest.main()

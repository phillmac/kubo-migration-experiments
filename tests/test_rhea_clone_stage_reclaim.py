import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_clone_stage_reclaim as m


class VersionReader:
    def __init__(self, data):
        self.data = data
        self.calls = []
        self.bad = None

    def get_object(self, *, Bucket, Key, VersionId):
        assert Bucket == m.r.iam.BUCKET and Key.startswith(m.r.proof.PREFIX)
        name = Key[len(m.r.proof.PREFIX):]
        assert VersionId == 'v-' + name
        self.calls.append(name)
        body = self.data[name]
        version = VersionId
        if self.bad == (name, 'hash'):
            body = b'x' * len(body)
        if self.bad == (name, 'version'):
            version = 'wrong'
        if self.bad == (name, 'short'):
            body = body[:-1]
        return dict(VersionId=version, ETag='etag-'+name, ContentLength=len(self.data[name]), Body=io.BytesIO(body))


class StageReclamation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.stage = s = m.Stage.__new__(m.Stage)
        s.original = root/'000020'
        s.retired = root/'retired/000020'
        s.retired.parent.mkdir()
        s.journal = root/'journal'
        s.journal.mkdir()
        s.relative = Path('cache')
        (s.original/s.relative).mkdir(parents=True)
        (s.original/'closed-payloads').mkdir()
        self.input, self.output = '000111.sst', '000222.sst'
        self.data = {self.input: b'input' * 16000, self.output: b'output' * 17000}
        self.cloud = VersionReader(self.data)
        self.rows = {}
        for name, body in self.data.items():
            file = s.original/s.relative/name
            file.write_bytes(body)
            if name == self.output:
                os.link(file, s.original/'closed-payloads'/name)
            st = file.stat()
            self.rows[name] = dict(output=name == self.output, identity=m.identity(st), atime_ns=st.st_atime_ns,
                                   mtime_ns=st.st_mtime_ns, pin=dict(version_id='v-'+name, etag='etag-'+name,
                                   size=len(body), sha256=m.r.c.raw_sha(body)))
        self.plan = dict(tables=self.rows)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        for owner, attr, replacement in (
            (s, 'assert_idle', lambda: None), (s, 'plan', lambda _: self.plan), (m, 'idle_tree', lambda _: None),
            (m.r.host, 'read', lambda p: json.loads(p.read_bytes())),
            (m, 'credentials_pool', lambda rows, op: {n: op(self.cloud, n, row) for n, row in rows.items()})):
            self.stack.enter_context(patch.object(owner, attr, replacement))

    def test_round_trip_keeps_aliases_and_times_then_releases_again(self):
        s = self.stage
        before = self.rows[self.output]['identity']
        first = s.reclaim()
        self.assertGreater(first['released_bytes'], 0)
        self.assertFalse(s.original.exists())
        self.assertEqual((s.retired/'closed-payloads'/self.output).stat().st_size, 0)
        self.assertEqual(s.reclaim()['action'], 'already reclaimed')
        self.assertCountEqual(self.cloud.calls, self.data)
        restored = s.restore()
        self.assertEqual(restored['pinned_bytes_read'], sum(map(len, self.data.values())))
        for n, row in self.rows.items():
            file = s.original/s.relative/n
            self.assertEqual(file.read_bytes(), self.data[n])
            self.assertEqual(file.stat().st_mtime_ns, row['mtime_ns'])
        self.assertEqual(m.identity((s.original/'closed-payloads'/self.output).stat()), before)
        self.assertEqual(s.restore()['action'], 'already restored')
        self.assertEqual(s.reclaim()['recovery_sha256'], first['recovery_sha256'])

    def test_every_remote_file_must_match_before_detach(self):
        for problem in ('hash', 'version', 'short'):
            with self.subTest(problem=problem):
                self.cloud.bad = (self.output, problem)
                with self.assertRaises(RuntimeError):
                    self.stage.reclaim()
                self.assertTrue(self.stage.original.is_dir())
                self.assertFalse(self.stage.retired.exists())
                self.assertFalse((self.stage.journal/'recovery.json').exists())
                self.assertEqual((self.stage.original/self.stage.relative/self.input).read_bytes(), self.data[self.input])

    def test_partial_restore_stays_detached_and_can_retry(self):
        s = self.stage
        s.reclaim()
        self.cloud.bad = (self.output, 'version')
        with self.assertRaises(RuntimeError):
            s.restore()
        self.assertFalse(s.original.exists())
        self.assertEqual((s.retired/'closed-payloads'/self.output).stat().st_size, 0)
        # An interruption may leave a partly written inode with its aliases intact.
        (s.retired/s.relative/self.output).write_bytes(b'partial')
        self.cloud.bad = None
        s.restore()
        self.assertEqual((s.original/'closed-payloads'/self.output).read_bytes(), self.data[self.output])

    def test_extra_link_and_current_or_future_generation_are_rejected(self):
        s = self.stage
        os.link(s.original/s.relative/self.input, s.journal/'other')
        with self.assertRaises(RuntimeError):
            s.reclaim()
        self.assertFalse(self.cloud.calls)
        for number in (14, 22, 23, True):
            with self.assertRaises(RuntimeError):
                m.historical(dict(generation=22), number)

    def test_rename_does_not_replace_an_empty_directory(self):
        self.stage.retired.mkdir()
        with self.assertRaises(FileExistsError):
            m.move_stage(self.stage.original, self.stage.retired)
        self.assertTrue(self.stage.original.is_dir())

    def test_metadata_witness_excludes_only_named_payloads(self):
        stage = self.stage.original
        p = stage/self.stage.relative/self.input
        first = m.metadata_digest(stage, {p, stage/self.stage.relative/self.output, stage/'closed-payloads'/self.output})
        p.write_bytes(b'new bytes')
        self.assertEqual(first, m.metadata_digest(stage, {p, stage/self.stage.relative/self.output, stage/'closed-payloads'/self.output}))
        (stage/'manifest').write_bytes(b'changed metadata')
        self.assertNotEqual(first, m.metadata_digest(stage, {p, stage/self.stage.relative/self.output, stage/'closed-payloads'/self.output}))

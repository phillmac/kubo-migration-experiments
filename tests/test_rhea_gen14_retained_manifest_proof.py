from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import rhea_gen14_retained_manifest_proof as m


class RetainedProofTest(unittest.TestCase):
    def setUp(self):
        self.old = 'marker.manifest.000016.MANIFEST-47475342'
        self.new = 'marker.manifest.000017.MANIFEST-47475351'
        self.fmt = 'marker.format-version.000012.013'
        def pin(version):
            return dict(version_id=version, size=0, sha256=m.EMPTY_SHA, etag='"empty"')
        self.meta = {self.old: pin('old-version'), self.fmt: pin('format-version')}
        self.pin = pin('published-version')
        self.baseline = [m.latest_row(k, v) for k, v in self.meta.items()]
        self.baseline.append(dict(name='marker.manifest.000015.MANIFEST-47475340', delete=True,
                                  latest=True, version_id='historical-tombstone'))
        self.added = m.latest_row(self.new, self.pin)

    def check(self, fresh, published=None):
        return m.retained_manifest_view(self.meta, self.new, self.baseline, fresh, published)

    def test_publication_preserves_all_previous_versions_and_flags(self):
        self.assertEqual(self.check(self.baseline[::-1])['active'], self.old)
        self.assertEqual(self.check([self.added] + self.baseline, self.pin),
                         dict(active=self.new, retained=[self.old], format=self.fmt))

    def test_rejects_early_missing_overwritten_and_deleted_versions(self):
        for fresh, receipt in ((self.baseline + [self.added], None), (self.baseline, self.pin),
                (self.baseline[:-1] + [self.added], self.pin),
                ([dict(self.baseline[0], latest=False), *self.baseline[1:], self.added,
                  dict(self.baseline[0], version_id='same-body-replacement')], self.pin),
                ([dict(self.baseline[0], latest=False), *self.baseline[1:], self.added,
                  dict(name=self.old, delete=True, latest=True, version_id='new-tombstone')], self.pin),
                (self.baseline + [self.added, self.added], self.pin)):
            with self.assertRaises(RuntimeError):
                self.check(fresh, receipt)

    def test_rejects_older_manifest_or_unbound_prior_pin(self):
        for name in ('marker.manifest.000018.MANIFEST-47475341', 'marker.manifest.000016.MANIFEST-47475351'):
            with self.assertRaises(RuntimeError):
                m.retained_manifest_view(self.meta, name, self.baseline, self.baseline)
        self.meta[self.old]['version_id'] = 'identical-bytes-different-version'
        with self.assertRaises(RuntimeError):
            self.check(self.baseline)

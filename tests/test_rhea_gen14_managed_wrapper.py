"""Exercise the launcher using only a harmless local stand-in, never an SDK."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
LAUNCHER = 'run_rhea_gen14_iam_managed.sh'
ENTRY = 'rhea_gen14_recover_iam_policy.py'
MODULES = (ENTRY, 'rhea_gen14_create_iam_credentials.py',
           'rhea_gen14_iam_admin_acceptance.py', 'rhea_multi_sst_marker_iam.py',
           'rhea_multi_sst_signed_admission.py')


class ManagedWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='managed-wrapper-offline-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'bundle'
        self.base.mkdir(mode=0o700)
        for name in (LAUNCHER, *MODULES):
            shutil.copyfile(SCRIPTS / name, self.base / name)
            (self.base / name).chmod(0o600)
        self.launcher = self.base / LAUNCHER

    def invoke(self, *args):
        return subprocess.run(['/usr/bin/bash', str(self.launcher), *args],
                              env={'PATH': '/usr/bin:/bin',
                                   'AWS_ACCESS_KEY_ID': 'CANARY_NEVER_PRINT',
                                   'AWS_SECRET_ACCESS_KEY': 'CANARY_NEVER_PRINT',
                                   'PYTHONPATH': '/untrusted'},
                              capture_output=True, text=True, timeout=6)

    def prepare_standin(self):
        original = hashlib.sha256((self.base / ENTRY).read_bytes()).hexdigest()
        (self.base / ENTRY).write_text(
            'import json,os,sys\n'
            'assert not any(k in os.environ for k in '
            '("AWS_ACCESS_KEY_ID","AWS_SECRET_ACCESS_KEY","PYTHONPATH"))\n'
            'print(json.dumps({"mode":sys.argv[1],"fixture":"NO_CREDENTIALS"}))\n')
        replacement = hashlib.sha256((self.base / ENTRY).read_bytes()).hexdigest()
        raw = self.launcher.read_text().replace(original, replacement)
        # Only this private copy relaxes root ancestry/owner checks to exercise
        # shell dispatch as an unprivileged CI user. Production bytes stay exact.
        raw = raw.replace('[[ "$(/usr/bin/id -u)" == 0 ]]', '[[ 1 == 1 ]]')
        start, end = raw.index('ancestor="$BASE"'), raw.index('done\n') + len('done\n')
        raw = raw[:start] + raw[end:]
        raw = raw.replace('[[ "$(/usr/bin/stat -c %u -- "$file")" == 0 ]]',
                          f'[[ "$(/usr/bin/stat -c %u -- "$file")" == {os.getuid()} ]]')
        self.launcher.write_text(raw)

    def test_actual_source_hashes_are_pinned(self):
        raw = self.launcher.read_text()
        for name in MODULES:
            with self.subTest(name=name):
                digest = hashlib.sha256((SCRIPTS / name).read_bytes()).hexdigest()
                self.assertIn(f"check '{name}' '{digest}'", raw)

    def test_modes_dispatch_to_standin_with_environment_cleared(self):
        self.prepare_standin()
        for mode in ('status', 'inspect', 'recover', 'verify'):
            value = self.invoke(mode)
            self.assertEqual(value.returncode, 0, value.stderr)
            self.assertEqual(json.loads(value.stdout),
                             {'mode': mode, 'fixture': 'NO_CREDENTIALS'})
            self.assertNotIn('CANARY', value.stdout + value.stderr)

    def test_modified_source_is_rejected_before_dispatch(self):
        self.prepare_standin()
        with (self.base / ENTRY).open('a') as stream:
            stream.write('\n# unexpected edit\n')
        value = self.invoke('recover')
        self.assertEqual(value.returncode, 2)
        self.assertIn('source hash mismatch', value.stderr)
        self.assertEqual(value.stdout, '')

    def test_extra_arguments_and_unknown_modes_are_rejected(self):
        for args in ((), ('reset',), ('recover', '--force')):
            self.assertEqual(self.invoke(*args).returncode, 2)

    def test_nonroot_is_rejected_before_loading_any_module(self):
        self.launcher.write_text(self.launcher.read_text().replace(
            '[[ "$(/usr/bin/id -u)" == 0 ]]', '[[ 1000 == 0 ]]'))
        value = self.invoke('recover')
        self.assertEqual(value.returncode, 2)
        self.assertIn('root required', value.stderr)
        self.assertEqual(value.stdout, '')


if __name__ == '__main__':
    unittest.main()

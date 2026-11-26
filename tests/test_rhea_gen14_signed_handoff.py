import hashlib
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_signed_handoff as h


class HandoffTest(unittest.TestCase):
    def test_binding_time_domain_and_revocation_before_open(self):
        a = h.admission
        binding = dict(scope=h.SCOPE, worker_request=None, restored_read_only=True)
        claims = dict(binding=binding, issued=1000, expires=1100, nonce=secrets.token_hex(32))
        raw = a.canonical(claims)
        with tempfile.TemporaryDirectory() as temp:
            d = Path(temp)
            subprocess.run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(d/'key')], check=True)
            pub = subprocess.check_output(['openssl', 'pkey', '-in', str(d/'key'), '-pubout'])
            def sign(domain):
                (d/'message').write_bytes(domain + raw)
                return subprocess.check_output(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey',
                                                str(d/'key'), '-in', str(d/'message')])
            sig = sign(a.DOMAIN)
            with patch.object(h, 'HANDOFF_KEY', hashlib.sha256(pub).hexdigest()):
                self.assertEqual(h.checked_claims(raw, sig, pub, binding, 1050).nonce, claims['nonce'])
                for change in (dict(worker_request={'maximum_units': 2}), dict(restored_read_only=1)):
                    with self.assertRaises(a.Refusal):
                        h.checked_claims(raw, sig, pub, dict(binding, **change), 1050)
                for now in (999, 1100):
                    with self.assertRaises(a.Refusal):
                        h.checked_claims(raw, sig, pub, binding, now)
                with self.assertRaises(a.Refusal):
                    h.checked_claims(raw, sign(a.DEPLOYMENT_DOMAIN), pub, binding, 1050)

    def test_reader_cache_blocks_dirty_and_untracked(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(h, 'CACHE', Path(temp)):
            data, meta = Path(temp)/'vfs', Path(temp)/'vfsMeta'
            data.mkdir()
            meta.mkdir()
            (data/'x').write_bytes(b'x')
            with self.assertRaises(h.admission.Refusal):
                h.clean_reader_cache()
            (meta/'x').write_text('{"Dirty":true}')
            with self.assertRaises(h.admission.Refusal):
                h.clean_reader_cache()
            (meta/'x').write_text('{"Dirty":false}')
            self.assertEqual(h.clean_reader_cache(), 1)

    def test_restore_refuses_unrelated_existing_reader(self):
        with patch.object(h, 'main_pid', side_effect=lambda u: 0 if u == h.WRITER else 77), \
             patch.object(h, 'mount_row', side_effect=lambda m: None if m == h.DB else 'reader'), \
             patch.object(h.os, 'statvfs', return_value=type('Mount', (), {'f_flag': 0})()), \
             patch.object(h.clone, 'read_path', return_value=h.admission.canonical({'binding': {'reader': 'old'}})), \
             patch.object(h, 'reader', return_value='different'), patch.object(h, 'output') as command:
            with self.assertRaises(h.admission.Refusal):
                h.restore()
            command.assert_not_called()

    def test_collects_only_intentional_exit_from_signed_pid(self):
        proc = {'pid': 2147483647}
        saved = h.admission.canonical({'binding': {'reader': {'process': proc}}})
        status = dict(LoadState='loaded', ActiveState='failed', SubState='failed', MainPID='0',
                      Result='exit-code', ExecMainPID=str(proc['pid']), ExecMainCode='1', ExecMainStatus='143',
                      User='', Group='', DropInPaths='', NeedDaemonReload='no', FragmentPath='/run/systemd/transient/'+h.READER)
        with tempfile.TemporaryDirectory() as d, patch.object(h, 'TRIAL', Path(d)), \
             patch.object(h.clone, 'read_path', return_value=saved), patch.object(h, 'mount_row', return_value=None), \
             patch.object(h, 'entry') as written, patch.object(h, 'output') as cmd:
            for key, bad in (('ExecMainPID', '4'), ('ExecMainStatus', '1')):
                cmd.return_value = '\n'.join(k+'='+v for k,v in dict(status, **{key:bad}).items())
                with self.assertRaises(RuntimeError):
                    h.collect_stopped_reader()
                written.assert_not_called()
                self.assertEqual(len(cmd.call_args.args[0]), 4)
            cmd.return_value = '\n'.join(k+'='+v for k,v in status.items())
            h.collect_stopped_reader()
            written.assert_called_once_with('reader-exit143.json', status)
            cmd.assert_called_with(['/usr/bin/systemctl', 'reset-failed', h.READER])

"""Offline cryptographic/nonce tests; keys exist only in disposable test dirs."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import copy
import fcntl
import os
from pathlib import Path
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_multi_sst_signed_admission as a


class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='offline-admission-', dir=ROOT)
        cls.path = Path(cls.tmp.name)
        cls.private = cls.path / 'ephemeral-private.pem'
        cls.public = cls.path / 'ephemeral-public.pem'
        cls.command('genpkey', '-algorithm', 'Ed25519', '-out', str(cls.private))
        cls.private.chmod(0o600)
        cls.command('pkey', '-in', str(cls.private), '-pubout', '-out', str(cls.public))
        cls.pem = cls.public.read_bytes()
        cls.pin = a.sha(cls.pem)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @staticmethod
    def command(*args):
        return subprocess.run(['/usr/bin/openssl', *args], check=True, capture_output=True,
                              stdin=subprocess.DEVNULL, timeout=10,
                              env={'PATH': '/usr/bin:/bin', 'OPENSSL_CONF': '/dev/null'})

    def setUp(self):
        self.now = int(time.time())
        self.intent = {'unit_count': 2, 'request': {'maximum_units': 2}, 'all_fields': 'bound'}
        self.boot = '12345678-1234-1234-1234-123456789abc'
        pin = a.sha(b'fixed offline identity')
        self.binding = dict(schema=1, scope='rhea-gen14-one-batch', intent_sha256=a.sha(a.canonical(self.intent)),
            anchor=dict(generation=13, cap=9, pending=None, checkpoint_sha256=a.ANCHOR, legacy_journal_sha256=pin),
            units=2, host='rhea', boot_id=self.boot,
            installation={name: pin for name in ('deployment', 'writer', 'controller', 'adapter', 'signed_admission',
                                                'source_pins', 'installed_manifest')},
            target=dict(bucket=a.BUCKET, prefix='rhea/'),
            identities=dict(mount={'mountinfo': 'offline fixed mount 1'},
                            rc={'inode': 3, 'peer_pid': 500, 'peer_uid': 0, 'peer_gid': 0},
                            process=dict(pid=500, start_ticks=100, boot_id=self.boot, exe_sha256=pin),
                            cloud={'Account': 'offline-account'}, services={'reader': 'inactive'}))
        self.claims = dict(copy.deepcopy(self.binding), issued=self.now - 1, expires=self.now + 120,
                           nonce=secrets.token_hex(32))

    def sign(self, raw, *, domain=a.DOMAIN, key=None):
        with tempfile.TemporaryDirectory(dir=self.path) as tmp:
            message, signature = Path(tmp) / 'message', Path(tmp) / 'signature'
            message.write_bytes(domain + raw)
            self.command('pkeyutl', '-sign', '-rawin', '-inkey', str(key or self.private),
                         '-in', str(message), '-out', str(signature))
            return signature.read_bytes()

    def verify(self, claims=None, **overrides):
        raw = a.canonical(self.claims if claims is None else claims)
        args = dict(expected_binding=self.binding, intent=self.intent, key_sha256=self.pin,
                    now=self.now, key_not_before=self.now - 100, key_not_after=self.now + 1000, openssl_uid=os.stat('/usr/bin/openssl').st_uid)
        args.update(overrides)
        return a.verify_claims(raw, self.sign(raw), self.pem, **args)

    def test_real_ed25519_one_and_two_units(self):
        for units in (1, 2):
            with self.subTest(units=units):
                self.intent['unit_count'] = units
                self.intent['request']['maximum_units'] = units
                self.binding.update(units=units, intent_sha256=a.sha(a.canonical(self.intent)))
                self.claims.update(self.binding)
                result = self.verify()
                self.assertEqual(result.nonce, self.claims['nonce'])
                self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o600)

    def test_tampered_signed_bytes(self):
        raw = a.canonical(self.claims)
        changed = raw.replace(b'rhea-gen14-one-batch', b'rhea-gen15-one-batch')
        with self.assertRaises(a.Refusal):
            a.verify_detached(changed, self.sign(raw), self.pem, key_sha256=self.pin, domain=a.DOMAIN, openssl_uid=os.stat('/usr/bin/openssl').st_uid)

    def test_wrong_key_with_valid_pem_pin(self):
        with tempfile.TemporaryDirectory(dir=self.path) as tmp:
            wrong = Path(tmp) / 'wrong-private.pem'
            self.command('genpkey', '-algorithm', 'Ed25519', '-out', str(wrong))
            raw = a.canonical(self.claims)
            with self.assertRaises(a.Refusal):
                a.verify_detached(raw, self.sign(raw, key=wrong), self.pem, key_sha256=self.pin, domain=a.DOMAIN, openssl_uid=os.stat('/usr/bin/openssl').st_uid)

    def test_wrong_key_pin(self):
        with self.assertRaises(a.Refusal):
            self.verify(key_sha256='0' * 64)

    def test_domain_separation(self):
        raw = a.canonical(self.claims)
        with self.assertRaises(a.Refusal):
            a.verify_detached(raw, self.sign(raw, domain=a.DEPLOYMENT_DOMAIN), self.pem,
                              key_sha256=self.pin, domain=a.DOMAIN, openssl_uid=os.stat('/usr/bin/openssl').st_uid)

    def test_no_private_key_as_public_key(self):
        with self.assertRaises(a.Refusal):
            a.verify_detached(b'message', bytes(64), self.private.read_bytes(),
                              key_sha256=a.sha(self.private.read_bytes()), domain=a.DOMAIN, openssl_uid=os.stat('/usr/bin/openssl').st_uid)

    def test_expired_and_future_claims(self):
        for field, value in (('expires', self.now), ('issued', self.now + 1), ('expires', self.now + 901)):
            with self.subTest(field=field, value=value), self.assertRaises(a.Refusal):
                self.verify(dict(self.claims, **{field: value}))

    def test_expired_or_not_yet_valid_key(self):
        for override in ({'key_not_after': self.now}, {'key_not_before': self.now + 1}):
            with self.subTest(override=override), self.assertRaises(a.Refusal):
                self.verify(**override)

    def test_entire_intent_bound(self):
        changed = dict(self.intent, all_fields='tampered')
        with self.assertRaises(a.Refusal):
            self.verify(intent=changed)

    def test_boot_rc_mount_process_cloud_service_identity_mismatch(self):
        for name in ('boot_id', 'mount', 'rc', 'process', 'cloud', 'services'):
            changed = copy.deepcopy(self.claims)
            if name == 'boot_id':
                changed[name] = '87654321-1234-1234-1234-123456789abc'
            else:
                changed['identities'][name]['tampered'] = True
            with self.subTest(name=name), self.assertRaises(a.Refusal):
                self.verify(changed)

    def test_installed_hashes_and_target_mismatch(self):
        for name in (*self.binding['installation'], 'bucket', 'prefix'):
            changed = copy.deepcopy(self.claims)
            changed['target' if name in ('bucket', 'prefix') else 'installation'][name] = 'tampered'
            with self.subTest(name=name), self.assertRaises(a.Refusal):
                self.verify(changed)

    def test_legacy_anchor_and_units(self):
        for field, value in (('generation', 14), ('cap', 10), ('pending', {}), ('checkpoint_sha256', '0' * 64)):
            changed = copy.deepcopy(self.binding)
            changed['anchor'][field] = value
            with self.subTest(field=field), self.assertRaises(a.Refusal):
                a.validate_binding(changed)
        for units in (0, 3, True, 1.0):
            with self.subTest(units=units), self.assertRaises(a.Refusal):
                a.validate_binding(dict(self.binding, units=units))

    def test_short_degenerate_uppercase_nonces(self):
        for nonce in ('12' * 8, '00' * 32, 'AB' * 32, '../bad'):
            with self.subTest(nonce=nonce), self.assertRaises(a.Refusal):
                self.verify(dict(self.claims, nonce=nonce))

    def test_duplicate_unknown_and_noncanonical_json(self):
        for raw in (b'{"schema":1,"schema":1}\n', b'{"x":NaN}\n', b'{ "x":1 }\n', b'[]\n'):
            with self.subTest(raw=raw), self.assertRaises(a.Refusal):
                a.parse(raw)
        with self.assertRaises(a.Refusal):
            self.verify(dict(self.claims, signature_verified=True))

    def test_truncated_and_empty_signatures(self):
        for signature in (b'', bytes(63), bytes(65)):
            with self.subTest(length=len(signature)), self.assertRaises(a.Refusal):
                a.verify_detached(b'claims', signature, self.pem, key_sha256=self.pin, domain=a.DOMAIN, openssl_uid=os.stat('/usr/bin/openssl').st_uid)

    def test_production_unprovisioned_no_environment_bypass(self):
        with patch.dict(os.environ, {'RHEA_TEST': '1', 'RHEA_PUBLIC_KEY': str(self.public)}):
            with self.assertRaises(a.Refusal):
                a.verify_production(b'{}', bytes(64), expected_binding=self.binding, intent=self.intent)

    @contextmanager
    def nonce_tree(self, *, locked=True):
        with tempfile.TemporaryDirectory(dir=self.path) as tmp:
            directory = Path(tmp) / 'nonces'
            directory.mkdir(mode=0o700)
            lock = Path(tmp) / 'writer.lock'
            fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                if locked:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with a.protected_directory(directory, uid=os.geteuid(), private=True, ancestor_uid=os.stat('/').st_uid) as parent:
                    yield directory, parent, lock
            finally:
                os.close(fd)

    def consume(self, parent, lock, verified):
        a._consume_at(parent, verified, lock_path=lock, uid=os.geteuid(), ancestor_uid=os.stat('/').st_uid)

    def test_nonce_replay_including_new_process_lifetime(self):
        verified = self.verify()
        with self.nonce_tree() as (directory, parent, lock):
            self.consume(parent, lock, verified)
            raw = (directory / (verified.nonce + '.json')).read_bytes()
            self.assertEqual(a.parse(raw)['claims_sha256'], a.sha(verified.raw))
            self.assertEqual(stat.S_IMODE((directory / (verified.nonce + '.json')).stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                self.consume(parent, lock, copy.deepcopy(verified))

    def test_nonce_atomic_race(self):
        verified = self.verify()
        with self.nonce_tree() as (_, parent, lock):
            def attempt():
                try:
                    self.consume(parent, lock, verified)
                    return 'consumed'
                except FileExistsError:
                    return 'replay'
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _: attempt(), range(2)))
            self.assertCountEqual(outcomes, ['consumed', 'replay'])

    def test_nonce_symlink_no_target_write(self):
        verified = self.verify()
        with self.nonce_tree() as (directory, parent, lock):
            target = directory / 'untouched'
            target.write_bytes(b'preserve')
            (directory / (verified.nonce + '.json')).symlink_to(target)
            with self.assertRaises(FileExistsError):
                self.consume(parent, lock, verified)
            self.assertEqual(target.read_bytes(), b'preserve')

    def test_nonce_torn_record_never_reused(self):
        verified = self.verify()
        with self.nonce_tree() as (directory, parent, lock):
            record = directory / (verified.nonce + '.json')
            record.write_bytes(b'{"schema":')
            with self.assertRaises(FileExistsError):
                self.consume(parent, lock, verified)
            self.assertEqual(record.read_bytes(), b'{"schema":')

    def test_nonce_fsync_failure_remains_burned(self):
        verified = self.verify()
        with self.nonce_tree() as (directory, parent, lock):
            with patch.object(a.os, 'fsync', side_effect=OSError('offline power loss')):
                with self.assertRaises(OSError):
                    self.consume(parent, lock, verified)
            self.assertTrue((directory / (verified.nonce + '.json')).exists())
            with self.assertRaises(FileExistsError):
                self.consume(parent, lock, verified)

    def test_nonce_requires_existing_shared_lock(self):
        with self.nonce_tree(locked=False) as (_, parent, lock):
            with self.assertRaises(a.Refusal):
                self.consume(parent, lock, self.verify())

    def test_unrelated_torn_nonce_poisons_store(self):
        verified = self.verify()
        with self.nonce_tree() as (directory, parent, lock):
            (directory / (secrets.token_hex(32) + '.json')).write_bytes(b'{"schema":')
            with self.assertRaises(a.Refusal):
                self.consume(parent, lock, verified)
            self.assertFalse((directory / (verified.nonce + '.json')).exists())

    def test_nonce_lock_symlink_refused(self):
        verified = self.verify()
        with self.nonce_tree() as (_, parent, lock):
            link = lock.parent / 'linked-lock'
            link.symlink_to(lock)
            with self.assertRaises(OSError):
                self.consume(parent, link, verified)

    def test_expired_verified_nonce_not_consumed(self):
        verified = self.verify()
        with self.nonce_tree() as (directory, parent, lock):
            with patch.object(a.time, 'time', return_value=verified.expires):
                with self.assertRaises(a.Refusal):
                    self.consume(parent, lock, verified)
            self.assertFalse((directory / (verified.nonce + '.json')).exists())

    def test_nonce_file_fsync_precedes_parent_fsync(self):
        verified = self.verify()
        synced = []
        original = os.fsync
        def sync(fd):
            synced.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'record')
            original(fd)
        with self.nonce_tree() as (_, parent, lock), patch.object(a.os, 'fsync', side_effect=sync):
            self.consume(parent, lock, verified)
        self.assertEqual(synced, ['record', 'directory'])

    def test_writer_lock_contender_excluded(self):
        with self.nonce_tree() as (_, _, lock):
            fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)

    def test_untrusted_root_permissions_and_symlink_parents(self):
        with self.nonce_tree() as (directory, _, _):
            if os.geteuid() != 0:
                with self.assertRaises(a.Refusal):
                    with a.protected_directory(directory, private=True):
                        pass
            child = directory / 'unsafe'
            child.mkdir(mode=0o777)
            child.chmod(0o777)
            with self.assertRaises(a.Refusal):
                with a.protected_directory(child, uid=os.geteuid(), private=True, ancestor_uid=os.stat('/').st_uid):
                    pass
            link = directory / 'link'
            link.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(OSError):
                with a.protected_directory(link, uid=os.geteuid(), private=True, ancestor_uid=os.stat('/').st_uid):
                    pass

    def test_key_file_permissions_links_and_type(self):
        with self.nonce_tree() as (directory, parent, _):
            key = directory / 'key'
            key.write_bytes(self.pem)
            key.chmod(0o644)
            with self.assertRaises(a.Refusal):
                a.read_at(parent, 'key', uid=os.geteuid())
            key.chmod(0o600)
            (directory / 'hardlink').hardlink_to(key)
            with self.assertRaises(a.Refusal):
                a.read_at(parent, 'key', uid=os.geteuid())
            os.mkfifo(directory / 'fifo', 0o600)
            with self.assertRaises(a.Refusal):
                a.read_at(parent, 'fifo', uid=os.geteuid())


if __name__ == '__main__':
    unittest.main()

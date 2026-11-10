#!/usr/bin/env python3
"""Detached Ed25519 admission primitives. NOT DEPLOYED / NOT LIVE TESTED.

Production trust anchors are deliberately unprovisioned; no command, environment
variable or caller key can provision them. This module never signs anything.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

OPENSSL = '/usr/bin/openssl'
INSTALL = Path('/root/.local/share/rhea-multi-sst-controller-v2')
PUBLIC_KEY = INSTALL / 'admission.pub'
NONCES = INSTALL / 'consumed-nonces'
WRITER_LOCK = Path('/run/rhea-wasabi-lab/writer.lock')
# Independent security provisioning MUST replace these in reviewed source.
PUBLIC_KEY_SHA256 = None
KEY_NOT_BEFORE = None
KEY_NOT_AFTER = None
DOMAIN = b'RHEA-MULTI-SST-ADMISSION-v1\x00'
DEPLOYMENT_DOMAIN = b'RHEA-MULTI-SST-DEPLOYMENT-v1\x00'
ANCHOR = '2d26a443de2cb899b3909cc53a815b670f61570022d69a576c73b0ed395b2774'
BUCKET = 'rhea-pebble-lab-20261101-39037c6f01'
MAX_BYTES = 256 * 1024
MAX_LIFETIME = 900
HEX = re.compile(r'[0-9a-f]{64}\Z')
UUID = re.compile(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z')


class Refusal(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'invalid JSON size/type')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: require(False, 'nonfinite JSON'))
        require(type(value) is dict and canonical(value) == raw, 'canonical JSON object required')
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        raise Refusal('invalid canonical JSON') from exc


@contextmanager
def protected_directory(path, *, uid=0, private=False, ancestor_uid=0):
    """Traverse using directory FDs; never follow a substituted path component.

    uid injection is for offline primitive tests only. Production uses uid=0 and
    fixed paths. No creation, chmod, symlink resolution or permission repair.
    """
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'absolute protected path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root = os.fstat(fd)
        require(root.st_uid == root.st_gid == ancestor_uid and not root.st_mode & 0o022,
                'untrusted filesystem root')
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            # Test trees may live below sticky /tmp, never production trees.
            sticky_tmp = uid != 0 and part == 'tmp' and info.st_mode & stat.S_ISVTX and info.st_uid == ancestor_uid
            require((info.st_uid == info.st_gid == ancestor_uid
                     or (info.st_uid == uid and (uid != 0 or info.st_gid == 0)))
                    and (not info.st_mode & 0o022 or sticky_tmp), 'untrusted directory owner/mode')
        info = os.fstat(fd)
        require(info.st_uid == uid and (not private or stat.S_IMODE(info.st_mode) == 0o700),
                'private directory owner/mode required')
        if uid == 0:
            require(info.st_gid == 0, 'root group required')
        yield fd
    finally:
        os.close(fd)


def read_at(directory_fd, name, *, uid=0, mode=0o600, limit=MAX_BYTES):
    require('/' not in name and name not in ('.', '..'), 'invalid protected leaf')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == uid
                and (uid != 0 or before.st_gid == 0)
                and stat.S_IMODE(before.st_mode) == mode, 'untrusted file owner/type/mode')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after = os.fstat(fd)
        require(len(raw) <= limit and (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'file changed or too large')
        return raw
    finally:
        os.close(fd)


def protected_read(path, *, mode=0o600, limit=MAX_BYTES):
    path = Path(path)
    with protected_directory(path.parent) as fd:
        return read_at(fd, path.name, mode=mode, limit=limit)


def _ed25519_public(pem):
    require(type(pem) is bytes and len(pem) < 1024, 'invalid public key')
    lines = pem.strip().splitlines()
    require(len(lines) >= 3 and lines[0] == b'-----BEGIN PUBLIC KEY-----'
            and lines[-1] == b'-----END PUBLIC KEY-----', 'public PEM required')
    try:
        der = base64.b64decode(b''.join(lines[1:-1]), validate=True)
    except ValueError as exc:
        raise Refusal('invalid public PEM') from exc
    require(len(der) == 44 and der[:12] == bytes.fromhex('302a300506032b6570032100'),
            'Ed25519 public key required')


def verify_detached(raw, signature, public_pem, *, key_sha256, domain, openssl_uid=0):
    """Pure verification API; injected key bytes/pins are ONLY for offline use.

    OpenSSL consumes regular files because Ed25519 -rawin needs a known input
    length on OpenSSL 3.0 as well as 3.5. Temporary material contains no secrets.
    """
    require(type(raw) is bytes and len(raw) <= MAX_BYTES and type(signature) is bytes
            and len(signature) == 64, 'invalid signed input/signature')
    require(isinstance(key_sha256, str) and HEX.fullmatch(key_sha256)
            and sha(public_pem) == key_sha256, 'verification key pin mismatch')
    require(domain in (DOMAIN, DEPLOYMENT_DOMAIN), 'unknown signature domain')
    _ed25519_public(public_pem)
    # Validate the absolute executable and trusted ancestors, without PATH lookup.
    with protected_directory(Path(OPENSSL).parent, uid=openssl_uid, ancestor_uid=openssl_uid) as fd:
        read_at(fd, Path(OPENSSL).name, uid=openssl_uid, mode=0o755, limit=32 * 1024**2)
    with tempfile.TemporaryDirectory(prefix='rhea-public-verification-') as tmp:
        paths = [Path(tmp) / name for name in ('public.pem', 'message', 'signature')]
        for path, data in zip(paths, (public_pem, domain + raw, signature)):
            out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(out, 'wb') as stream:
                stream.write(data)
        try:
            result = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-pubin', '-rawin',
                                     '-inkey', str(paths[0]), '-in', str(paths[1]),
                                     '-sigfile', str(paths[2])], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
                                         'OPENSSL_CONF': '/dev/null'})
        except (OSError, subprocess.SubprocessError) as exc:
            raise Refusal('OpenSSL verification unavailable') from exc
        require(result.returncode == 0, 'Ed25519 signature verification failed')


def validate_binding(binding):
    require(type(binding) is dict and set(binding) == {'schema', 'scope', 'intent_sha256', 'anchor',
            'units', 'host', 'boot_id', 'installation', 'target', 'identities'}, 'binding schema mismatch')
    require(type(binding['schema']) is int and binding['schema'] == 1
            and binding['scope'] == 'rhea-gen14-one-batch'
            and binding['host'] == 'rhea' and UUID.fullmatch(binding['boot_id'])
            and type(binding['units']) is int and binding['units'] in (1, 2), 'host/batch mismatch')
    anchor = binding['anchor']
    require(type(anchor) is dict and set(anchor) == {'generation', 'cap', 'pending', 'checkpoint_sha256',
            'legacy_journal_sha256'} and type(anchor['generation']) is int and anchor['generation'] == 13
            and type(anchor['cap']) is int and anchor['cap'] == 9 and anchor['pending'] is None
            and anchor['checkpoint_sha256'] == ANCHOR, 'legacy gen13/cap9 anchor mismatch')
    hashes = binding['installation']
    require(type(hashes) is dict and set(hashes) == {'deployment', 'writer', 'controller', 'adapter',
            'signed_admission', 'source_pins', 'installed_manifest'}, 'installation binding missing')
    require(all(type(value) is str and HEX.fullmatch(value) for value in
                [binding['intent_sha256'], anchor['legacy_journal_sha256'], *hashes.values()]), 'invalid digest')
    require(binding['target'] == {'bucket': BUCKET, 'prefix': 'rhea/'}, 'protected target mismatch')
    identities = binding['identities']
    require(type(identities) is dict and set(identities) == {'mount', 'rc', 'process', 'cloud', 'services'}
            and all(type(value) is dict and value for value in identities.values()), 'identity evidence missing')
    process = identities['process']
    require(set(process) == {'pid', 'start_ticks', 'boot_id', 'exe_sha256'}
            and type(process['pid']) is int and process['pid'] > 1
            and type(process['start_ticks']) is int and process['start_ticks'] > 0
            and process['boot_id'] == binding['boot_id']
            and type(process['exe_sha256']) is str and HEX.fullmatch(process['exe_sha256']), 'process identity missing')


@dataclass(frozen=True)
class VerifiedAdmission:
    raw: bytes
    signature: bytes
    nonce: str
    expires: int


def verify_claims(raw, signature, public_pem, *, expected_binding, intent, key_sha256,
                  now, key_not_before, key_not_after, openssl_uid=0):
    """No host IO or nonce mutation. A signature alone never grants execution."""
    claims = parse(raw)
    validate_binding(expected_binding)
    require(set(claims) == set(expected_binding) | {'issued', 'expires', 'nonce'}, 'claims schema mismatch')
    binding = {key: claims[key] for key in expected_binding}
    require(canonical(binding) == canonical(expected_binding), 'signed identity/intent binding mismatch')
    require(sha(canonical(intent)) == claims['intent_sha256']
            and type(intent.get('unit_count')) is int and intent['unit_count'] == claims['units']
            and type(intent.get('request')) is dict
            and type(intent['request'].get('maximum_units')) is int
            and intent['request']['maximum_units'] == claims['units'], 'full intent/request mismatch')
    issued, expires = claims['issued'], claims['expires']
    require(all(type(value) is int for value in (issued, expires, now, key_not_before, key_not_after))
            and key_not_before <= issued <= now < expires <= key_not_after
            and 0 < expires - issued <= MAX_LIFETIME, 'future/expired admission or verification key')
    # Signer must generate 32 random bytes (256 bits); entropy cannot be measured
    # from one claim. Reject degenerate repeated bytes as an additional check.
    nonce = claims['nonce']
    require(type(nonce) is str and HEX.fullmatch(nonce) and len(set(bytes.fromhex(nonce))) >= 8,
            '256-bit unpredictable nonce required')
    verify_detached(raw, signature, public_pem, key_sha256=key_sha256, domain=DOMAIN, openssl_uid=openssl_uid)
    return VerifiedAdmission(raw, signature, nonce, expires)


def verify_production(raw, signature, *, expected_binding, intent):
    require(os.geteuid() == 0, 'root required')
    require(PUBLIC_KEY_SHA256 is not None and KEY_NOT_BEFORE is not None and KEY_NOT_AFTER is not None,
            'independent production admission key pin/validity unprovisioned')
    return verify_claims(raw, signature, protected_read(PUBLIC_KEY), expected_binding=expected_binding,
                         intent=intent, key_sha256=PUBLIC_KEY_SHA256, now=int(time.time()),
                         key_not_before=KEY_NOT_BEFORE, key_not_after=KEY_NOT_AFTER)


def _consume_at(directory_fd, verified, *, lock_path, uid, ancestor_uid=0):
    """Offline-testable primitive. Production supplies ONLY fixed paths/root.

    The caller holds RealHost.lock across verification, this call and subsequent
    intent creation. Probe a separate open description to ensure lock exclusion.
    No existing record (including a link or torn record) is ever reused/deleted.
    """
    require(type(verified) is VerifiedAdmission and int(time.time()) < verified.expires
            and HEX.fullmatch(verified.nonce), 'expired/unverified nonce')
    info = os.fstat(directory_fd)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == uid
            and (uid != 0 or info.st_gid == 0) and stat.S_IMODE(info.st_mode) == 0o700,
            'unsafe nonce directory')
    with protected_directory(Path(lock_path).parent, uid=uid, private=True, ancestor_uid=ancestor_uid) as parent:
        read_at(parent, Path(lock_path).name, uid=uid)
        probe = os.open(Path(lock_path).name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            lock_info = os.fstat(probe)
            require(stat.S_ISREG(lock_info.st_mode) and lock_info.st_uid == uid
                    and (uid != 0 or lock_info.st_gid == 0) and lock_info.st_nlink == 1
                    and stat.S_IMODE(lock_info.st_mode) == 0o600, 'unsafe shared lock')
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                raise Refusal('shared writer lock must already be held')
            owned = False
            for line in Path('/proc/locks').read_text().splitlines():
                fields = line.split()
                if len(fields) < 6 or fields[1:4] != ['FLOCK', 'ADVISORY', 'WRITE'] or fields[4] != str(os.getpid()):
                    continue
                major, minor, inode = fields[5].split(':')
                if (int(major, 16), int(minor, 16), int(inode)) == (
                        os.major(lock_info.st_dev), os.minor(lock_info.st_dev), lock_info.st_ino):
                    owned = True
            require(owned, 'current process must own the exact shared writer flock')
        finally:
            os.close(probe)
    name = verified.nonce + '.json'
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError('nonce evidence already exists; preserve for manual inspection')
    # An orphan/torn/unknown record poisons this store, even for a fresh nonce.
    for existing in os.listdir(directory_fd):
        if existing == name:
            raise FileExistsError('nonce concurrently consumed')
        require(re.fullmatch(r'[0-9a-f]{64}\.json', existing), 'unknown nonce evidence')
        value = parse(read_at(directory_fd, existing, uid=uid))
        require(set(value) == {'schema', 'claims_sha256', 'signature_sha256', 'nonce'}
                and type(value['schema']) is int and value['schema'] == 1
                and value['nonce'] == existing[:-5]
                and all(type(value[k]) is str and HEX.fullmatch(value[k])
                        for k in ('claims_sha256', 'signature_sha256')), 'torn/tampered nonce evidence')
    record = canonical({'schema': 1, 'claims_sha256': sha(verified.raw),
                        'signature_sha256': sha(verified.signature), 'nonce': verified.nonce})
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            require(stream.write(record) == len(record), 'short nonce write')
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(directory_fd)
    require(read_at(directory_fd, verified.nonce + '.json', uid=uid) == record, 'nonce readback mismatch')


def consume_production_nonce(verified, host):
    require(os.geteuid() == 0 and host.locked, 'RealHost shared writer lock required')
    with protected_directory(NONCES, private=True) as fd:
        _consume_at(fd, verified, lock_path=WRITER_LOCK, uid=0)


def main():
    print('REFUSED: signed admission is a library; production trust is unprovisioned; no live CLI')
    return 2


if __name__ == '__main__':
    raise SystemExit(main())

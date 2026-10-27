#!/usr/bin/env python3
"""Destructive tests of newly generated copies ONLY; never an existing repo.

Run unprivileged inside a loopback-only namespace on a disposable hosted runner.
ENOSPC uses a separately mounted, bounded tmpfs. Reports contain no configs/keys.
SIGKILL here models process death, not power failure or loss of fsynced storage.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

from kubo_migration_lab import Lab, Refusal, digest, guard_repo, require_isolation, tree_hashes, verify_binary

MIB = 1024 * 1024
PINNED = {
    'old': ('0.31.0', '28b534763361cc27c3a92e5dc4bc3683e276b695bdae80a5f8ae17f67b3f9712'),
    'bridge': ('0.34.1', '84640f968fe1e8b4e3c589589563c235be931bc85219f8ee306da908ee452905'),
    'target': ('0.43.1', '8768c8a2907f429f177917091e8abe250d3368d1b82ea0348332cf7e53807bf0'),
}


def require(condition, message):
    if not condition:
        raise Refusal(message)


def file_sizes(repo):
    out = {}
    for p in Path(repo).rglob('*'):
        try:
            if p.is_file():
                s = p.stat()
                out[str(p.relative_to(repo))] = {'size': s.st_size, 'allocated': s.st_blocks * 512}
        except FileNotFoundError:
            pass  # Concurrent compaction; samples are explicitly lower bounds.
    return out


def synced_copy(lab, source, name):
    dest = lab.clone(source, name)
    for p in dest.rglob('*'):
        if p.is_file():
            with p.open('rb') as stream:
                os.fsync(stream.fileno())
    for p in [x for x in dest.rglob('*') if x.is_dir()] + [dest]:
        fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return dest


def validate_pressure_mount(base, mount):
    base, mount = Path(base).resolve(), Path(mount)
    require(mount.absolute() == mount.resolve() and mount.parent == base and mount.name == 'limited',
            'Pressure mount must be the exact nonsymlink scratch/limited path')
    found = False
    for row in Path('/proc/self/mountinfo').read_text().splitlines():
        left, right = row.split(' - ', 1)
        if left.split()[4].replace('\\040', ' ') == str(mount):
            found = right.split()[0] == 'tmpfs'
    require(found and os.path.ismount(mount), 'Pressure mount must be a separately mounted tmpfs')
    v = os.statvfs(mount)
    require(64 * MIB <= v.f_blocks * v.f_frsize <= 512 * MIB, 'Pressure filesystem must be bounded to 64..512 MiB')
    require(not any(mount.iterdir()), 'Pressure filesystem must initially be empty')
    return mount


class Experiment:
    def __init__(self, base):
        self.lab = Lab(base)
        self.root = self.lab.root
        self.events = []

    def env(self, repo):
        return {'PATH': '/usr/bin:/bin', 'HOME': str(self.root / 'home'),
                'IPFS_PATH': str(repo), 'GOMAXPROCS': '2', 'GOMEMLIMIT': '512MiB', 'LANG': 'C.UTF-8'}

    def run(self, binary, repo, *args, timeout=90, kill_during_sst=False, checked=True, alternate_parent=None):
        guard_repo(alternate_parent or self.root, repo)
        require_isolation()
        cmd = [str(binary), '--offline', *args]
        start_files = file_sizes(repo)
        peak = sum(v['allocated'] for v in start_files.values())
        trigger = None
        timed_out = False
        if kill_during_sst:
            require(shutil.which('strace'), 'strace required for a slowed interruption window')
            # Delay write entry only to make the crash point observable. Not a throughput test.
            cmd = ['strace', '-f', '-qq', '-s', '0', '-e', 'trace=write,pwrite64,writev',
                   '-e', 'inject=write:delay_enter=1ms', '-o', '/dev/null', *cmd]
        started = time.monotonic()
        with tempfile.TemporaryFile(dir=self.root / 'home') as out, tempfile.TemporaryFile(dir=self.root / 'home') as err:
            proc = subprocess.Popen(cmd, cwd=self.root, env=self.env(repo), stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, start_new_session=True)
            try:
                while proc.poll() is None:
                    files = file_sizes(repo)
                    peak = max(peak, sum(v['allocated'] for v in files.values()))
                    candidates = {k: v['size'] for k, v in files.items()
                                  if k.endswith('.sst') and k not in start_files and v['size'] >= MIB}
                    if kill_during_sst and candidates and trigger is None:
                        # Stop all traced descendants before recording the observed interrupted state.
                        os.killpg(proc.pid, signal.SIGSTOP)
                        trigger = {'new_sst_sizes': candidates,
                                   'format_markers': sorted(str(p.relative_to(repo)) for p in Path(repo).rglob('*format-version*'))}
                        os.killpg(proc.pid, signal.SIGKILL)
                    if time.monotonic() - started > timeout:
                        timed_out = True
                        os.killpg(proc.pid, signal.SIGKILL)
                    time.sleep(0.003)
                code = proc.wait(timeout=5)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
            out.seek(0)
            h = hashlib.sha256()
            n = 0
            preview = b''
            while chunk := out.read(MIB):
                h.update(chunk)
                n += len(chunk)
                if n <= 32768:
                    preview += chunk
            err.seek(0)
            errors = err.read().decode('utf-8', 'replace')
        event = {'repo': Path(repo).name, 'args': list(args), 'returncode': code,
                 'timeout': timed_out, 'elapsed_seconds': round(time.monotonic() - started, 5),
                 'stdout_bytes': n, 'stdout_sha256': h.hexdigest(),
                 'stdout': preview.decode('utf-8', 'replace') if n <= 32768 else None,
                 'stderr': errors[-16000:], 'sampled_peak_allocated_bytes': peak,
                 'sampling_note': '3ms samples are a lower bound, not exact peak',
                 'interruption': trigger}
        self.events.append(event)
        (self.lab.evidence / 'commands.json').write_text(json.dumps(self.events, indent=2) + '\n')
        if checked:
            require(code == 0 and not timed_out, 'Command failed: ' + errors[-2000:])
        return event

    def fingerprint(self, binary, repo, root, payload_sha, raw, raw_sha, alternate_parent=None):
        def run(*args):
            return self.run(binary, repo, *args, alternate_parent=alternate_parent)
        require(run('cat', root)['stdout_sha256'] == payload_sha, 'Fixture bytes changed')
        require(run('block', 'get', raw)['stdout_sha256'] == raw_sha, 'Raw bytes changed')
        return {'recursive': sorted(run('pin', 'ls', '--type=recursive', '--quiet')['stdout'].splitlines()),
                'direct': sorted(run('pin', 'ls', '--type=direct', '--quiet')['stdout'].splitlines()),
                'mfs': run('files', 'stat', '--hash', '/')['stdout'].strip()}

    def make_seed(self, old, size_mib):
        repo = self.root / 'seed'
        repo.mkdir()
        self.run(old, repo, 'init', '--profile=pebbleds')
        fixture = self.root / 'fixture.bin'
        h = hashlib.sha256()
        with fixture.open('wb') as stream:
            for i in range(size_mib):
                chunk = hashlib.shake_256(('failure-lab-%d' % i).encode()).digest(MIB)
                h.update(chunk)
                stream.write(chunk)
        raw_file = self.root / 'direct.bin'
        raw_file.write_bytes(b'preserve-this-direct-pin\n')
        root = self.run(old, repo, 'add', '-Q', '--cid-version=0', '--raw-leaves=false', str(fixture))['stdout'].strip()
        raw = self.run(old, repo, 'block', 'put', '--cid-codec=raw', str(raw_file))['stdout'].strip()
        self.run(old, repo, 'pin', 'add', '--recursive=false', raw)
        self.run(old, repo, 'files', 'cp', '/ipfs/' + root, '/fixture.bin')
        params = (root, h.hexdigest(), raw, digest(raw_file))
        fp = self.fingerprint(old, repo, *params)
        require(len(fp['direct']) == 1, 'Fixture needs a nonempty direct pin')
        return repo, params, fp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--case', choices=['sigkill', 'enospc', 'missing-sst'], required=True)
    parser.add_argument('--size-mib', type=int, default=64)
    args = parser.parse_args()
    require(16 <= args.size_mib <= 256, 'Bounded fixture sizes only')
    os.umask(0o077)
    require_isolation()
    require(os.getuid() != 0, 'Kubo tests must be unprivileged')
    bins = {k: verify_binary(Path(args.base) / 'bin' / v / 'ipfs', sha) for k, (v, sha) in PINNED.items()}
    x = Experiment(args.base)
    report = {'scope': 'fresh synthetic copies only', 'case': args.case, 'production_approved': False,
              'fault_demonstrated': False, 'restore_verified': False, 'same_copy_recovered': None}
    try:
        seed, params, fp = x.make_seed(bins['old'], args.size_mib)
        sealed = tree_hashes(seed)
        report['seed_apparent_bytes'] = sum(v['size'] for v in file_sizes(seed).values())
        copy = synced_copy(x.lab, seed, 'fault-copy')
        parent = x.root
        filler = None
        if args.case == 'enospc':
            mount = validate_pressure_mount(args.base, Path(args.base) / 'limited')
            pressure = mount / 'fault-copy'
            shutil.copytree(copy, pressure)
            copy, parent = pressure, mount
            filler = mount / 'pressure.bin'
            free = shutil.disk_usage(mount).free
            require(free > MIB, 'Insufficient pressure volume for baseline copy')
            with filler.open('xb') as stream:
                os.posix_fallocate(stream.fileno(), 0, free - 65536)
            report['free_bytes_at_injection'] = shutil.disk_usage(mount).free
        if args.case == 'missing-sst':
            victim = max(copy.glob('pebbleds/*.sst'), key=lambda p: p.stat().st_size)
            report['removed_sst'] = {'path': str(victim.relative_to(copy)), 'bytes': victim.stat().st_size,
                                     'sha256': digest(victim)}
            victim.unlink()
        fault = x.run(bins['bridge'], copy, 'pin', 'ls', '--quiet', timeout=20,
                      kill_during_sst=args.case == 'sigkill', checked=False, alternate_parent=parent)
        if args.case == 'sigkill':
            require(fault['interruption'] is not None and fault['returncode'] == -signal.SIGKILL,
                    'Did not kill an active process after observing a new SST')
        elif args.case == 'enospc':
            require('no space left on device' in fault['stderr'].lower(), 'No observed ENOSPC; reject test')
            require(fault['returncode'] != 0 or fault['timeout'], 'Full filesystem did not interrupt bridge')
        else:
            require(fault['returncode'] != 0 and not fault['timeout'], 'Missing SST did not fail promptly')
            require('sst' in fault['stderr'].lower(), 'Failure not identified as SST related')
        report['fault_demonstrated'] = True
        report['fault'] = fault
        if filler is not None:
            filler.unlink()  # Remove only our explicitly created pressure file.
            report['free_bytes_after_pressure_release'] = shutil.disk_usage(parent).free
        if args.case != 'missing-sst':
            resume = x.run(bins['bridge'], copy, 'pin', 'ls', '--quiet', timeout=90,
                           checked=False, alternate_parent=parent)
            report['resume'] = resume
            if resume['returncode'] == 0 and not resume['timeout']:
                report['same_copy_recovered'] = x.fingerprint(bins['bridge'], copy, *params, alternate_parent=parent) == fp
                require(report['same_copy_recovered'], 'Reopened copy has changed content/pins/MFS')
            else:
                report['same_copy_recovered'] = False
        restored = synced_copy(x.lab, seed, 'restored-old')
        require(x.fingerprint(bins['old'], restored, *params) == fp, 'Untouched-generation restore failed')
        report['restore_verified'] = True
        require(tree_hashes(seed) == sealed, 'Original generation changed')
        report['seed_unchanged'] = True
        report['status'] = 'fault-demonstrated-and-old-generation-restored'
    except Exception as exc:
        report.update(status='failed', error=str(exc))
        raise
    finally:
        (x.lab.evidence / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()

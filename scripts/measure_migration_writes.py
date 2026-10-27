#!/usr/bin/env python3
"""Synthetic-only migration write amplification; local Linux storage, no network.

Primary metric: successful repository-file write syscall return bytes, including
rewrites and files subsequently deleted. Secondary metrics: target /proc IO,
whole changed/new files surviving at phase end, and net repository-size change.
Copy/fixture creation is excluded from migration phases. No cloud-upload claim.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

from kubo_migration_lab import Lab, Refusal, digest, guard_repo, require_isolation, verify_binary

MIB = 1024 ** 2
WRITE_CALLS = {'write', 'pwrite64', 'writev', 'pwritev', 'pwritev2'}
TRACE_CALLS = ','.join(sorted(WRITE_CALLS | {'copy_file_range', 'sendfile', 'splice', 'mmap', 'msync', 'io_uring_enter', 'fsync', 'fdatasync', 'ftruncate', 'truncate', 'fallocate', 'rename', 'renameat', 'renameat2', 'unlink', 'unlinkat'}))


def manifest(root):
    root = Path(root)
    return {str(p.relative_to(root)): {'size': p.stat().st_size,
                                     'allocated': p.stat().st_blocks * 512,
                                     'sha256': digest(p)}
            for p in sorted(root.rglob('*')) if p.is_file()}


def totals(files):
    return {'files': len(files), 'apparent_bytes': sum(v['size'] for v in files.values()),
            'allocated_bytes': sum(v['allocated'] for v in files.values()),
            'sst_bytes': sum(v['size'] for k, v in files.items() if k.endswith('.sst'))}


def changed_files(before, after):
    added = sorted(set(after) - set(before))
    modified = sorted(k for k in set(after) & set(before) if after[k]['sha256'] != before[k]['sha256'])
    removed = sorted(set(before) - set(after))
    return {'added': added, 'modified': modified, 'removed': removed,
            'surviving_new_or_changed_file_bytes': sum(after[k]['size'] for k in added + modified),
            'removed_file_bytes': sum(before[k]['size'] for k in removed),
            'net_apparent_growth_bytes': totals(after)['apparent_bytes'] - totals(before)['apparent_bytes']}


def file_kind(name):
    p = Path(name)
    if p.suffix == '.sst': return 'sst'
    if p.suffix == '.log': return 'wal'
    if p.name.startswith('MANIFEST'): return 'manifest'
    if p.name.startswith('OPTIONS'): return 'options'
    if name.startswith('pebbleds/'): return 'other_pebble'
    return 'repo_metadata'


def completed_calls(lines):
    pending = None
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('--- ', '+++ ')):
            continue
        if '<unfinished ...>' in line:
            if pending is not None:
                raise Refusal('Nested unfinished strace call')
            pending = line.split('<unfinished ...>', 1)[0]
            continue
        if line.startswith('<... '):
            match = re.match(r'<\.\.\. (\w+) resumed>(.*)', line)
            if pending is None or not match or not pending.startswith(match.group(1) + '('):
                raise Refusal('Unmatched resumed strace call')
            line, pending = pending + match.group(2), None
        yield line
    if pending is not None:
        raise Refusal('Incomplete strace: unresolved unfinished call')


def parse_trace(texts, repo):
    prefix = str(Path(repo).resolve()) + '/'
    by_file, by_kind = Counter(), Counter()
    mutators, syncs = Counter(), Counter()
    write_calls = 0
    for text in texts:
        for line in completed_calls(text.splitlines()):
            match = re.match(r'(\w+)\((.*)\)\s+=\s+(-?\d+)', line)
            if not match:
                if re.match(r'(write|pwrite|copy_file_range|sendfile|splice|io_uring_enter)', line):
                    raise Refusal('Cannot parse potential write: ' + line[:200])
                continue
            call, arguments, result = match.group(1), match.group(2), int(match.group(3))
            if result < 0:
                continue
            if call == 'io_uring_enter':
                raise Refusal('Unaccounted asynchronous IO path')
            if call == 'mmap' and 'PROT_WRITE' in arguments and 'MAP_SHARED' in arguments and prefix in arguments:
                raise Refusal('Writable shared repository mmap is not accounted by syscall-byte metric')
            if call in WRITE_CALLS:
                fd = re.match(r'\d+<([^>]+)>', arguments)
                if fd is None:
                    raise Refusal('Successful write without decoded FD path')
                path = fd.group(1)
            elif call in ('copy_file_range', 'sendfile', 'splice'):
                fds = re.findall(r'\d+<([^>]+)>', arguments)
                index = 0 if call == 'sendfile' else 1
                if len(fds) <= index:
                    raise Refusal('Cannot decode copy destination')
                path = fds[index]
            else:
                if prefix in arguments:
                    if call in ('fsync', 'fdatasync'):
                        syncs[call] += 1
                    elif call in ('ftruncate', 'truncate', 'fallocate', 'rename', 'renameat', 'renameat2', 'unlink', 'unlinkat'):
                        mutators[call] += 1
                continue
            path = path.removesuffix(' (deleted)')
            if path.startswith(prefix):
                name = path[len(prefix):]
                by_file[name] += result
                by_kind[file_kind(name)] += result
                write_calls += 1
    return {'repo_write_bytes': sum(by_file.values()), 'repo_write_syscalls': write_calls,
            'bytes_by_file': dict(sorted(by_file.items())), 'bytes_by_kind': dict(sorted(by_kind.items())),
            'sync_calls': dict(syncs), 'non_payload_mutations': dict(mutators)}


def make_fixture(path, size_mib, seed):
    h = hashlib.sha256()
    with Path(path).open('xb') as stream:
        for index in range(size_mib):
            chunk = hashlib.shake_256(('%s:%d' % (seed, index)).encode()).digest(MIB)
            stream.write(chunk)
            h.update(chunk)
    return h.hexdigest()


class Meter:
    def __init__(self, lab):
        self.lab = lab
        self.helper = Path(__file__).with_name('measure_io_child.py').resolve()
        self.counter = 0
        self.phases = []

    def command(self, binary, repo, arguments, traced=False):
        guard_repo(self.lab.root, repo)
        require_isolation()
        self.counter += 1
        stem = '%03d' % self.counter
        report_path = self.lab.evidence / ('child-' + stem + '.json')
        trace_prefix = self.lab.evidence / ('trace-' + stem)
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.lab.root / 'home'), 'IPFS_PATH': str(repo),
               'GOMAXPROCS': '2', 'GOMEMLIMIT': '512MiB', 'LANG': 'C.UTF-8'}
        target = [str(binary)] + list(arguments)
        command = ['/usr/bin/python3', str(self.helper), str(report_path)] + target
        if traced:
            command = ['/usr/bin/strace', '-ff', '-qq', '-yy', '-s', '0', '-e', 'trace=' + TRACE_CALLS,
                       '-o', str(trace_prefix)] + command
        process = subprocess.Popen(command, env=env, cwd=str(self.lab.root), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        try:
            _, errors = process.communicate(timeout=200)
            if process.returncode:
                raise Refusal('Observer failed: ' + errors.decode('utf-8', 'replace')[-2000:])
        finally:
            try:
                os.killpg(process.pid, 0)
            except ProcessLookupError:
                pass
            else:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
                raise Refusal('Observer timed out or left descendants')
        result = json.loads(report_path.read_text())
        if traced:
            paths = sorted(self.lab.evidence.glob(trace_prefix.name + '.*'))
            if not paths:
                raise Refusal('Missing syscall trace')
            result['trace'] = parse_trace([p.read_text() for p in paths], repo)
            for path in paths:
                with path.open('rb') as source, gzip.open(str(path) + '.gz', 'wb') as dest:
                    shutil.copyfileobj(source, dest)
                path.unlink()
        if result['returncode'] != 0:
            raise Refusal('Measured command failed: ' + str(result['stderr']['text']))
        return result

    def kubo(self, binary, repo, *arguments):
        return self.command(binary, repo, ['--offline'] + list(arguments))

    def phase(self, name, binary, repo, commands):
        before = manifest(repo)
        results = [self.command(binary, repo, ['--offline'] + list(args), traced=True) for args in commands]
        after = manifest(repo)
        phase = {'name': name, 'repo_before': totals(before), 'repo_after': totals(after),
                 'file_changes': changed_files(before, after), 'commands': results,
                 'repo_write_bytes': sum(x['trace']['repo_write_bytes'] for x in results),
                 'kernel_write_bytes': sum(x['proc_io']['write_bytes'] for x in results),
                 'kernel_cancelled_write_bytes': sum(x['proc_io']['cancelled_write_bytes'] for x in results)}
        phase['bytes_by_kind'] = dict(sum((Counter(x['trace']['bytes_by_kind']) for x in results), Counter()))
        self.phases.append(phase)
        (self.lab.evidence / 'phases.json').write_text(json.dumps(self.phases, indent=2) + '\n')
        print('PHASE', name, 'repo_write_bytes', phase['repo_write_bytes'], 'kernel_write_bytes', phase['kernel_write_bytes'], flush=True)
        return results

    def calibrate(self):
        repo = self.lab.root / 'calibration'
        repo.mkdir()
        program = ("import os, pathlib; p=pathlib.Path(os.environ['IPFS_PATH']); "
                   "f=os.open(str(p/'x'),os.O_CREAT|os.O_WRONLY,0o600); "
                   "os.write(f,b'a'*1048576); os.pwrite(f,b'b'*524288,0); os.close(f); "
                   "os.rename(p/'x',p/'renamed'); "
                   "f=os.open(str(p/'gone'),os.O_CREAT|os.O_WRONLY,0o600); "
                   "os.write(f,b'c'*131072); os.writev(f,[b'd'*128,b'e'*256]); "
                   "os.close(f); os.unlink(p/'gone'); print('nonrepository stdout')")
        result = self.command('/usr/bin/python3', repo, ['-c', program], traced=True)
        expected = 1048576 + 524288 + 131072 + 128 + 256
        if result['trace']['repo_write_bytes'] != expected:
            raise Refusal('Write meter calibration mismatch')
        if result['proc_io']['wchar'] < expected:
            raise Refusal('Kernel character counter missed calibration writes')
        return {'expected_repo_write_bytes': expected, 'observed_repo_write_bytes': result['trace']['repo_write_bytes'],
                'includes_overwrites_and_deleted_files': True, 'stdout_excluded': True}


def text(result):
    value = result['stdout']['text']
    if value is None:
        raise Refusal('Expected bounded text output')
    return value.strip()


def fingerprint(results):
    return {'payload_sha256': results[0]['stdout']['sha256'], 'payload_bytes': results[0]['stdout']['bytes'],
            'direct_payload_sha256': results[1]['stdout']['sha256'], 'unpinned_payload_sha256': results[2]['stdout']['sha256'],
            'recursive_pins': sorted(text(results[3]).splitlines()), 'direct_pins': sorted(text(results[4]).splitlines()),
            'mfs_root': text(results[5])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    parser.add_argument('--size-mib', type=int, choices=(16, 64, 256, 1024), required=True)
    parser.add_argument('--replicate', type=int, choices=(1, 2), required=True)
    for key in ('old', 'bridge', 'target'):
        parser.add_argument('--' + key, required=True)
        parser.add_argument('--' + key + '-sha256', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    require_isolation()
    bins = {key: verify_binary(getattr(args, key), getattr(args, key + '_sha256')) for key in ('old', 'bridge', 'target')}
    lab = Lab(args.base)
    if shutil.disk_usage(lab.root).free < (args.size_mib * MIB * 8 + 2 * 1024 ** 3):
        raise Refusal('Insufficient independent-copy and compaction headroom')
    meter = Meter(lab)
    report = {'scope': 'synthetic-local-pebbleds-only', 'production_approved': False,
              'size_mib': args.size_mib, 'replicate': args.replicate, 'phases': meter.phases,
              'metric': 'successful repository-file write/writev/pwrite/copy syscall return bytes',
              'exclusions': ['fixture creation', 'cloning and rollback copies', 'observer logs', 'stdout/stderr pipes', 'filesystem journal', 'device firmware writes', 'cloud transfers'],
              'strace_version': subprocess.check_output(['/usr/bin/strace', '-V'], text=True).splitlines()[0],
              'kernel': os.uname().release, 'binary_sha256': {k: digest(v) for k, v in bins.items()}}
    print('EVIDENCE=' + str(lab.evidence), flush=True)
    try:
        report['calibration'] = meter.calibrate()
        repo = lab.root / 'seed'
        repo.mkdir()
        for key, version in [('old', '0.31.0'), ('bridge', '0.34.1'), ('target', '0.43.1')]:
            if text(meter.kubo(bins[key], repo, 'version', '--number')) != version:
                raise Refusal('Unexpected binary version')
        meter.kubo(bins['old'], repo, 'init', '--profile=pebbleds')
        source = lab.root / 'fixture.bin'
        expected_hash = make_fixture(source, args.size_mib, 'fixture-%d' % args.replicate)
        root = text(meter.kubo(bins['old'], repo, 'add', '-Q', '--cid-version=0', '--raw-leaves=false', str(source)))
        raw_path = lab.root / 'direct.bin'
        raw_path.write_bytes(b'nonempty-direct-pin-fixture')
        direct = text(meter.kubo(bins['old'], repo, 'block', 'put', '--cid-codec=raw', str(raw_path)))
        meter.kubo(bins['old'], repo, 'pin', 'add', '--recursive=false', direct)
        unpinned_path = lab.root / 'unpinned.bin'
        unpinned_path.write_bytes(b'independent-unpinned-block-fixture')
        unpinned = text(meter.kubo(bins['old'], repo, 'block', 'put', '--cid-codec=raw', str(unpinned_path)))
        meter.kubo(bins['old'], repo, 'files', 'cp', '/ipfs/' + root, '/fixture.bin')
        checks = [('cat', root), ('block', 'get', direct), ('block', 'get', unpinned),
                  ('pin', 'ls', '--type=recursive', '--quiet'), ('pin', 'ls', '--type=direct', '--quiet'), ('files', 'stat', '--hash', '/')]
        baseline = fingerprint([meter.kubo(bins['old'], repo, *cmd) for cmd in checks])
        if baseline['payload_sha256'] != expected_hash or baseline['payload_bytes'] != args.size_mib * MIB:
            raise Refusal('Seed data mismatch')
        if baseline['direct_pins'] != [direct]:
            raise Refusal('Nonempty direct-pin fixture missing')
        sealed = manifest(repo)
        denominator = totals(sealed)['apparent_bytes']
        report['baseline'] = {'fixture_sha256': expected_hash, 'fingerprint': baseline, 'repo': totals(sealed),
                              'denominator_bytes': denominator, 'denominator_definition': 'sum of all regular file lengths in closed original Kubo repo'}
        control = lab.clone(repo, 'old-control')
        meter.phase('old_reopen_control', bins['old'], control, [checks[3]])
        working = lab.clone(repo, 'working')
        identity = json.loads((working / 'config').read_text())['Identity']
        datastore = json.loads((working / 'config').read_text())['Datastore']
        disk_spec = digest(working / 'datastore_spec')
        meter.phase('bridge_first_open', bins['bridge'], working, [checks[3]])
        report['bridge_markers'] = [p.name for p in working.rglob('*format-version*')]
        if (working / 'version').read_text().strip() != '16': raise Refusal('Wrong bridge repo version')
        meter.phase('schema_16_to_18', bins['target'], working, [('repo', 'migrate', '--to=18')])
        conf = json.loads((working / 'config').read_text())
        if (working / 'version').read_text().strip() != '18' or conf['Identity'] != identity or conf['Datastore'] != datastore or digest(working / 'datastore_spec') != disk_spec:
            raise Refusal('Schema migration invariant failed')
        meter.phase('target_first_open', bins['target'], working, [checks[3]])
        report['target_markers'] = [p.name for p in working.rglob('*format-version*')]
        acceptance = fingerprint(meter.phase('target_read_acceptance', bins['target'], working, checks))
        if acceptance != baseline:
            raise Refusal('Target data/pins/MFS mismatch')
        meter.phase('target_reopen_control', bins['target'], working, [checks[3]])
        extra = lab.root / 'extra.bin'
        extra_hash = make_fixture(extra, 1, 'new-target-write-%d' % args.replicate)
        written = meter.phase('target_new_1mib', bins['target'], working, [('block', 'put', '--cid-codec=raw', str(extra))])
        new_cid = text(written[0])
        readback = meter.phase('target_new_readback', bins['target'], working, [('block', 'get', new_cid)])[0]
        if readback['stdout']['sha256'] != extra_hash or readback['stdout']['bytes'] != MIB:
            raise Refusal('Target new write/reopen mismatch')
        rollback = lab.clone(repo, 'rollback-control')
        if fingerprint([meter.kubo(bins['old'], rollback, *cmd) for cmd in checks]) != baseline:
            raise Refusal('Old generation restore mismatch')
        if manifest(repo) != sealed:
            raise Refusal('Sealed original changed')
        migration_names = {'bridge_first_open', 'schema_16_to_18', 'target_first_open'}
        migration = sum(x['repo_write_bytes'] for x in meter.phases if x['name'] in migration_names)
        validation = sum(x['repo_write_bytes'] for x in meter.phases if x['name'] == 'target_read_acceptance')
        report.update(status='passed', migration_repo_write_bytes=migration,
                      migration_mib_written_per_mib_repo=migration / denominator,
                      migration_plus_acceptance_mib_per_mib=(migration + validation) / denominator,
                      migration_surviving_changed_file_bytes=sum(x['file_changes']['surviving_new_or_changed_file_bytes'] for x in meter.phases if x['name'] in migration_names),
                      target_content_pins_mfs_verified=True, target_new_write_verified=True,
                      old_generation_restore_verified=True, original_unchanged=True)
    except BaseException as exc:
        report.update(status='failed', error=str(exc))
        raise
    finally:
        (lab.evidence / 'write-report.json').write_text(json.dumps(report, indent=2) + '\n')
        summary = {k: v for k, v in report.items() if k not in ('phases', 'baseline')}
        if 'baseline' in report: summary['baseline_repo'] = report['baseline']['repo']
        print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()

"""Reclaim or restore one certified historical staging directory on the Rhea disposable clone.

Both operations take the checkpoint writer lock. The recovery plan and metadata remain on
Rhea. The retired directory keeps the original inodes and hard links. Restore downloads
their pinned versions before making the original directory visible again.
"""
import argparse
import contextlib
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile

if __name__ == '__main__':
    sys.path.insert(0, '/root/.local/share/rhea-clone-batch-runner-4g-v1/scripts')

import rhea_clone_batch_runner as r

require = r.c.require
CHUNK = 1024 * 1024


def file_hash(stream):
    value = hashlib.sha256()
    for block in iter(lambda: stream.read(CHUNK), b''):
        value.update(block)
    return value.hexdigest()


def allocation(path):
    return int(subprocess.check_output(['du', '-sx', '-B1', '--', str(path)], text=True).split()[0])


def available(path):
    fs = os.statvfs(path)
    return fs.f_bavail * fs.f_frsize


def sync_dir(path):
    with r.host.c_dir(path) as directory:
        os.fsync(directory)


def seal_plan(path, plan):
    """A crash must leave either a complete recovery plan or the original files."""
    raw = r.c.canonical(plan)
    fd, temp_name = tempfile.mkstemp(dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        rename_unused(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    sync_dir(path.parent)
    require(r.host.read(path) == plan, 'recovery plan readback differs')


def rename_unused(source, destination):
    # Linux RENAME_NOREPLACE also protects an existing empty directory.
    rename = ctypes.CDLL(None, use_errno=True).renameat2
    if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def move_stage(source, destination):
    rename_unused(source, destination)
    sync_dir(source.parent)
    sync_dir(destination.parent)


def idle_tree(path):
    """Check the root-owned local directory before detaching, modifying or reattaching it."""
    with r.a.protected_directory(path, private=True):
        pass
    dev = path.stat().st_dev
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        for field in line.split()[3:5]:
            require(field != str(path) and not field.startswith(str(path) + '/'), 'staging tree is mounted')
    for p in path.rglob('*'):
        st = p.lstat()
        metadata = path/'writer/metadata'
        owner = 65534 if p == metadata or p.parent == metadata else 0
        require(st.st_dev == dev and st.st_uid == st.st_gid == owner and not st.st_mode & 0o022
                and (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)), 'unexpected staging entry: ' + str(p))
    use = subprocess.run(['/usr/bin/lsof', '-nP', '-t', '+D', str(path)], capture_output=True, timeout=90)
    require(use.returncode == 1 and not use.stdout and not use.stderr, 'open staging user or incomplete lsof inspection')


def metadata_digest(stage, payload_paths):
    entries = []
    for p in sorted(stage.rglob('*')):
        if p in payload_paths:
            continue
        st = p.lstat()
        digest = None
        if stat.S_ISREG(st.st_mode):
            require(st.st_nlink == 1, 'unexpected link to local recovery metadata')
            with p.open('rb') as stream:
                digest = file_hash(stream)
        entries.append([p.relative_to(stage).as_posix(), st.st_mode, st.st_uid, st.st_gid, st.st_mtime_ns, digest])
    return r.c.digest(entries)


def historical(head, generation):
    require(type(generation) is int and 15 <= generation < head['generation'], 'select a certified historical generation')


def credentials_pool(rows, operation):
    with contextlib.ExitStack() as stack:
        clients = [stack.enter_context(r.admin_reader()) for _ in range(min(4, len(rows)))]
        return r.bulk.map_ssts(rows, clients, operation)


def fetch_version(client, name, pin, destination):
    response = client.get_object(Bucket=r.iam.BUCKET, Key=r.proof.PREFIX + name, VersionId=pin['version_id'])
    with contextlib.closing(response['Body']) as body:
        require((response.get('VersionId'), response.get('ETag'), response.get('ContentLength')) ==
                (pin['version_id'], pin['etag'], pin['size']), 'versioned GET identity differs: ' + name)
        total = 0
        digest = hashlib.sha256()
        for block in iter(lambda: body.read(CHUNK), b''):
            total += len(block)
            require(total <= pin['size'], 'versioned GET exceeds sealed size: ' + name)
            digest.update(block)
            destination.write(block)
    require(total == pin['size'] and digest.hexdigest() == pin['sha256'], 'versioned GET bytes differ: ' + name)
    destination.flush()
    destination.seek(0)
    require(file_hash(destination) == pin['sha256'], 'downloaded recovery file differs: ' + name)
    destination.seek(0)
    return total


def identity(st):
    return [st.st_dev, st.st_ino, st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), st.st_nlink]


@contextlib.contextmanager
def open_table(path, record, write=False):
    flags = os.O_RDWR if write else os.O_RDONLY
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NOATIME)
    with os.fdopen(fd, 'r+b' if write else 'rb') as f:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and identity(st) == record['identity'], 'staging file identity changed')
        yield f


def check_local(path, record, *, empty_ok=False):
    with open_table(path, record) as stream:
        size = os.fstat(stream.fileno()).st_size
        if size == 0 and empty_ok:
            return False
        require(size == record['pin']['size'] and file_hash(stream) == record['pin']['sha256'],
                'cached SST bytes differ: ' + path.name)
        return True


def write_restored(path, record, source):
    with open_table(path, record, write=True) as f:
        f.seek(0)
        shutil.copyfileobj(source, f, CHUNK)
        f.truncate()
        f.flush()
        os.utime(f.fileno(), ns=(record['atime_ns'], record['mtime_ns']))
        os.fsync(f.fileno())
    check_local(path, record)


class Stage:
    """Use under the installed clone runner's exclusive writer lock."""
    def __init__(self, generation, expected_head, expected_certificate):
        self.generation = generation
        self.release, self.worker = r.release()
        self.head, self.current = r.read_head()
        require(self.head['sha256'] == expected_head, 'live checkpoint differs from requested head')
        historical(self.head, generation)
        self.reader = r.h.reader(True)
        self.production = r.guard(self.reader)
        self.assert_idle()
        number = f'{generation:06d}'
        self.state = r.ROOT / number
        self.original = r.host.BATCH_DATA / number
        self.retired = r.host.BATCH_DATA / 'retired' / number
        self.journal = r.ROOT / 'stage-reclamation' / number
        cert = self.current
        for gen in range(self.head['generation'], generation, -1):
            prev = r.host.read(r.ROOT / f'{gen-1:06d}' / 'checkpoint.json')
            require(prev['generation'] == gen-1 and r.c.digest(prev) == cert['previous_checkpoint_sha256'],
                    'broken checkpoint ancestry')
            cert = prev
        self.certificate = r.c.digest(cert)
        require(self.certificate == expected_certificate and r.host.read(self.state/'completed.json')['sha256'] == self.certificate,
                'selected certificate differs')
        r.bulk.predecessor(cert, self.certificate)
        parent = r.host.read(r.ROOT / f'{generation-1:06d}' / 'checkpoint.json')
        _, _, old, _ = r.proof.ledger_context(parent, cert['previous_checkpoint_sha256'])
        writer = r.host.read(self.state/'writer-closed.json')['report']
        require(r.c.digest(writer) == cert['go_report_sha256'], 'certified writer report differs')
        inputs = {row['name']: old[row['name']] for row in writer['sst_diff']['retired']}
        outputs = cert['created_sst_versions']
        require(inputs and outputs and not inputs.keys() & outputs.keys() and
                outputs.keys() == {row['name'] for row in writer['sst_diff']['created']}, 'unexpected SST delta')
        self.pins = {**inputs, **outputs}
        self.outputs = outputs
        fs = r.host.read(self.state/'writer-launch.json')['mount']['fs']
        label, remote = fs.rstrip('/').split(':')
        require(label.startswith('iam_writer') and '/' not in label and remote == r.iam.BUCKET+'/'+r.iam.PREFIX.rstrip('/'),
                'unexpected quarantined backend')
        self.relative = Path('writer/quarantined-cache/vfs') / label / remote
        self.meta = Path('writer/quarantined-cache/vfsMeta') / label / remote
        qu = r.host.read(self.state/'quarantine.json')
        require(qu['stopped'] and qu['no_rc_socket'] and qu['cache'] == str(self.original/'writer/quarantined-cache'),
                'writer quarantine differs')
        r.host.mkdir(self.journal.parent)
        r.host.mkdir(self.journal)
        r.host.mkdir(self.retired.parent)

    def assert_idle(self):
        next_name = f"{self.head['generation']+1:06d}"
        require(not (r.ROOT/next_name).exists() and not (r.host.BATCH_DATA/next_name).exists()
                and not r.h.main_pid(r.host.UNIT) and not r.h.main_pid('rhea-clone-batch-'+next_name),
                'another clone operation is pending')
        require(r.read_head()[0] == self.head and r.guard(r.h.reader(True)) == self.production, 'clone or production changed')

    def location(self):
        source = os.path.lexists(self.original)
        retired = os.path.lexists(self.retired)
        require(source != retired, 'ambiguous historical staging location')
        return self.original if source else self.retired

    def plan(self, stage):
        idle_tree(stage)
        require((stage/'writer/cache').read_bytes() == b'QUARANTINED - never reuse this cache\n' and
                not os.path.lexists(stage/'writer/runtime/rc.sock'), 'staging cache is active or unsealed')
        data = stage / self.relative
        meta = stage / self.meta
        closed = stage / 'closed-payloads'
        require({p.name for p in data.iterdir()} == {p.name for p in meta.iterdir()} == self.pins.keys()
                and {p.name for p in closed.iterdir()} == self.outputs.keys(), 'staging payload set differs')
        require(r.proof.physical_metadata(stage/'writer/metadata') == r.proof.physical_metadata(self.state/'closed-metadata'),
                'local writer metadata differs from the certified snapshot')
        meta_sha = metadata_digest(stage, {data/n for n in self.pins} | {closed/n for n in self.outputs})
        path = self.journal/'recovery.json'
        saved = r.host.read(path) if path.exists() else None
        require(saved is not None or stage == self.original, 'detached staging is missing its recovery plan')
        if saved:
            require(saved['schema'] == 1 and saved['generation'] == self.generation and saved['certificate_sha256'] == self.certificate
                    and saved['data_path'] == self.relative.as_posix() and saved['tables'].keys() == self.pins.keys()
                    and saved['metadata_sha256'] == meta_sha,
                    'recovery plan binding differs')
        rows = {}
        for name, pin in sorted(self.pins.items()):
            require(r.proof.p.base.SST_NAME.fullmatch(name) and pin['size'] > 0, 'invalid SST identity')
            output = name in self.outputs
            file = data/name
            st = file.lstat()
            require(stat.S_ISREG(st.st_mode) and identity(st)[2:] == [0, 0, 0o600, 2 if output else 1]
                    and (not output or os.path.samefile(file, closed/name)), 'unexpected payload links: ' + name)
            journal = json.loads((meta/name).read_bytes())
            require(journal['Dirty'] is output and journal['Size'] == pin['size']
                    and journal['Rs'] == [dict(Pos=0, Size=pin['size'])], 'VFS range or dirty state differs: ' + name)
            if saved:
                record = saved['tables'][name]
                require(all(record['pin'].get(k) == v for k,v in pin.items()) and record['identity'] == identity(st)
                        and record['output'] is output, 'stored pin or inode differs: ' + name)
            else:
                require(st.st_size == pin['size'], 'wrong intact cache size: ' + name)
                record = dict(output=output, identity=identity(st), atime_ns=st.st_atime_ns, mtime_ns=st.st_mtime_ns)
                with open_table(file, record) as f:
                    digest = file_hash(f)
                require(pin.get('sha256', digest) == digest, 'certified file hash differs: ' + name)
                record['pin'] = dict(pin, sha256=digest)
            rows[name] = record
        require(len({tuple(row['identity'][:2]) for row in rows.values()}) == len(rows), 'different keys share an inode')
        return dict(schema=1, generation=self.generation, certificate_sha256=self.certificate,
                    data_path=self.relative.as_posix(), metadata_sha256=meta_sha, tables=rows)

    def reclaim(self):
        self.assert_idle()
        stage = self.location()
        plan = self.plan(stage)
        rows = plan['tables']
        intact = {n for n,row in rows.items() if check_local(stage/self.relative/n, row, empty_ok=stage == self.retired)}
        if not intact:
            return dict(action='already reclaimed', pinned_bytes_read=0, allocated_bytes=allocation(stage))
        before = allocation(stage)

        def verify(client, name, row):
            with tempfile.TemporaryFile(dir=self.journal) as spool:
                return fetch_version(client, name, row['pin'], spool)
        downloaded = credentials_pool(rows, verify)
        path = self.journal/'recovery.json'
        if not path.exists():
            seal_plan(path, plan)
        require(r.host.read(path) == plan, 'durable recovery plan differs')
        self.assert_idle()
        idle_tree(stage)
        if stage == self.original:
            move_stage(stage, self.retired)
        free_before = available(self.retired)
        for name in sorted(intact):
            row = rows[name]
            with open_table(self.retired/self.relative/name, row, write=True) as f:
                require(file_hash(f) == row['pin']['sha256'], 'detached file changed: ' + name)
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())
        require(all(not check_local(self.retired/self.relative/n, row, empty_ok=True) for n,row in rows.items()),
                'an SST still has allocated payload')
        self.assert_idle()
        after = allocation(self.retired)
        return dict(action='reclaimed', recovery_sha256=r.c.digest(plan), pinned_bytes_read=sum(downloaded.values()),
                    allocated_before=before, allocated_after=after, released_bytes=before-after,
                    free_before=free_before, free_after=available(self.retired))

    def restore(self):
        self.assert_idle()
        stage = self.location()
        require((self.journal/'recovery.json').is_file(), 'no durable recovery plan')
        plan = self.plan(stage)
        rows = plan['tables']
        if stage == self.original:
            for n,row in rows.items():
                check_local(stage/self.relative/n, row)
            return dict(action='already restored', pinned_bytes_read=0)

        def restore_one(client, name, row):
            file = self.retired/self.relative/name
            with open_table(file, row) as stream:
                if os.fstat(stream.fileno()).st_size == row['pin']['size'] and file_hash(stream) == row['pin']['sha256']:
                    os.utime(stream.fileno(), ns=(row['atime_ns'], row['mtime_ns']))
                    return 0
            with tempfile.TemporaryFile(dir=self.journal) as spool:
                n = fetch_version(client, name, row['pin'], spool)
                write_restored(file, row, spool)
                return n
        downloaded = credentials_pool(rows, restore_one)
        for n,row in rows.items():
            file = self.retired/self.relative/n
            check_local(file, row)
            require(file.stat().st_mtime_ns == row['mtime_ns'] and
                    (not row['output'] or os.path.samefile(file, self.retired/'closed-payloads'/n)), 'restored metadata differs')
        self.assert_idle()
        idle_tree(self.retired)
        move_stage(self.retired, self.original)
        return dict(action='restored', pinned_bytes_read=sum(downloaded.values()), files=len(rows),
                    allocated_bytes=allocation(self.original), recovery_sha256=r.c.digest(plan))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('reclaim', 'restore'))
    parser.add_argument('generation', type=int)
    parser.add_argument('--head', required=True, help='expected current certified head SHA-256')
    parser.add_argument('--certificate', required=True, help='expected historical checkpoint SHA-256')
    args = parser.parse_args()
    require(os.geteuid() == 0 and sys.flags.isolated and sys.dont_write_bytecode, 'use root python3 -I -B on Rhea')
    os.umask(0o077)
    with r.prep.writer_lock():
        stage = Stage(args.generation, args.head, args.certificate)
        result = stage.reclaim() if args.action == 'reclaim' else stage.restore()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()

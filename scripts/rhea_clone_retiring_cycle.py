"""Time one signed clone checkpoint and reclaim an explicitly chosen stage after certification."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import threading
import time

RECLAIMER_SHA = 'cdc955270f65d47bc358dd5f7075a868ab7922878c0e22357f9f12b81d76a3eb'
RECLAIMER_DIR = Path('/root/.local/share/rhea-clone-stage-tools') / RECLAIMER_SHA
RUNNER_DIR = Path('/root/.local/share/rhea-clone-batch-runner-4g-v1/scripts')

if __name__ == '__main__':
    if os.geteuid() != 0 or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise SystemExit('run with root python3 -I -B')
    if hashlib.sha256((RECLAIMER_DIR/'rhea_clone_stage_reclaim.py').read_bytes()).hexdigest() != RECLAIMER_SHA:
        raise SystemExit('installed reclamation tool differs')
    sys.path[:0] = [str(RECLAIMER_DIR), str(RUNNER_DIR)]
import rhea_clone_stage_reclaim as stage

r = stage.r
require = r.c.require


def space():
    root = r.host.BATCH_DATA
    require(root.stat().st_dev == r.ROOT.stat().st_dev, 'staging and checkpoint journal are on different filesystems')
    return dict(staging_bytes=stage.allocation(root), journal_bytes=stage.allocation(r.ROOT),
                available_bytes=stage.available(root))


class FreeSpaceSamples:
    def __init__(self):
        self.count = 0
        self.minimum = None
        self.max_gap = 0
        self.last = None
        self.error = None

    def sample(self):
        now = time.monotonic_ns()
        free = stage.available(r.host.BATCH_DATA)
        self.minimum = free if self.minimum is None else min(self.minimum, free)
        if self.last is not None:
            self.max_gap = max(self.max_gap, now - self.last)
        self.count += 1
        self.last = now

    @contextlib.contextmanager
    def running(self):
        stop = threading.Event()
        def collect():
            try:
                while not stop.wait(2):
                    self.sample()
            except Exception as error:
                self.error = type(error).__name__
        self.sample()
        worker = threading.Thread(target=collect, daemon=True)
        worker.start()
        try:
            yield
        finally:
            stop.set()
            worker.join()
            self.sample()


def has_successor(head, intent):
    if head == intent['parent']:
        return False
    require(head['generation'] == intent['generation'] and
            head['previous_checkpoint_sha256'] == intent['parent']['sha256'], 'head left the selected checkpoint')
    return True


def arm(folder, request):
    path = folder/'armed.json'
    if path.exists():
        intent = r.host.read(path)
        require(intent['request'] == request, 'a different retirement was armed for this checkpoint')
        return intent
    with r.prep.writer_lock():
        head, cert = r.read_head()
        generation, historical = request['generation'], request['retire']
        require(generation == head['generation'] + 1 and head['sha256'] == request['parent'] and
                15 <= historical <= head['generation'], 'select the exact successor and a certified stage')
        new = f'{generation:06d}'
        old = f'{historical:06d}'
        require(not (r.ROOT/new).exists() and not (r.host.BATCH_DATA/new).exists(), 'checkpoint has already started')
        previous = r.host.read(r.ROOT/old/'checkpoint.json')
        r.bulk.predecessor(previous, request['certificate'])
        require(r.host.read(r.ROOT/old/'completed.json')['sha256'] == request['certificate'] and
                (r.host.BATCH_DATA/old).is_dir() and not os.path.lexists(r.host.BATCH_DATA/'retired'/old),
                'selected staging is missing or already retired')
        prod = r.guard(r.h.reader(True))
        release, worker = r.release()
        before = space()
        require(before['available_bytes'] >= cert['limits']['minimum_free_bytes'], 'disk reserve already reached')
        intent = dict(request=request, generation=generation, parent=head, release=release, worker=worker,
                      production_sha256=r.c.digest(prod), reserve=cert['limits']['minimum_free_bytes'],
                      marked_before=cert['marked_after'], target_stage_bytes=stage.allocation(r.host.BATCH_DATA/old),
                      before=before, armed_ns=time.time_ns(), boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        stage.seal_plan(path, intent)
        return intent


def observe_successor(intent):
    unit = f"rhea-clone-batch-{intent['generation']:06d}"
    started = r.ROOT / f"{intent['generation']:06d}" / 'writer-launch.json'
    while True:
        head = r.host.read(r.ROOT/'HEAD.json')
        if has_successor(head, intent) or started.exists():
            state = r.h.output(['/usr/bin/systemctl', 'show', '--value', '-p', 'ActiveState', unit])
            if state in ('inactive', 'failed'):
                require(has_successor(r.host.read(r.ROOT/'HEAD.json'), intent),
                        'checkpoint stopped before certification')
                require(state == 'inactive', 'checkpoint service failed during shutdown')
                return
        time.sleep(2)


def reclaim(folder, intent):
    head, cert = r.read_head()
    require(has_successor(head, intent) and r.release() == (intent['release'], intent['worker']),
            'signed checkpoint or release changed')
    selected = intent['request']
    s = stage.Stage(selected['retire'], head['sha256'], selected['certificate'])
    require(r.c.digest(s.production) == intent['production_sha256'] and cert['remote_generation_verified'] and
            cert['pebble_reopen_verified'] and cert['reopen']['io']['sst_write_bytes'] == 0 and
            cert['reopen']['io']['metadata_write_bytes'] == 0, 'successor or production verification differs')
    tmp = folder/'ready.json'
    if not tmp.exists():
        require(s.location() == s.original and stage.allocation(s.original) == intent['target_stage_bytes'],
                'selected stage changed before the checkpoint finished')
        stage.seal_plan(tmp, dict(head=head, space=space(), retirement_start_ns=time.time_ns()))
    ready = r.host.read(tmp)
    require(ready['head'] == head, 'retirement was prepared for a different head')
    result = s.reclaim()
    require(s.location() == s.retired and not os.path.lexists(s.original), 'historical staging is still attached')
    recovery = r.host.read(s.journal/'recovery.json')
    require(recovery['certificate_sha256'] == s.certificate and recovery['generation'] == s.generation and
            recovery['tables'].keys() == s.pins.keys(), 'recovery plan differs')
    for name, row in recovery['tables'].items():
        st = (s.retired/s.relative/name).lstat()
        require(st.st_size == st.st_blocks == 0 and stage.identity(st) == row['identity'], 'retired payload still allocated')
    remaining = stage.allocation(s.retired)
    require(remaining < intent['target_stage_bytes'], 'no space was released')
    s.assert_idle()
    return dict(head=head, ready=ready, last_reclaim=result, target_stage_bytes_after=remaining,
                recovery_sha256=r.c.digest(recovery), payload_count=len(s.pins), output_count=len(s.outputs),
                selected_version_bytes=sum(p['size'] for p in s.pins.values()), after=space(), finished_ns=time.time_ns())


def run(request):
    parent = r.ROOT.parent/'rhea-clone-retiring-cycles'
    folder = parent/f"{request['generation']:06d}"
    r.host.mkdir(parent)
    r.host.mkdir(folder)
    # The observer has its own lock. The checkpoint writer needs its lock during the wait.
    fd = os.open(folder/'observer.lock', os.O_CREAT | os.O_NOFOLLOW | os.O_RDWR, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        intent = arm(folder, request)
        out = folder/'completed.json'
        if out.exists():
            result = r.host.read(out)
            require(result['intent_sha256'] == r.c.digest(intent), 'completed cycle differs from its intent')
            return result
        samples = FreeSpaceSamples()
        observed_ns = time.time_ns()
        with samples.running():
            print('ARMED', r.c.digest(intent), flush=True)
            observe_successor(intent)
            print('CERTIFIED', intent['generation'], 'retiring', request['retire'], flush=True)
            # A read-only health command or ExecStopPost can briefly own the writer lock.
            with contextlib.ExitStack() as stack:
                while True:
                    try:
                        stack.enter_context(r.prep.writer_lock())
                        break
                    except BlockingIOError:
                        time.sleep(1)
                measured = reclaim(folder, intent)
        coverage = dict(count=samples.count, minimum_available_bytes=samples.minimum, max_gap_ns=samples.max_gap,
                        first_observation_ns=observed_ns, error=samples.error,
                        boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
        result = dict(schema=1, intent_sha256=r.c.digest(intent), intent=intent, disk_samples=coverage, **measured)
        stage.seal_plan(out, result)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('generation', type=int)
    parser.add_argument('--parent', required=True, help='expected current certified head SHA-256')
    parser.add_argument('--retire', required=True, type=int, help='specific staging generation to release')
    parser.add_argument('--certificate', required=True, help='expected retirement target certificate SHA-256')
    args = parser.parse_args()
    require(16 <= args.generation <= 999999 and 15 <= args.retire < args.generation, 'invalid generation selection')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    result = run(vars(args))
    print(json.dumps(dict(head=result['head'], recovery_sha256=result['recovery_sha256'],
                          receipt_sha256=r.c.digest(result)), sort_keys=True), flush=True)

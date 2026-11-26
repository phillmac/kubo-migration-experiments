"""Controller-side protocol for one already-launched generation-14 child.

The signed host adapter owns the writer lock, mount, child launch and locked
append-only journal. Only the parent persists Go records. A denied or
disconnected child is allowed to close and is never relaunched here.
"""
import base64
import hashlib
import os
import socket
import stat
import subprocess
from pathlib import Path
import re
import select
import time

import rhea_multi_sst_checkpoint_controller as c
from rhea_multi_sst_signed_admission import ANCHOR

RECORD = re.compile(r'(?:pending|closed|unit-00[12]-(?:intent|receipt|failed))\.json')
MAX_FRAME = 1 << 20


def child_identity(pid):
    proc = Path('/proc') / str(pid)
    with (proc / 'exe').open('rb') as binary:
        sha = hashlib.file_digest(binary, 'sha256').hexdigest()
    return c.process_tuple(dict(pid=pid, start_ticks=int((proc / 'stat').read_text().rsplit(')', 1)[1].split()[19]),
                                exe_sha256=sha, boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()))


def supervise(proc, sock, intent, journal, monitor, health, *, clock=time.monotonic):
    """Return the controller writer receipt only after actual exit and closed-file validation."""
    request = intent['request']
    records = {}
    identity = final = failure = None
    buffer = bytearray()
    sequence, next_check = 0, 0

    def check(force=False):
        nonlocal failure, next_check
        if failure is None and (force or clock() >= next_check):
            try:
                monitor()
                next_check = clock() + 0.5
            except Exception as exc:
                failure = exc

    try:
        while True:
            check()
            if not select.select([sock], [], [], 0.25)[0]:
                continue
            data = sock.recv(65536)
            if not data:
                c.require(not buffer, 'partial writer frame at EOF')
                break
            buffer.extend(data)
            c.require(len(buffer) <= MAX_FRAME, 'oversized writer frame')
            if b'\n' not in buffer:
                continue
            c.require(buffer.endswith(b'\n') and buffer.count(b'\n') == 1, 'writer sent pipelined frames')
            msg = c.parse(bytes(buffer))
            buffer.clear()
            sequence += 1
            kind = msg['kind']
            c.require(type(msg['seq']) is int and msg['seq'] == sequence and final is None,
                      'out-of-order writer event')
            ack = dict(seq=sequence, allow=False)
            if sequence == 1:
                c.require(kind == 'ready' and set(msg) == {'seq', 'kind'}, 'missing writer handshake')
                identity = child_identity(proc.pid)
                c.require(identity['exe_sha256'] == intent['go_binary_sha256'] and
                          identity['boot_id'] == intent['reader_identity']['boot_id'], 'child executable or boot differs')
                check(True)
                if failure is None:
                    ack.update(allow=True, request=request)
            elif kind == 'check':
                c.require(set(msg) == {'seq','kind','value'} and type(msg['value']) is int
                          and 0 <= msg['value'] <= 512 << 20, 'invalid writer operation size')
                check()
                ack['allow'] = failure is None
            elif kind == 'record':
                name = msg.get('name')
                c.require(set(msg) == {'seq','kind','name','value'} and isinstance(name, str)
                          and RECORD.fullmatch(name) and name not in records, 'invalid or repeated writer journal record')
                if name == 'pending.json' or name.endswith('-intent.json'):
                    check(True)
                recovery = name in ('closed.json',) or name.endswith(('-receipt.json', '-failed.json'))
                if failure is None or recovery:
                    if name == 'pending.json':
                        c.require(msg['value'] == dict(schema=c.verifier.WRITER_SCHEMA, phase='executing', request=request),
                                  'writer pending request differs')
                    journal.put(name, msg['value'])
                    records[name] = base64.b64encode(journal.read(name)).decode('ascii')
                    if name.endswith('-intent.json'):
                        next_check = 0
                    ack['allow'] = True
            elif kind == 'finished':
                c.require(set(msg) == {'seq','kind','value'} and type(msg['value']) is dict, 'invalid final writer report')
                final = msg['value']
                ack['allow'] = True
            else:
                raise c.Refusal('unknown writer event')
            sock.sendall(c.canonical(ack))
    finally:
        sock.close()
        # Closing the socket revokes every later write check. Keep the child
        # and its journal intact while Pebble attempts its normal close.
        proc.wait()
    if failure is not None:
        raise c.Refusal('writer monitor revoked the batch') from failure
    c.require(final is not None and identity is not None and proc.returncode == 0, 'incomplete writer exit or report')
    check(True)
    c.require(failure is None, 'final host check failed')
    receipt = dict(report=final, go_files=records, source_process=identity, binary_sha256=identity['exe_sha256'],
                   exit_code=proc.returncode, stopped=True, monitor_complete=True, health=health())
    c.validate_closed(receipt, intent)
    return receipt


def run_go_monitored(controller, journal, monitor, health):
    """Launch the child at the engine's durable writer_intent boundary under its host lock.

    The host adapter calls this after authenticating admission, quiescing the reader,
    and starting the scoped rclone in its private mount namespace.
    """
    c.require(os.geteuid() == 0 and controller.locked and journal.locked,
              'root controller and locked journals required')
    intent, state = controller.audit()
    c.validate_intent(intent)
    from rhea_gen14_clone_credentials import LEGACY, TRIAL, read_path
    prepared = c.parse(read_path(TRIAL / 'prepared-writer-request.json'))
    c.require(prepared['phase'] == 'prepared' and prepared['generation'] == 14 and
              prepared['previous_checkpoint_sha256'] == intent['previous_checkpoint_sha256'] and
              prepared['binary_sha256'] == intent['go_binary_sha256'] and
              c.digest(verified_request(prepared['proposal'], read_path(LEGACY / 'checkpoints/000013-step.json')))
              == c.digest(intent['request']), 'signed intent differs from the pre-handoff read-only plan')
    c.require(state['phase'] == 'writer_intent', 'no durable writer intent for this child')
    handoff = controller.receipt('writer_ready')
    writer = handoff['writer_identity']
    c.require(controller.receipt('writer_intent') == dict(request=intent['request'], writer_identity=writer)
              and handoff['binary_sha256'] == intent['go_binary_sha256']
              and handoff['reader_stopped'] is True and handoff['markers_withheld'] is True,
              'writer handoff differs from the recorded intent')
    c.require(not (set(os.listdir(journal.path)) - {'lock'}), 'existing writer evidence forbids launch')
    procdir = Path('/proc') / str(writer['pid'])
    path = c.INSTALL / 'rhea-gen14'
    c.private_path(c.INSTALL, directory=True, root_only=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as binary:
        st = os.fstat(fd)
        c.require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
                  and stat.S_IMODE(st.st_mode) == 0o555 and
                  hashlib.file_digest(binary, 'sha256').hexdigest() == intent['go_binary_sha256'],
                  'installed child executable differs')
        ns = os.open(procdir / 'ns/mnt', os.O_RDONLY | os.O_CLOEXEC)
        try:
            c.require(not os.path.samestat(os.fstat(ns), os.stat('/proc/1/ns/mnt'))
                      and child_identity(writer['pid']) == writer, 'scoped writer PID or namespace changed')
            monitor()
            # An uncertain launch, even one preceding the first Go record, is
            # inspected. This receipt blocks a new child after a parent crash.
            journal.put('launch.json', dict(intent_sha256=c.digest(intent), writer_identity=writer))
            argv = ['/usr/bin/nsenter', '--mount=/proc/self/fd/' + str(ns),
                    '/usr/bin/unshare', '--net', '/usr/bin/setpriv', '--reuid=65534', '--regid=65534',
                    '--clear-groups', '--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
                    '--no-new-privs', '/proc/self/fd/' + str(fd), 'worker']
            parent, child = socket.socketpair()
            with parent, child:
                process = subprocess.Popen(argv, pass_fds=(fd, ns), stdin=child, stdout=subprocess.DEVNULL,
                                           cwd='/', env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
                child.close()
                return supervise(process, parent, intent, journal, monitor, health)
        finally:
            os.close(ns)


def verified_request(proposal, certificate):
    """Derive the unsigned request from the protected checkpoint and the actual picker inputs."""
    c.require(c.raw_sha(certificate) == ANCHOR,
              'generation-13 certificate differs')
    cert = c.parse(certificate)
    before = dict(format=cert['after_format'], marked=cert['marked_after'], files=cert['sst_count'],
                  bytes=cert['sst_bytes'], inventory_sha256=cert['sst_inventory_sha256'])
    picker, inputs = proposal['first_picker_plan'], proposal['first_inputs']
    level = picker['input_level']
    c.require(type(level) is int and 0 <= level <= 6 and type(picker['output_level']) is int
              and level == picker['output_level'] and isinstance(inputs, list) and inputs,
              'invalid picker level or inputs')
    candidate = hashlib.sha256(f'pebble-lab-candidate-v1\ninput-level\t{level}\noutput-level\t{level}\n'.encode())
    total, previous = 0, -1
    names = []
    for row in inputs:
        number, size = row['number'], row['size']
        c.require(type(number) is int and number > previous and type(size) is int and size > 0
                  and row['name'] == f'{number:06d}.sst' and type(row['level']) is int and row['level'] == level,
                  'invalid or duplicate SST input')
        names.append(row['name'])
        total += size
        candidate.update(f'{number}\t{size}\n'.encode())
        previous = number
    c.require(0 < total <= 256 << 20 and type(picker['input_bytes']) is int and total == picker['input_bytes']
              and sorted(names) == picker['input_files'] and candidate.hexdigest() == picker['candidate_sha256'],
              'candidate digest, names or byte budget differs')
    binding = (f"fullclone-plan-v1\nformat\t{before['format']}\nmarked\t{before['marked']}\n"
               f"inventory\t{before['inventory_sha256']}\ncandidate\t{candidate.hexdigest()}\n")
    plan_sha = hashlib.sha256(binding.encode()).hexdigest()
    expected = dict(maximum_units=2, before=before, initial_plan_sha256=plan_sha)
    c.require(c.digest(expected) == c.digest(proposal['request']) and picker['plan_sha256'] == plan_sha,
              'request differs from the checkpoint and physical picker binding')
    return expected

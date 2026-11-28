"""Invoked by the source-locked Go disk fixture with a test-only child binary."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import rhea_gen14_writer_supervisor as supervisor


def exercise(mode, executable, db, journal_path, raw_request):
    c = supervisor.c
    journal = c.Store(journal_path)
    with open(executable, 'rb') as binary:
        sha = hashlib.file_digest(binary, 'sha256').hexdigest()
    intent = dict(go_binary_sha256=sha, reader_identity=dict(boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()),
                  request=json.loads(raw_request), unit_count=2)
    def monitor():
        if mode == 'revoke-second' and (journal.path / 'unit-002-intent.json').exists():
            raise c.Refusal('fixture monitor revoked the second rewrite')
    def health():
        return dict(cache_bytes=0, free_bytes=3 << 40, queue_bytes=0, queue_files=0, errors=0, transferring=0)
    if mode == 'disconnect':
        put = journal.put
        def lose_ack(name, value):
            put(name, value)
            if name == 'unit-002-intent.json':
                raise ConnectionError('lost acknowledgement of durable second intent')
        journal.put = lose_ack
    with journal.lock():
        parent, child = socket.socketpair()
        with child:
            process = subprocess.Popen([executable, '-test.run=^TestGeneration14SocketChild$'],
                                       stdin=child, stdout=subprocess.DEVNULL,
                                       env=dict(PATH='/usr/bin:/bin', RHEA_GEN14_FIXTURE_DB=db))
        try:
            receipt = supervisor.supervise(process, parent, intent, journal, monitor, health)
        except (c.Refusal, ConnectionError):
            if mode == 'complete':
                raise
            if mode in ('revoke-second', 'disconnect'):
                assert (journal.path / 'unit-001-receipt.json').is_file()
                assert (journal.path / 'unit-002-intent.json').is_file()
                assert not (journal.path / 'unit-002-receipt.json').exists()
            elif mode == 'stale-request':
                assert not (journal.path / 'pending.json').exists()
            assert process.returncode != 0
        else:
            assert mode == 'complete' and receipt['report']['physical_compactions'] == 2
            assert json.loads(base64.b64decode(receipt['go_files']['closed.json'])) == receipt['report']
    print(json.dumps(dict(mode=mode, child_exit=process.returncode, retained=sorted(p.name for p in journal.path.glob('*.json')))))


if __name__ == '__main__':
    exercise(*sys.argv[1:])

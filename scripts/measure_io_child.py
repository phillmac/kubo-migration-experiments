#!/usr/bin/env python3
"""Measure one synthetic child's IO using waited-child accounting.

Linux /proc/self/io includes waited-for children. This helper samples itself
before fork and after wait+pipe drain. It performs no file writes in between;
its JSON journal is written only after the final sample. The write-byte delta
therefore excludes the tracer and journal. Read counters include pipe-draining
observer overhead and must NOT be presented as target-only storage reads.
"""
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


def io_counters():
    return {k: int(v) for k, v in (line.split(':', 1) for line in Path('/proc/self/io').read_text().splitlines())}


def drain(stream, result):
    h = hashlib.sha256()
    count = 0
    preview = bytearray()
    while True:
        chunk = stream.read(65536)
        if not chunk:
            break
        h.update(chunk)
        count += len(chunk)
        if len(preview) < 32768:
            preview.extend(chunk[:32768 - len(preview)])
    result.update(bytes=count, sha256=h.hexdigest(), text=(preview.decode('utf-8', 'replace') if count <= 32768 else None))
    stream.close()


def main():
    destination = Path(sys.argv[1])
    command = sys.argv[2:]
    if not command or destination.exists():
        raise SystemExit('Expected a command and a new report path')
    before = io_counters()
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    result = {'pid': process.pid, 'command': command,
              'counter_scope': 'helper+self waited child delta; helper makes no writes until after sample',
              'read_counter_caveat': 'includes observer pipe-draining reads'}
    outputs = {'stdout': {}, 'stderr': {}}
    threads = [threading.Thread(target=drain, args=(getattr(process, key), outputs[key]), daemon=True) for key in outputs]
    for thread in threads:
        thread.start()
    def stop(signum, frame):
        raise TimeoutError('Child measurement interrupted')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        result['returncode'] = process.wait(timeout=180)
        for thread in threads:
            thread.join(timeout=3)
            if thread.is_alive():
                raise RuntimeError('Output pipe not closed after process exit')
        after = io_counters()
        result['proc_io'] = {key: after[key] - before[key] for key in before}
        result.update(outputs)
    except BaseException as exc:
        result['error'] = str(exc)
        process.kill()
        process.wait(timeout=5)
        raise
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 6)
        destination.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

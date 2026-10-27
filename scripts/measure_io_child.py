#!/usr/bin/env python3
"""Run one bounded synthetic command and sample its IO before reaping it.

The parent runs this helper under strace in a network-disabled namespace.
Output is drained into hashes in memory, never into repository/storage files.
Only small text outputs are retained. This helper has no network operations.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


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
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    started = time.monotonic()
    result = {'pid': process.pid, 'command': command}
    outputs = {'stdout': {}, 'stderr': {}}
    threads = [threading.Thread(target=drain, args=(getattr(process, key), outputs[key]), daemon=True) for key in outputs]
    for thread in threads:
        thread.start()
    def stop(signum, frame):
        raise TimeoutError('Child measurement interrupted')
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while True:
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                break
            if time.monotonic() - started > 180:
                raise TimeoutError('Synthetic command exceeded 180 seconds')
            time.sleep(0.01)
        # WNOWAIT preserves /proc/<pid>/io after all target threads have exited.
        result['proc_io'] = {k: int(v) for k, v in (line.split(':', 1) for line in Path('/proc/%d/io' % process.pid).read_text().splitlines())}
        result['returncode'] = process.wait(timeout=3)
        for thread in threads:
            thread.join(timeout=3)
            if thread.is_alive():
                raise RuntimeError('Output pipe not closed after process exit')
        result.update(outputs)
    except BaseException as exc:
        result['error'] = str(exc)
        process.kill()
        process.wait(timeout=5)
        raise
    finally:
        result['elapsed_seconds'] = round(time.monotonic() - started, 6)
        destination.write_text(json.dumps(result, indent=2) + '\n')
    # The helper succeeds when it measured an exit, including a negative control.
    # The caller separately checks the target's recorded return code.


if __name__ == '__main__':
    main()

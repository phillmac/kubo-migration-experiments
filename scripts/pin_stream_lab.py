#!/usr/bin/env python3
"""Synthetic pin-stream cancellation comparison; flatfs fixture, not Pebble test.

A closed, newly generated flatfs fixture lets us remove one precisely identified
synthetic block without bypassing pin protections on any live datastore. No
production paths or existing-repository argument are accepted.
"""
import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
from urllib.parse import urlencode

from failure_lab import PINNED, require
from kubo_migration_lab import Lab, digest, require_isolation, tree_hashes, verify_binary


def varint(n):
    require(n >= 0, 'Negative varint')
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return bytes(out)


def cbor_head(major, n):
    require(0 <= n < 65536, 'Bounded CBOR only')
    if n < 24:
        return bytes([major * 32 + n])
    if n < 256:
        return bytes([major * 32 + 24, n])
    return bytes([major * 32 + 25]) + n.to_bytes(2, 'big')


def cid(payload, codec):
    return varint(1) + varint(codec) + b'\x12\x20' + hashlib.sha256(payload).digest()


def cid_text(value):
    return 'b' + base64.b32encode(value).decode().lower().rstrip('=')


def verified_ok(item):
    # PinStatus is an embedded Go struct: JSON is flattened and false Ok omitted.
    require(isinstance(item, dict) and isinstance(item.get('Cid'), str), 'Not a per-pin verify record')
    if item.get('Ok') is True:
        return True
    require(isinstance(item.get('BadNodes'), list) and len(item['BadNodes']) > 0,
            'Missing broken-node evidence; do not classify stream errors as broken pins')
    return False


def make_car(path, count=4096):
    require(64 <= count <= 8192, 'Bounded root count')
    child = b'one synthetic shared child deliberately removed after pinning\n'
    child_cid = cid(child, 0x55)
    roots, blocks = [], [(child_cid, child)]
    for i in range(count):
        name = ('child-%06d' % i).encode()
        link = b'\x0a' + varint(len(child_cid)) + child_cid + b'\x12' + varint(len(name)) + name
        payload = b'\x12' + varint(len(link)) + link
        root = cid(payload, 0x70)
        roots.append(root)
        blocks.append((root, payload))
    header = b'\xa2\x65roots' + cbor_head(4, count)
    header += b''.join(b'\xd8\x2a' + cbor_head(2, len(r) + 1) + b'\0' + r for r in roots)
    header += b'\x67version\x01'
    with Path(path).open('xb') as stream:
        stream.write(varint(len(header)) + header)
        for key, payload in blocks:
            stream.write(varint(len(key) + len(payload)) + key + payload)
    return child, child_cid, roots


class PinLab:
    def __init__(self, base):
        self.lab = Lab(base)
        self.root = self.lab.root
        self.events = []

    def guard(self, repo, daemon=False):
        repo = Path(repo)
        require(repo.parent == self.root and not repo.is_symlink(), 'Not an owned synthetic repo')
        for p in repo.rglob('*'):
            require(not p.is_symlink(), 'Symlink in synthetic repo')
        require(daemon or not (repo / 'api').exists(), 'Unexpected API redirection')

    def env(self, repo):
        return {'PATH': '/usr/bin:/bin', 'HOME': str(self.root / 'home'),
                'IPFS_PATH': str(repo), 'GOMAXPROCS': '2', 'GOMEMLIMIT': '512MiB', 'LANG': 'C.UTF-8'}

    def cli(self, binary, repo, *args):
        self.guard(repo)
        require_isolation()
        p = subprocess.run([str(binary), '--offline', *args], env=self.env(repo), cwd=self.root,
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=120)
        self.events.append({'repo': repo.name, 'args': args, 'returncode': p.returncode,
                            'stdout_sha256': hashlib.sha256(p.stdout).hexdigest(),
                            'stderr': p.stderr.decode('utf-8', 'replace')[-4000:]})
        require(p.returncode == 0, 'CLI failed: ' + p.stderr.decode('utf-8', 'replace')[-2000:])
        return p.stdout

    def daemon_test(self, binary, repo, probe, count):
        self.guard(repo)
        config_path = repo / 'config'
        conf = json.loads(config_path.read_text())
        expected_peer = conf['Identity']['PeerID']
        conf['Addresses']['API'] = '/ip4/127.0.0.1/tcp/0'
        conf['Addresses']['Gateway'] = ''
        conf['Addresses']['Swarm'] = []
        conf['Bootstrap'] = []
        conf['AutoConf'] = {'Enabled': False}
        conf.setdefault('DNS', {})['Resolvers'] = {}
        conf.setdefault('Routing', {})['DelegatedRouters'] = []
        conf.setdefault('Ipns', {})['DelegatedPublishers'] = []
        config_path.write_text(json.dumps(conf))
        report = {'cycles': [], 'pin_root_count': count, 'status': 'starting',
                  'offline_fixture_config_normalized': ['Addresses', 'Bootstrap', 'AutoConf', 'DNS.Resolvers',
                                                        'Routing.DelegatedRouters', 'Ipns.DelegatedPublishers']}
        with tempfile.TemporaryFile(dir=self.root / 'home') as log:
            proc = subprocess.Popen([str(binary), 'daemon', '--offline', '--migrate=false'],
                                    cwd=self.root, env=self.env(repo), stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=log, start_new_session=True)
            port = None
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    require(proc.poll() is None, 'Daemon exited before readiness')
                    if (repo / 'api').is_file():
                        match = re.fullmatch(r'/ip4/127\.0\.0\.1/tcp/(\d+)', (repo / 'api').read_text().strip())
                        require(match, 'Unexpected local API address')
                        port = int(match.group(1))
                        break
                    time.sleep(0.05)
                require(port, 'Daemon readiness timeout')

                def request(path, query=None, abandon=False):
                    require_isolation()
                    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
                    started = time.monotonic()
                    try:
                        url = '/api/v0/' + path
                        if query:
                            url += '?' + urlencode(query)
                        connection.request('POST', url)
                        response = connection.getresponse()
                        require(response.status == 200, 'RPC failed with HTTP ' + str(response.status))
                        if abandon:
                            data = response.readline(32768)
                            require(data.endswith(b'\n'), 'No complete verification record before disconnect')
                        else:
                            data = response.read(16 * 1024 * 1024 + 1)
                            require(len(data) <= 16 * 1024 * 1024, 'RPC response exceeds bound')
                        return data, round(time.monotonic() - started, 6)
                    finally:
                        connection.close()

                identity = json.loads(request('id')[0])
                require(identity.get('ID') == expected_peer, 'Wrong local synthetic daemon identity')
                pins = json.loads(request('pin/ls', {'type': 'recursive'})[0])
                require(len(pins['Keys']) >= count, 'Expected recursive pin inventory missing')
                for i in range(8):
                    first, elapsed = request('pin/verify', {'verbose': 'true'}, abandon=True)
                    item = json.loads(first)
                    cycle = {'cycle': i + 1, 'first_record_broken': not verified_ok(item),
                             'disconnect_after_one_record_seconds': elapsed}
                    _, cycle['pin_ls_seconds'] = request('pin/ls', {'type': 'recursive'})
                    _, cycle['pin_add_seconds'] = request('pin/add', {'arg': probe, 'recursive': 'false'})
                    _, cycle['pin_rm_seconds'] = request('pin/rm', {'arg': probe, 'recursive': 'false'})
                    report['cycles'].append(cycle)
                data, seconds = request('pin/verify', {'verbose': 'true'})
                rows = [json.loads(line) for line in data.splitlines() if line]
                broken = sum(not verified_ok(r) for r in rows)
                require(broken == count, 'Did not verify all deliberately broken roots')
                report.update(status='responsive', fully_drained_broken_roots=broken, final_verify_seconds=seconds)
            except Exception as exc:
                report.update(status='unresponsive-or-failed', error=repr(exc))
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=8)
                        report['shutdown'] = 'graceful'
                    except subprocess.TimeoutExpired:
                        os.killpg(proc.pid, signal.SIGKILL)
                        proc.wait(timeout=5)
                        report['shutdown'] = 'forced-after-eight-seconds'
                else:
                    report['shutdown'] = 'already-exited'
                report['daemon_returncode'] = proc.returncode
                log.seek(0)
                report['daemon_log_tail'] = log.read().decode('utf-8', 'replace')[-8000:]
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True)
    args = parser.parse_args()
    require_isolation()
    require(os.getuid() != 0, 'Unprivileged execution required')
    os.umask(0o077)
    x = PinLab(args.base)
    bins = {k: verify_binary(Path(args.base) / 'bin' / v / 'ipfs', sha) for k, (v, sha) in PINNED.items()}
    report = {'scope': 'synthetic flatfs pin cancellation; NOT Pebble migration', 'production_approved': False}
    try:
        seed = x.root / 'pin-seed'
        seed.mkdir()
        x.cli(bins['old'], seed, 'init')
        child, child_cid, roots = make_car(x.root / 'pins.car')
        x.cli(bins['old'], seed, 'dag', 'import', str(x.root / 'pins.car'))
        raw_file = x.root / 'probe.bin'
        raw_file.write_bytes(b'synthetic responsiveness probe\n')
        probe = x.cli(bins['old'], seed, 'block', 'put', '--cid-codec=raw', str(raw_file)).decode().strip()
        key = base64.b32encode(child_cid[2:]).decode().rstrip('=')
        matches = list((seed / 'blocks').rglob(key + '.data'))
        require(len(matches) == 1 and matches[0].read_bytes() == child, 'Exact synthetic child file not located')
        matches[0].unlink()
        report['deliberately_missing_child'] = cid_text(child_cid)
        sealed = tree_hashes(seed)
        for label in ('old', 'target'):
            repo = x.root / ('pins-' + label)
            shutil.copytree(seed, repo)
            if label == 'target':
                x.cli(bins['target'], repo, 'repo', 'migrate', '--to=18')
            report[label] = x.daemon_test(bins[label], repo, probe, len(roots))
        require(report['target']['status'] == 'responsive' and report['target']['shutdown'] == 'graceful',
                'Target pin cancellation/lifecycle acceptance failed')
        require(tree_hashes(seed) == sealed, 'Closed source changed')
        report['seed_unchanged'] = True
        report['old_bug_reproduced'] = report['old']['status'] != 'responsive'
        report['interpretation'] = ('Old failure observed; inspect diagnostic before claiming exact root cause'
                                    if report['old_bug_reproduced'] else
                                    'Both versions responsive: cancellation smoke test only, original lock bug NOT reproduced')
        report['status'] = 'target-smoke-accepted'
    except Exception as exc:
        report.update(status='failed', error=repr(exc))
        raise
    finally:
        (x.lab.evidence / 'commands.json').write_text(json.dumps(x.events, indent=2) + '\n')
        (x.lab.evidence / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2), flush=True)


if __name__ == '__main__':
    main()

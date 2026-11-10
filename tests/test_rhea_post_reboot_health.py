"""Offline post-reboot identity boundaries; no host, Docker, service or SDK calls."""
import copy
from contextlib import contextmanager
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


m = module('post_reboot_health_tests', ROOT / 'scripts/rhea_post_reboot_health.py')
c = module('post_reboot_health_controller_fixture', ROOT / 'scripts/run_rhea_full_clone_steps_bounded.py')
w = module('post_reboot_health_wrapper_fixture', ROOT / 'scripts/rhea_wasabi_lab_mount.py')


def pin(raw):
    return {'bytes': len(raw), 'sha256': m.sha(raw)}


def service(unit, pid=0, *, user='', group=''):
    active = bool(pid)
    return {'Id': unit, 'LoadState': 'loaded', 'ActiveState': 'active' if active else 'inactive',
            'SubState': 'running' if active else 'dead', 'MainPID': str(pid), 'User': user, 'Group': group,
            'ControlGroup': '/system.slice/' + unit if active else '',
            'FragmentPath': '/run/systemd/transient/' + unit, 'DropInPaths': '', 'NeedDaemonReload': 'no',
            'Result': 'success', 'ExecMainCode': '0', 'ExecMainStatus': '0'}


def identity(pid, ticks):
    return {'pid': pid, 'start_ticks': str(ticks), 'boot_id': m.BOOT_ID}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.cert = json.loads((ROOT / 'docs/evidence/rhea-full-clone-000009-step-20261104.json').read_bytes())
        self.state = json.loads((ROOT / 'docs/evidence/rhea-bounded-adoption-state-after-20261106.json').read_bytes())
        self.old = SimpleNamespace(
            READER_UNIT='rhea-pebble-lab-reader-fast-mount-20261102.service',
            READER_PROPERTIES={'Description': 'Rhea-lab-reader-S3-optimized-mount', 'Restart': 'on-failure',
                               'RestartSec': '30s', 'MemoryMax': '2147483648', 'Nice': '10'},
            READER_ARGV=['/usr/bin/rclone', '--config', str(m.READER_CONFIG), 'mount',
                         'rhea_pebble_lab_reader:rhea-pebble-lab-20261101-39037c6f01/rhea',
                         '/mnt/rhea-pebble-lab-reader-20261102'],
            READER_DB=Path('/mnt/rhea-pebble-lab-reader-20261102/pebbleds'),
            READER_CACHE=Path('/data/rhea-pebble-lab-reader-cache-fast-20261102'),
        )
        self.reader = {'service': service(self.old.READER_UNIT, 4200),
                       'properties': copy.deepcopy(self.old.READER_PROPERTIES),
                       'mount': {'target': str(self.old.READER_DB.parent), 'source': 'fixed-reader'},
                       'process': identity(4200, 60001)}
        self.server = {'process': identity(3905, 40001), 'executable': '/usr/bin/rclone',
                       'cgroup': '/system.slice/docker-' + 'c' * 64 + '.scope',
                       'listener': {'address': '127.0.0.1', 'port': 5572, 'pid': 3905, 'inode': '70001'}}
        self.production = {unit: service(unit) for unit in w.PROD_OFF}
        self.production.update({m.PRODUCTION_UNIT: service(m.PRODUCTION_UNIT, 3890, user='ubuntu'),
                                'production_process': identity(3890, 40000),
                                'service_leader_executable': '/usr/bin/bash', 'walker_unit_file_state': 'disabled',
                                'rc_server': self.server})
        self.records = {
            'intent.json': {'schema': 1, 'boot_id': m.BOOT_ID, 'state_sha256': m.STATE_SHA},
            'production-start-intent.json': {'argv': m.start_command(m.PRODUCTION_UNIT, m.PRODUCTION_PROPERTIES,
                                                                    ['/usr/bin/bash', str(m.LAUNCHER)])},
            'production-restored.json': {'production': self.production},
            'reader-start-intent.json': {'argv': m.start_command(self.old.READER_UNIT, self.old.READER_PROPERTIES,
                                                               self.old.READER_ARGV)},
            'reader-restored.json': {'reader': self.reader},
            'reader-metadata.json': {'state': c.checkpoint_state(self.cert), 'db': str(self.old.READER_DB),
                'metadata': {name: {key: item[key] for key in ('size', 'sha256')}
                             for name, item in self.cert['remote_metadata'].items()},
                'manifest': self.cert['manifest'],
                'manifest_sha256': self.cert['remote_metadata'][self.cert['manifest']]['sha256'],
                'listed_sst_files': self.cert['sst_count']},
        }
        self.receipts = {name: m.canonical(value) for name, value in self.records.items()}
        inputs = {str(path): {'bytes': 100, 'sha256': '1' * 64} for path in m.INPUTS}
        for path, digest in m.SOURCE_INPUT_PINS.items():
            inputs[str(path)]['sha256'] = digest
        self.value = {'schema': 1, 'scope': m.SCOPE, 'observed_unix': 1794000000.0,
                      'boot_id': m.BOOT_ID, 'kernel': m.KERNEL, 'generation': 9, 'rewrites': 5, 'pending': None,
                      'state_sha256': m.STATE_SHA, 'checkpoint_sha256': m.CERT_SHA, 'pins_sha256': m.PINS_SHA,
                      'adoption_completed_sha256': m.ADOPTION_COMPLETED_SHA, 'parking_completed_sha256': m.PARK_SHA,
                      'reader': self.reader, 'production': self.production,
                      'receipts': {name: pin(raw) for name, raw in self.receipts.items()}, 'protected_inputs': inputs}
        self.ctx = {'c': c, 'w': w, 'old': self.old, 'cert': self.cert, 'identity': self.value,
                    'identity_sha256': m.sha(m.canonical(self.value))}

    def replace_receipt(self, name, value):
        self.receipts[name] = m.canonical(value)
        self.value['receipts'][name] = pin(self.receipts[name])


class IdentityTests(Fixture):
    def test_exact_adopted_state_and_launch_receipts_are_accepted_without_mutation(self):
        before = copy.deepcopy((self.value, self.receipts, self.cert, self.state))
        self.assertIs(m.validate_identity(self.ctx, self.value, self.receipts), self.value)
        self.assertEqual(before, (self.value, self.receipts, self.cert, self.state))
        self.assertEqual(m.sha(m.canonical(self.state)), m.STATE_SHA)
        self.assertEqual(self.state['binding']['limits']['maximum_rewrites'], 5)

    def test_old_boot_changed_checkpoint_or_progress_refused(self):
        for key, value in (('boot_id', m.OLD_BOOT_ID), ('kernel', 'another-kernel'),
                           ('generation', 10), ('rewrites', 6), ('pending', {}),
                           ('state_sha256', '0' * 64), ('parking_completed_sha256', '0' * 64)):
            altered = copy.deepcopy(self.value)
            altered[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'boot, checkpoint or policy'):
                m.validate_identity(self.ctx, altered, self.receipts)

    def test_process_and_listener_types_are_strict(self):
        mutations = [lambda x: x['reader']['process'].update(boot_id=m.OLD_BOOT_ID),
                     lambda x: x['production']['production_process'].update(pid=True),
                     lambda x: x['production']['rc_server']['process'].update(start_ticks='0'),
                     lambda x: x['production']['rc_server']['listener'].update(address='0.0.0.0'),
                     lambda x: x['production']['rc_server']['listener'].update(pid=9999)]
        for change in mutations:
            altered = copy.deepcopy(self.value)
            change(altered)
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                m.validate_identity(self.ctx, altered, self.receipts)

    def test_rehashed_launch_change_and_receipt_substitution_are_refused(self):
        changed = copy.deepcopy(self.records['reader-start-intent.json'])
        changed['argv'].append('--read-only')
        self.replace_receipt('reader-start-intent.json', changed)
        with self.assertRaisesRegex(RuntimeError, 'launch command'):
            m.validate_identity(self.ctx, self.value, self.receipts)
        self.setUp()
        self.receipts['production-restored.json'] += b' '
        with self.assertRaisesRegex(RuntimeError, 'receipt bytes'):
            m.validate_identity(self.ctx, self.value, self.receipts)

    def test_identity_must_match_restored_process_and_certified_metadata(self):
        changed = copy.deepcopy(self.records['production-restored.json'])
        changed['production']['production_process']['start_ticks'] = '99999'
        self.replace_receipt('production-restored.json', changed)
        with self.assertRaisesRegex(RuntimeError, 'restoration observation'):
            m.validate_identity(self.ctx, self.value, self.receipts)
        self.setUp()
        changed = copy.deepcopy(self.records['reader-metadata.json'])
        changed['metadata'][self.cert['manifest']]['sha256'] = '0' * 64
        self.replace_receipt('reader-metadata.json', changed)
        with self.assertRaisesRegex(RuntimeError, 'certified generation'):
            m.validate_identity(self.ctx, self.value, self.receipts)

    def test_input_set_and_known_source_pins_cannot_be_broadened(self):
        for mutate in (lambda x: x.update({'/tmp/arbitrary.py': pin(b'anything')}),
                       lambda x: x.pop(str(m.VERIFY)),
                       lambda x: x[str(m.LAUNCHER)].update(sha256='0' * 64)):
            altered = copy.deepcopy(self.value)
            mutate(altered['protected_inputs'])
            with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                m.validate_identity(self.ctx, altered, self.receipts)


def docker_fixture(server):
    original = {'Id': 'a' * 64, 'Image': 'sha256:' + 'b' * 64,
                'Config': {'Image': 'retained-image', 'Cmd': ['mount', 'fixed:prefix', '/mount'],
                           'Entrypoint': ['rclone'], 'User': '', 'WorkingDir': '/', 'Env': ['FIXED=value']},
                'HostConfig': {'NetworkMode': 'host', 'Privileged': False, 'CapAdd': ['SYS_ADMIN'],
                               'CapDrop': None, 'SecurityOpt': ['apparmor:unconfined'],
                               'Devices': [{'PathOnHost': '/dev/fuse', 'PathInContainer': '/dev/fuse',
                                            'CgroupPermissions': 'rwm'}],
                               'RestartPolicy': {'Name': 'no', 'MaximumRetryCount': 0}, 'AutoRemove': True,
                               'Binds': ['/cache:/cache', '/config:/config:ro', '/mount:/mount:rshared']},
                'Mounts': [{'Type': 'bind', 'Source': '/cache', 'Destination': '/cache', 'RW': True},
                           {'Type': 'bind', 'Source': '/config', 'Destination': '/config', 'RW': False},
                           {'Type': 'bind', 'Source': '/mount', 'Destination': '/mount', 'RW': True}]}
    current = copy.deepcopy(original)
    current.update(Id='c' * 64, State={'Running': True, 'Paused': False, 'Restarting': False,
                                     'Dead': False, 'OOMKilled': False, 'Pid': server['process']['pid']})
    return [original], [current]


class DockerTests(Fixture):
    def test_only_bind_and_mount_order_are_ignored(self):
        saved, current = docker_fixture(self.server)
        current[0]['HostConfig']['Binds'].reverse()
        current[0]['Mounts'].reverse()
        self.assertTrue(m.validate_docker(saved, current, self.server)['configuration_matches_saved'])

    def test_duplicate_binds_and_destinations_are_refused(self):
        for key in ('Binds', 'Mounts'):
            saved, current = docker_fixture(self.server)
            rows = current[0]['HostConfig']['Binds'] if key == 'Binds' else current[0]['Mounts']
            rows.append(copy.deepcopy(rows[0]))
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'duplicate'):
                m.validate_docker(saved, current, self.server)

    def test_image_command_mount_privilege_restart_and_pid_changes_are_refused(self):
        changes = [lambda x: x.update(Image='sha256:' + 'd' * 64),
                   lambda x: x['Config']['Cmd'].append('--other'),
                   lambda x: x['Mounts'][0].update(Source='/other-cache'),
                   lambda x: x['HostConfig'].update(Privileged=True),
                   lambda x: x['HostConfig']['RestartPolicy'].update(Name='always'),
                   lambda x: x['State'].update(Pid=7777),
                   lambda x: x.update(Id='e' * 64)]
        for change in changes:
            saved, current = docker_fixture(self.server)
            change(current[0])
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                m.validate_docker(saved, current, self.server)


class InputTests(unittest.TestCase):
    @contextmanager
    def files(self, path, *, mode=None, link_target=None):
        raw = b'exact pinned file bytes\n'
        resolved, uid, gid, policy_mode = ((path, 0, 0, 0o600) if path in m.PRIVATE_INPUTS
                                           else m.PUBLIC_INPUT_POLICY[path])
        leaf = SimpleNamespace(st_mode=stat.S_IFREG | (mode if mode is not None else policy_mode),
                               st_uid=uid, st_gid=gid, st_nlink=1, st_size=len(raw), st_dev=1, st_ino=123)
        directory = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        link = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=1000, st_gid=1000)

        def lstat(item):
            if item == m.ALIAS_LINK:
                return link
            if item == resolved:
                return leaf
            if item in resolved.parents:
                return directory
            raise AssertionError('unplanned stat: ' + str(item))

        def resolve(item, **kwargs):
            self.assertIn(item, (path, resolved))
            return resolved

        stream = io.BytesIO(raw)
        stream.fileno = lambda: 123
        with patch.object(m.Path, 'lstat', lstat), patch.object(m.Path, 'resolve', resolve), \
             patch.object(m.os, 'readlink', return_value=str(link_target or m.ALIAS_DIRECTORY)), \
             patch.object(m.os, 'open', return_value=123) as opened, \
             patch.object(m.os, 'fdopen', return_value=stream), patch.object(m.os, 'fstat', return_value=leaf):
            yield pin(raw), opened

    def test_explicit_managed_symlink_and_group_writable_alias_are_hash_checked(self):
        with self.files(m.ALIASES) as (expected, opened):
            m.read_input(m.ALIASES, expected)
            self.assertEqual(opened.call_args.args[0], m.PUBLIC_INPUT_POLICY[m.ALIASES][0])
        with self.files(m.ALIASES, link_target=Path('/other/repository')) as (expected, opened):
            with self.assertRaisesRegex(RuntimeError, 'directory link'):
                m.read_input(m.ALIASES, expected)
            opened.assert_not_called()

    def test_private_file_mode_is_not_relaxed_for_public_alias_policy(self):
        with self.files(m.READER_CONFIG, mode=0o644) as (expected, opened):
            with self.assertRaisesRegex(RuntimeError, 'leaf ownership or mode'):
                m.read_input(m.READER_CONFIG, expected)
            opened.assert_not_called()

    def test_private_source_exact_hash_and_public_other_write_are_refused(self):
        with self.files(m.INSTALL) as (expected, unused):
            expected['sha256'] = '0' * 64
            with self.assertRaisesRegex(RuntimeError, 'input changed'):
                m.read_input(m.INSTALL, expected)
        with self.files(m.ALIASES, mode=0o666) as (expected, opened):
            with self.assertRaisesRegex(RuntimeError, 'permissions'):
                m.read_input(m.ALIASES, expected)
            opened.assert_not_called()


class ObservationTests(Fixture):
    @contextmanager
    def observations(self, *, authenticated=False):
        writer = service('writer')
        self.old.writer_absent = Mock(return_value=writer)
        self.old.reader_observation = Mock(return_value=self.reader)
        self.old.no_other_lab_users = Mock()
        rt = SimpleNamespace(host=SimpleNamespace(locked=True), stop_present=Mock(return_value=False),
                             profile=SimpleNamespace(cache=Path('/data/rhea-pebble-lab-real-cache-20261102')),
                             free_bytes=Mock(return_value=7 * 1024**4))
        self.ctx['rt'] = rt
        stats = {'fs': 'wasabi-ca-central-1:ipfs-remote-mount/rhea',
                 'diskCache': {'bytesUsed': 0, 'uploadsQueued': 0, 'uploadsInProgress': 0,
                               'erroredFiles': 0, 'outOfSpace': False}}
        client = Path('/root/.config/rclone/rc-auth/wasabi-ipfs-rc-client.json')
        helper = SimpleNamespace(API='http://127.0.0.1:5572', CLIENT=client,
                                 call_rc=Mock(side_effect=[stats, {'queue': []}]))
        rc = SimpleNamespace(API=helper.API, CLIENT=client, FS=stats['fs'], HELPER=Path('/pinned/helper'),
                             HELPER_SHA256='a' * 64, exact_module=Mock(return_value=helper),
                             validate_rc=Mock(), NoRedirect=m.urllib.request.HTTPRedirectHandler)
        self.ctx['rc'] = rc
        self.ctx['w'] = SimpleNamespace(secure_path=Mock(), clean_queue=w.clean_queue)

        def boot(path, **kwargs):
            self.assertEqual(path, Path('/proc/sys/kernel/random/boot_id'))
            return m.BOOT_ID + '\n'

        def cache(path):
            self.assertIn(path, (rt.profile.cache, self.old.READER_CACHE, m.PRODUCTION_CACHE))
            return True

        with patch.object(m, '_unchanged') as unchanged, \
             patch.object(m, 'production_observation', return_value=self.production) as production, \
             patch.object(m.Path, 'read_text', boot), patch.object(m.Path, 'is_dir', cache), \
             patch.object(m.os, 'uname', return_value=SimpleNamespace(release=m.KERNEL)), \
             patch.object(m.urllib.request, 'install_opener'):
            yield SimpleNamespace(rt=rt, unchanged=unchanged, production=production, helper=helper, stats=stats)

    def test_observation_uses_same_runtime_and_rechecks_identities_and_inputs(self):
        with self.observations() as env:
            result = m.observe(self.ctx, authenticated_rc=False)
            self.assertEqual(result['state_sha256'], m.STATE_SHA)
            self.assertEqual(result['reader_process'], self.reader['process'])
            self.assertEqual(result['production_rc_process'], self.server['process'])
            self.assertEqual((result['generation'], result['rewrites'], result['pending']), (9, 5, None))
            self.assertEqual(env.unchanged.call_count, 2)
            self.assertEqual(env.production.call_count, 2)
            self.assertTrue(all(call.args[0] is env.rt for call in self.old.reader_observation.call_args_list))
            env.helper.call_rc.assert_not_called()

    def test_unlocked_or_restarted_reader_refused_before_network(self):
        with self.observations() as env:
            env.rt.host.locked = False
            with self.assertRaisesRegex(RuntimeError, 'protected idle lock'):
                m.observe(self.ctx)
            env.production.assert_not_called()
        with self.observations() as env:
            changed = copy.deepcopy(self.reader)
            changed['process']['start_ticks'] = '99999'
            self.old.reader_observation.return_value = changed
            with self.assertRaisesRegex(RuntimeError, 'reader changed'):
                m.observe(self.ctx)
            env.helper.call_rc.assert_not_called()

    def test_rc_cleanliness_and_during_observation_changes_fail_closed(self):
        with self.observations(authenticated=True) as env:
            env.stats['diskCache']['uploadsQueued'] = 1
            with self.assertRaisesRegex(w.Refusal, 'uploads pending'):
                m.observe(self.ctx)
            self.assertEqual(env.helper.call_rc.call_args_list[0].args,
                             ('vfs/stats', {'fs': self.ctx['rc'].FS}))
        with self.observations() as env:
            changed = copy.deepcopy(self.production)
            changed['production_process']['start_ticks'] = '99999'
            env.production.side_effect = [self.production, changed]
            with self.assertRaisesRegex(RuntimeError, 'process changed'):
                m.observe(self.ctx, authenticated_rc=False)


class ProductionTests(Fixture):
    def test_actual_production_observer_binds_launch_process_container_mount_and_listener(self):
        saved, current = docker_fixture(self.server)
        current[0]['HostConfig']['Binds'].reverse()
        self.ctx['saved_inspect'] = m.canonical(saved)
        props = dict(m.PRODUCTION_PROPERTIES)
        props['TimeoutStopUSec'] = props.pop('TimeoutStopSec')
        commands = []

        def run(args):
            commands.append(args)
            if args[:3] == ['/usr/bin/systemctl', 'show', m.PRODUCTION_UNIT]:
                return '\n'.join(key + '=' + value for key, value in props.items())
            if args[:3] == ['/usr/bin/systemctl', 'show', m.WALKER]:
                return 'Id=' + m.WALKER + '\nUnitFileState=disabled\n'
            self.assertEqual(args, ['/usr/bin/docker', 'inspect', 'c' * 64])
            return json.dumps(current)

        def read_text(path, **kwargs):
            if path == Path('/proc/3905/cgroup'):
                return '0::' + self.server['cgroup'] + '\n'
            self.assertEqual(path, Path('/proc/self/mountinfo'))
            return 'fixture mountinfo'

        def read_bytes(path):
            self.assertEqual(path, Path('/proc/3890/cmdline'))
            return b'/usr/bin/bash\0' + str(m.LAUNCHER).encode() + b'\0'

        def readlink(path):
            return {Path('/proc/3890/exe'): '/usr/bin/bash', Path('/proc/3905/exe'): '/usr/bin/rclone'}[path]

        identities = {3890: self.production['production_process'], 3905: self.server['process']}
        rt = SimpleNamespace(host=SimpleNamespace(systemctl='/usr/bin/systemctl',
                service=Mock(side_effect=lambda unit: self.production[unit]), run=Mock(side_effect=run),
                no_hidden_wasabi_kubo=Mock()), _process_identity=Mock(side_effect=identities.__getitem__))
        self.ctx.update(rt=rt, w=SimpleNamespace(PROD_OFF=w.PROD_OFF,
                        mount_rows=Mock(return_value=[{'target': str(m.PRODUCTION_MOUNT), 'type': 'fuse.rclone',
                                                       'root': '/', 'options': ['rw'],
                                                       'source': 'wasabi-ca-central-1:ipfs-remote-mount/rhea'}])))
        with patch.object(m.Path, 'read_text', read_text), patch.object(m.Path, 'read_bytes', read_bytes), \
             patch.object(m.os, 'readlink', readlink), patch.object(m, 'listener_owner') as listener:
            self.assertEqual(m.production_observation(self.ctx), self.production)
            listener.assert_called_once_with(self.server)
            self.assertEqual(len(commands), 3)
            current[0]['State']['Pid'] = 9999
            with self.assertRaisesRegex(RuntimeError, 'sealed running RC server'):
                m.production_observation(self.ctx)

    def test_listener_requires_exact_single_inode_owned_by_sealed_pid(self):
        header = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
        row = '0: 0100007F:15C4 00000000:0000 0A 0:0 00:0 0 0 0 70001\n'
        fds = [Path('/proc/3905/fd/9')]
        with patch.object(m.Path, 'read_text', return_value=header + row), \
             patch.object(m.Path, 'iterdir', return_value=iter(fds)), \
             patch.object(m.os, 'readlink', return_value='socket:[70001]'):
            self.assertEqual(m.listener_owner(self.server), self.server['listener'])
        with patch.object(m.Path, 'read_text', return_value=header + row + row):
            with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
                m.listener_owner(self.server)
        with patch.object(m.Path, 'read_text', return_value=header + row), \
             patch.object(m.Path, 'iterdir', return_value=iter(fds)), \
             patch.object(m.os, 'readlink', return_value='socket:[other]'):
            with self.assertRaisesRegex(RuntimeError, 'does not own'):
                m.listener_owner(self.server)


class RetainedAdoptionTests(unittest.TestCase):
    def test_real_adoption_proof_is_reused_without_the_old_active_pid_observer(self):
        h = module('post_reboot_saved_adoption_fixture', ROOT / 'scripts/rhea_bounded_adoption_health.py')
        comparison = module('post_reboot_saved_metrics_fixture', ROOT / 'scripts/run_rhea_integrated_verification_profile.py')
        evidence = ROOT / 'docs/evidence'

        def exported(suffix):
            return (evidence / ('rhea-bounded-adoption-' + suffix + '-20261106.json')).read_bytes()

        state = c.json_object(exported('state-after'))
        files = {h.STATE: exported('state-after'), m.ADOPTION / 'intent.json': exported('intent'),
                 h.NEW_PINS: exported('pins-after')}
        stored = dict(files)
        stored[m.ADOPTION / 'completed.json'] = exported('completed')
        directory = m.ADOPTION / 'acceptance/000001'
        for name in ('intent', 'result', 'metrics', 'completed'):
            stored[directory / (name + '.json')] = exported('acceptance-' + name)
        ctx = {'h': h, 'c': c, 'w': SimpleNamespace(read_protected=Mock(side_effect=lambda path, **kw: stored[path])),
               'cert': state['checkpoint'],
               'bundle': json.loads((evidence / 'rhea-full-clone-pacing-certified-20261104.json').read_bytes())}

        def absent(path):
            self.assertEqual(path, directory / 'failure.json', 'unexpected real filesystem status query')
            return False

        with patch.object(h, '_phase_files', return_value=(files, state, m.PINS_SHA)) as phase, \
             patch.object(h, 'exact_module', return_value=comparison), \
             patch.object(h, 'observe', side_effect=AssertionError('old PID observer must not run')), \
             patch.object(m.Path, 'exists', absent), patch.object(m.Path, 'is_symlink', absent):
            protected, accepted = m._retained_adoption(ctx)
            self.assertEqual(accepted, state)
            self.assertEqual(sha := m.sha(protected[h.STATE]), m.STATE_SHA)
            self.assertEqual(len([path for path in protected if path.parent == directory]), 4)
            phase.assert_called_once_with(ctx, 'after', m.ADOPTION_INTENT_SHA)
            stored[directory / 'result.json'] += b' '
            with self.assertRaisesRegex(RuntimeError, 'retained adoption proof changed'):
                m._retained_adoption(ctx)


if __name__ == '__main__':
    unittest.main()

"""Offline safety and staging tests for the explicitly scoped Rhea lab wrapper.

No test invokes systemd, rclone, STS, S3, FUSE, or an external process. Small
versioned-object fixtures stand in for the certified compressed ledger.
"""

from __future__ import annotations

import copy
import builtins
from contextlib import contextmanager, nullcontext
from dataclasses import replace
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "rhea_wasabi_lab_mount.py"
SPEC = importlib.util.spec_from_file_location("rhea_wasabi_lab_mount_tests", SCRIPT)
m = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = m
SPEC.loader.exec_module(m)


def ledger_bytes(rows):
    """Return deterministic gzip bytes, including an exact trailing JSONL LF."""
    raw = b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in rows)
    return gzip.compress(raw, mtime=0)


def clean_observation(profile):
    return {
        "stats": {
            "fs": profile.remote,
            "diskCache": {
                "uploadsQueued": 0,
                "uploadsInProgress": 0,
                "erroredFiles": 0,
                "outOfSpace": False,
            },
        },
        "queue": {"queue": []},
    }


class FakeHost:
    """Explicit host boundary: recording a stage never touches the host."""

    def __init__(self, running=False):
        self.active = running
        self.events = []
        self.observation = clean_observation(m.PROFILES["resume-fixture"])
        self.guard_error = None
        self.dirty_on_lock = False
        self.locked = False

    def guard(self, profile, running=False, *, admission=True):
        self.events.append(("guard", profile.name, running, self.locked))
        if self.guard_error is not None:
            raise self.guard_error

    def running(self, profile):
        self.events.append(("running", profile.name))
        return self.active

    def observe(self, profile):
        self.events.append(("observe", profile.name, self.locked))
        return copy.deepcopy(self.observation)

    def stage(self, profile):
        self.events.append(("stage", profile.name, self.locked))

    def admit(self, profile):
        self.events.append(("admit", profile.name, self.locked))

    def launch(self, profile):
        self.events.append(("launch", profile.name, self.locked))
        self.active = True

    def halt(self, profile):
        self.events.append(("halt", profile.name, self.locked))
        self.active = False

    @contextmanager
    def lock(self):
        self.events.append(("lock",))
        self.locked = True
        if self.dirty_on_lock:
            self.observation["queue"]["queue"] = [{"id": 1, "name": "queued.sst"}]
        try:
            yield
        finally:
            self.locked = False
            self.events.append(("unlock",))


class ProfileTests(unittest.TestCase):
    def test_only_two_exact_profiles(self):
        self.assertEqual(set(m.PROFILES), {"full-clone", "resume-fixture"})
        for name, profile in m.PROFILES.items():
            self.assertEqual(m.get_profile(name), profile)
            self.assertEqual(m.get_profile(profile), profile)

    def test_unknown_and_prefix_collision_profiles_refused(self):
        for value in ("full-clone/../production", "full-clone-extra", "", "rhea"):
            with self.subTest(value=value), self.assertRaises(m.Refusal):
                m.get_profile(value)

    def test_malicious_remote_and_path_substitutions_refused(self):
        profile = m.PROFILES["full-clone"]
        changes = (
            {"remote": "rhea_pebble_lab:ipfs-remote-mount/rhea"},
            {"remote": profile.remote + "-malicious"},
            {"remote": profile.remote + "/../other"},
            {"mountpoint": Path("/mnt/production")},
            {"cache": Path("/data/production-cache")},
            {"unit": "rhea-ipfs-wasabi-rclone-mount.service"},
            {"writeback": "0s"},
            {"max_cache": "100Ti"},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                m.get_profile(replace(profile, **change))


class IdentityTests(unittest.TestCase):
    def identity(self, suffix="user/rhea-pebble-lab-20261101"):
        return {
            "Arn": "arn:aws:iam::123456789012:" + suffix,
            "Account": "123456789012",
            "UserId": "LAB_TEST_NON_ROOT_USER",
        }

    def test_exact_lab_non_root_identity_allowed(self):
        m.validate_identity(self.identity())

    def test_explicit_experiments_path_lab_user_allowed(self):
        m.validate_identity(self.identity("user/experiments/rhea-pebble-lab-20261101"))

    def test_root_production_and_similar_user_identities_refused(self):
        for suffix in (
            "root",
            "user/production",
            "user/rhea-pebble-lab-20261101-extra",
            "role/rhea-pebble-lab-20261101",
            "user/other/rhea-pebble-lab-20261101",
        ):
            with self.subTest(suffix=suffix), self.assertRaises(m.Refusal):
                m.validate_identity(self.identity(suffix))

    def test_incomplete_identity_refused(self):
        for value in ({}, {"Arn": self.identity()["Arn"]}, {"Arn": "root"}):
            with self.subTest(value=value), self.assertRaises(m.Refusal):
                m.validate_identity(value)


class ConfigTests(unittest.TestCase):
    def config(self):
        return (
            "[rhea_pebble_lab]\n"
            "type = s3\nprovider = Wasabi\nregion = ca-central-1\n"
            "endpoint = s3.ca-central-1.wasabisys.com\n"
            "access_key_id = OFFLINEFIXTUREACCESS\n"
            "secret_access_key = offline-fixture-value\n"
        )

    def test_explicit_lab_only_credentials(self):
        self.assertEqual(
            m.parse_config(self.config()),
            ("OFFLINEFIXTUREACCESS", "offline-fixture-value"),
        )

    def test_ambient_credentials_wrong_remote_endpoint_and_options_refused(self):
        variants = (
            self.config() + "env_auth = true\n",
            self.config().replace("rhea_pebble_lab", "production"),
            self.config() + "[production]\ntype = s3\n",
            self.config().replace("s3.ca-central-1.wasabisys.com", "evil.invalid"),
            self.config().replace("ca-central-1", "us-east-1"),
            self.config() + "session_token = unwanted-session\n",
            self.config() + "acl = public-read\n",
            self.config() + "access_key_id = DUPLICATEFIXTUREKEY\n",
            self.config().replace("secret_access_key = offline-fixture-value\n", ""),
        )
        for value in variants:
            with self.subTest(config=value), self.assertRaises(m.Refusal):
                m.parse_config(value)


class ProtectedPathTests(unittest.TestCase):
    def info(self, mode=None, uid=0, gid=0, links=1):
        return SimpleNamespace(
            st_mode=stat.S_IFDIR | 0o755 if mode is None else mode,
            st_uid=uid,
            st_gid=gid,
            st_nlink=links,
        )

    def test_private_root_owned_path(self):
        with patch.object(Path, "lstat", return_value=self.info(stat.S_IFDIR | 0o700)):
            m.secure_path(Path("/safe/cache"), leaf_mode=0o700)

    def test_symlinks_untrusted_owners_permissions_and_hardlinks_refused(self):
        variants = (
            self.info(stat.S_IFLNK | 0o777),
            self.info(uid=1000),
            self.info(gid=1000),
            self.info(stat.S_IFDIR | 0o777),
            self.info(stat.S_IFREG | 0o600, links=2),
        )
        for info in variants:
            with self.subTest(info=info), patch.object(Path, "lstat", return_value=info):
                with self.assertRaises(m.Refusal):
                    m.secure_path(Path("/safe/cache"), leaf_mode=0o700)

    def test_leaf_mode_and_nondirectory_ancestor_refused(self):
        with patch.object(Path, "lstat", return_value=self.info()):
            with self.assertRaises(m.Refusal):
                m.secure_path(Path("/safe/cache"), leaf_mode=0o700)
        with patch.object(Path, "lstat", return_value=self.info(stat.S_IFREG | 0o600)):
            with self.assertRaises(m.Refusal):
                m.secure_path(Path("/safe/cache"))

    def test_missing_required_path_and_noncanonical_path_refused(self):
        with patch.object(Path, "lstat", side_effect=FileNotFoundError):
            with self.assertRaises(m.Refusal):
                m.secure_path(Path("/safe/cache"))
            m.secure_path(Path("/safe/cache"), missing=True)
        for path in (Path("relative"), Path("/safe/../production")):
            with self.subTest(path=path), self.assertRaises(m.Refusal):
                m.secure_path(path)


class LocalHostTests(unittest.TestCase):
    def setUp(self):
        self.host = m.RealHost()
        self.profile = m.PROFILES["resume-fixture"]

    def test_required_dependency_missing_refused_without_running_command(self):
        with patch.object(m.os, "geteuid", return_value=0), patch.object(
            m.socket, "gethostname", return_value="rhea"
        ), patch.object(m.shutil, "which", return_value=None), patch.object(
            self.host, "run"
        ) as run:
            with self.assertRaises(m.Refusal):
                self.host.dependencies()
            run.assert_not_called()

    def test_wrong_host_and_nonroot_refused(self):
        for uid, hostname in ((1000, "rhea"), (0, "other-host")):
            with self.subTest(uid=uid, hostname=hostname), patch.object(
                m.os, "geteuid", return_value=uid
            ), patch.object(m.socket, "gethostname", return_value=hostname):
                with self.assertRaises(m.Refusal):
                    self.host.dependencies()

    def test_missing_boto_dependency_is_a_sanitized_refusal(self):
        original = builtins.__import__

        def unavailable(name, *args, **kwargs):
            if name == "boto3":
                raise ImportError("offline fixture: missing boto3")
            return original(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=unavailable):
            with self.assertRaisesRegex(m.Refusal, "dependency missing"):
                self.host.cloud(("OFFLINEFIXTUREACCESS", "offline-fixture-value"))

    @contextmanager
    def simulated_paths(self, entries=(), free=None):
        with patch.object(m, "secure_path"), patch.object(
            Path, "exists", autospec=True,
            side_effect=lambda path: path != self.profile.rc_socket,
        ), patch.object(Path, "is_symlink", return_value=False), patch.object(
            Path, "is_dir", return_value=True
        ), patch.object(Path, "iterdir", side_effect=lambda: iter(entries)), patch.object(
            m.os, "statvfs",
            return_value=SimpleNamespace(f_bavail=m.MIN_FREE if free is None else free, f_frsize=1),
        ):
            yield

    def test_empty_target_and_exact_free_space_pass(self):
        with self.simulated_paths():
            self.host.paths(self.profile, running=False, rows=[])

    def test_nonempty_target_and_low_free_space_refused(self):
        for values in ({"entries": (Path("unexpected"),)}, {"free": m.MIN_FREE - 1}):
            with self.subTest(values=values), self.simulated_paths(**values):
                with self.assertRaises(m.Refusal):
                    self.host.paths(self.profile, running=False, rows=[])

    def test_management_paths_allow_low_free_space_without_relaxing_mount_identity(self):
        with self.simulated_paths(free=0):
            self.host.paths(self.profile, running=False, rows=[], admission=False)
        with self.simulated_paths(free=0), self.assertRaises(m.Refusal):
            self.host.paths(self.profile, running=False, rows=[], admission=True)
        with self.simulated_paths(entries=(Path("unexpected"),), free=0), self.assertRaises(m.Refusal):
            self.host.paths(self.profile, running=False, rows=[], admission=False)

    def test_wrong_remote_mount_and_protected_bind_mount_refused(self):
        wrong_source = {
            "target": str(self.profile.mountpoint),
            "type": "fuse.rclone", "source": self.profile.remote + "-other",
            "root": "/", "options": ["rw"],
        }
        cache_bind = dict(wrong_source, target=str(self.profile.cache))
        for running, rows in ((True, [wrong_source]), (False, [cache_bind])):
            with self.subTest(running=running), self.simulated_paths():
                with self.assertRaises(m.Refusal):
                    self.host.paths(self.profile, running=running, rows=rows)

    def test_concurrent_writer_mount_and_process_refused(self):
        row = {
            "target": "/mnt/unexpected-writer", "type": "fuse.rclone",
            "source": self.profile.remote, "options": ["rw"], "root": "/",
        }
        with self.assertRaises(m.Refusal):
            self.host.competitors(self.profile, running=False, rows=[row])
        with patch.object(Path, "iterdir", return_value=iter([Path("/proc/123456")])), patch.object(
            Path, "read_bytes", return_value=("rclone\0mount\0" + self.profile.remote + "\0").encode()
        ):
            with self.assertRaises(m.Refusal):
                self.host.competitors(self.profile, running=False, rows=[])

    def test_service_alias_dropin_and_changed_unit_refused(self):
        state = {
            "FragmentPath": str(m.UNIT_DIR / self.profile.unit),
            "DropInPaths": "", "NeedDaemonReload": "no",
        }
        for change in (
            {"FragmentPath": "/etc/systemd/system/production.service"},
            {"DropInPaths": "/etc/systemd/system/injected.conf"},
            {"NeedDaemonReload": "yes"},
        ):
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                self.host.unit_identity(self.profile, dict(state, **change), active=False)
        with patch.object(m, "read_protected", return_value=b"unexpected unit"):
            with self.assertRaises(m.Refusal):
                self.host.unit_identity(self.profile, state, active=False)

    def test_unsafe_rc_socket_refused_before_connection(self):
        for mode, uid, gid in (
            (stat.S_IFSOCK | 0o600, 1000, 0),
            (stat.S_IFSOCK | 0o600, 0, 1000),
            (stat.S_IFSOCK | 0o666, 0, 0),
            (stat.S_IFREG | 0o600, 0, 0),
        ):
            info = SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)
            with self.subTest(mode=mode, uid=uid, gid=gid), patch.object(
                self.host, "service", return_value={"MainPID": "999"}
            ), patch.object(self.host, "unit_identity", return_value=999), patch.object(
                m, "secure_path"
            ), patch.object(Path, "lstat", return_value=info), patch.object(
                m.socket, "socket"
            ) as connect:
                with self.assertRaises(m.Refusal):
                    self.host.rc(self.profile, "vfs/stats")
                connect.assert_not_called()

    def test_rc_socket_peer_must_be_exact_service_root_process(self):
        info = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_uid=0, st_gid=0)
        for peer in ((1000, 0, 0), (999, 1000, 0), (999, 0, 1000)):
            connection = Mock()
            connection.getsockopt.return_value = struct.pack("3i", *peer)
            with self.subTest(peer=peer), patch.object(
                self.host, "service", return_value={"MainPID": "999"}
            ), patch.object(self.host, "unit_identity", return_value=999), patch.object(
                m, "secure_path"
            ), patch.object(Path, "lstat", return_value=info), patch.object(
                m.socket, "socket", return_value=connection
            ), patch.object(m.http.client, "HTTPConnection") as http:
                with self.assertRaises(m.Refusal):
                    self.host.rc(self.profile, "vfs/stats")
                http.assert_not_called()
                connection.close.assert_called_once_with()

    def test_staging_writes_only_simulated_lab_unit_and_retains_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            units = root / "units"
            units.mkdir()
            cache = root / "cache"
            cache.mkdir(mode=0o700)
            retained = cache / "retained-cache-data"
            retained.write_bytes(b"offline persistent cache fixture")
            profile = replace(self.profile, mountpoint=root / "mount", cache=cache)
            registry = dict(m.PROFILES, **{profile.name: profile})
            self.host.systemctl = "/offline/systemctl"
            with patch.object(m, "PROFILES", registry), patch.object(
                m, "RUNTIME", root / "runtime"
            ), patch.object(m, "UNIT_DIR", units), patch.object(
                m, "secure_path"
            ), patch.object(
                m, "read_protected", side_effect=lambda path, **kwargs: path.read_bytes()
            ), patch.object(self.host, "run") as run:
                self.host.stage(profile)
                self.host.stage(profile)
                unit = units / profile.unit
                self.assertEqual(unit.read_text(), m.render_unit(profile))
                self.assertEqual(stat.S_IMODE(unit.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(profile.mountpoint.stat().st_mode), 0o700)
                self.assertEqual(retained.read_bytes(), b"offline persistent cache fixture")
                self.assertEqual(
                    run.call_args_list,
                    [unittest.mock.call([self.host.systemctl, "daemon-reload"])] * 2,
                )
                unit.write_text("unexpected unit injection\n")
                with self.assertRaises(m.Refusal):
                    self.host.stage(profile)

    def test_production_state_gates_precede_cloud_and_staging(self):
        selected = m.PROFILES["full-clone"]
        states = {
            name: {"LoadState": "loaded", "ActiveState": "inactive"} for name in m.PROD_OFF
        }
        states[m.PROD_MOUNT] = {
            "LoadState": "loaded", "ActiveState": "active", "SubState": "running"
        }
        states[m.READER] = {"ActiveState": "inactive"}
        for name, change in (
            (m.PROD_OFF[0], {"ActiveState": "active"}),
            (m.PROD_OFF[1], {"ActiveState": "activating"}),
            (m.PROD_MOUNT, {"ActiveState": "inactive"}),
            (m.READER, {"ActiveState": "active"}),
        ):
            changed = copy.deepcopy(states)
            changed[name].update(change)
            with self.subTest(name=name), patch.object(self.host, "dependencies"), patch.object(
                self.host, "service", side_effect=lambda unit: changed[unit]
            ), patch.object(self.host, "paths") as paths, patch.object(self.host, "cloud") as cloud:
                with self.assertRaises(m.Refusal):
                    self.host.guard(selected, running=False)
                paths.assert_not_called()
                cloud.assert_not_called()

    def test_absent_production_kubo_unit_needs_process_scan(self):
        selected = m.PROFILES["full-clone"]
        states = {
            m.PROD_OFF[0]: {"LoadState": "not-found", "ActiveState": "inactive"},
            m.PROD_OFF[1]: {"LoadState": "loaded", "ActiveState": "inactive"},
            m.PROD_MOUNT: {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"},
            m.READER: {"ActiveState": "inactive"},
        }
        with patch.object(self.host, "dependencies"), patch.object(
            self.host, "service", side_effect=lambda name: states[name]
        ), patch.object(self.host, "no_hidden_wasabi_kubo") as no_process, patch.object(
            self.host, "running", return_value=False
        ), patch.object(self.host, "paths", side_effect=RuntimeError("passed process gate")):
            with self.assertRaisesRegex(RuntimeError, "passed process gate"):
                self.host.guard(selected, running=False)
        no_process.assert_called_once_with()

    def test_absent_pin_walker_or_active_kubo_still_refused(self):
        selected = m.PROFILES["full-clone"]
        base = {
            m.PROD_OFF[0]: {"LoadState": "not-found", "ActiveState": "inactive"},
            m.PROD_OFF[1]: {"LoadState": "loaded", "ActiveState": "inactive"},
        }
        for change in ({m.PROD_OFF[0]: {"LoadState": "not-found", "ActiveState": "active"}},
                       {m.PROD_OFF[1]: {"LoadState": "not-found", "ActiveState": "inactive"}}):
            states = copy.deepcopy(base)
            states.update(change)
            with patch.object(self.host, "dependencies"), patch.object(
                self.host, "service", side_effect=lambda name: states[name]
            ), patch.object(self.host, "no_hidden_wasabi_kubo"):
                with self.assertRaises(m.Refusal):
                    self.host.guard(selected, running=False)

    def test_hidden_wasabi_kubo_process_refused_without_blocking_other_ipfs(self):
        with tempfile.TemporaryDirectory() as location:
            proc = Path(location) / "12345"
            proc.mkdir()
            (proc / "fd").mkdir()
            (proc / "comm").write_text("ipfs\n")
            (proc / "cmdline").write_bytes(b"ipfs\0daemon\0--offline\0")
            (proc / "environ").write_bytes(b"IPFS_PATH=/data/ipfs\0")
            real_iterdir = Path.iterdir

            def scan_iterdir(path):
                return iter([proc]) if path == Path("/proc") else real_iterdir(path)

            with patch.object(Path, "iterdir", autospec=True, side_effect=scan_iterdir):
                self.host.no_hidden_wasabi_kubo()
                (proc / "environ").write_bytes(b"IPFS_PATH=/home/ubuntu/.ipfs-wasabi\0")
                with self.assertRaisesRegex(m.Refusal, "Wasabi Kubo process"):
                    self.host.no_hidden_wasabi_kubo()
                (proc / "environ").write_bytes(b"IPFS_PATH=/data/ipfs\0")
                (proc / "fd" / "5").symlink_to(
                    "/home/ubuntu/.ipfs-wasabi/pebbleds/CURRENT"
                )
                with self.assertRaisesRegex(m.Refusal, "Wasabi Kubo"):
                    self.host.no_hidden_wasabi_kubo()


class UnitTests(unittest.TestCase):
    def test_fixed_commands_root_privacy_resources_and_host_visibility(self):
        for profile in m.PROFILES.values():
            with self.subTest(profile=profile.name):
                command = m.mount_command(profile)
                unit = m.render_unit(profile)
                self.assertEqual(command[:4], [str(m.RCLONE), "mount", profile.remote, str(profile.mountpoint)])
                self.assertIn("unix://" + str(profile.rc_socket), command)
                self.assertIn(str(profile.cache), command)
                self.assertIn(str(m.CONFIG), command)
                for setting in (
                    "Type=simple", "User=root", "Group=root", "UMask=0077", "Restart=no",
                    "MemoryMax=", "MemorySwapMax=0", "TasksMax=128", "CPUQuota=200%",
                    "PrivateTmp=no", "PrivateMounts=no", "SendSIGKILL=no",
                ):
                    self.assertIn(setting, unit)
                for forbidden in (
                    "Conflicts=", "ExecStop=", "PrivateTmp=yes", "PrivateMounts=yes",
                    "ProtectSystem=", "ProtectHome=", "PrivateNetwork=", "WantedBy=",
                    "ipfs-remote-mount", "127.0.0.1:", "0.0.0.0", "--allow-other",
                ):
                    self.assertNotIn(forbidden, unit)

    def test_mountinfo_escapes_decoded_and_malformed_rows_refused(self):
        text = "100 99 0:42 / /mnt/lab\\040fixture rw,nosuid - fuse.rclone remote:lab rw\n"
        row = m.mount_rows(text)[0]
        self.assertEqual(row["target"], "/mnt/lab fixture")
        self.assertEqual(row["source"], "remote:lab")
        for text in ("bad row", "100 99 0:42 / /mnt/lab rw - fuse.rclone"):
            with self.subTest(text=text), self.assertRaises(m.Refusal):
                m.mount_rows(text)


    def test_launch_accepts_active_service_only_after_host_mount_visible(self):
        host = m.RealHost()
        host.systemctl = "/offline/systemctl"
        profile = m.PROFILES["full-clone"]
        remote = profile.remote.replace(":", "{_9Ic9}:", 1)
        mountinfo = (
            f"100 99 0:42 / {profile.mountpoint} rw,nosuid - "
            f"fuse.rclone {remote} rw\n"
        )
        with patch.object(host, "run") as run, patch.object(
            host, "service", return_value={"ActiveState": "active"}
        ), patch.object(Path, "read_text", return_value=mountinfo), patch.object(
            Path, "exists", return_value=True
        ), patch.object(host, "unit_identity", return_value=888) as identity:
            host.launch(profile)
        run.assert_called_once_with(["/offline/systemctl", "start", profile.unit])
        identity.assert_called_once()

    def test_launch_refuses_active_service_without_host_mount(self):
        host = m.RealHost()
        host.systemctl = "/offline/systemctl"
        profile = m.PROFILES["full-clone"]
        with patch.object(host, "run") as run, patch.object(
            host, "service", return_value={"ActiveState": "active"}
        ), patch.object(Path, "read_text", return_value=""), patch.object(
            m.time, "monotonic", side_effect=[0, 0, 91]
        ), patch.object(m.time, "sleep"), patch.object(
            host, "unit_identity"
        ) as identity:
            with self.assertRaisesRegex(m.Refusal, "host visible"):
                host.launch(profile)
        run.assert_called_once_with(["/offline/systemctl", "start", profile.unit])
        identity.assert_not_called()


class CliTests(unittest.TestCase):
    def test_missing_dependency_details_do_not_escape_to_output(self):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(m, "Controller", side_effect=RuntimeError("sensitive-fixture-value")), patch.object(
            sys, "stdout", output
        ), patch.object(sys, "stderr", errors):
            self.assertEqual(m.main(["preflight", "--profile", "resume-fixture"]), 1)
        self.assertIn("FAIL_CLOSED", errors.getvalue())
        self.assertNotIn("sensitive-fixture-value", output.getvalue() + errors.getvalue())

    def test_apply_on_read_only_command_and_unknown_profile_refused(self):
        for argv in (
            ["preflight", "--profile", "resume-fixture", "--apply"],
            ["status", "--profile", "resume-fixture", "--apply"],
            ["start", "--profile", "production"],
        ):
            with self.subTest(argv=argv), patch.object(m, "Controller") as controller, patch.object(
                sys, "stderr", io.StringIO()
            ):
                with self.assertRaises(SystemExit):
                    m.main(argv)
                controller.assert_not_called()


class LedgerFixture(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {
                "Key": "rhea/pebbleds/CURRENT",
                "VersionId": "version-current",
                "Size": 18,
                "ETag": '"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
            },
            {
                "Key": "rhea/pebbleds/MANIFEST-47475278",
                "VersionId": "version-manifest",
                "Size": 8,
                "ETag": '"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"',
            },
            {
                "Key": "rhea/version",
                "VersionId": "version-repo",
                "Size": 3,
                "ETag": '"cccccccccccccccccccccccccccccccc"',
            },
            {
                "Key": "rhea/datastore_spec",
                "VersionId": "version-datastore",
                "Size": 20,
                "ETag": '"dddddddddddddddddddddddddddddddd"',
            },
            {
                "Key": "rhea/pebbleds/000001.sst",
                "VersionId": "version-table",
                "Size": 5,
                "ETag": '"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"',
            },
        ]

    @contextmanager
    def ledger_constants(self, blob, count=None, size=None, ssts=1):
        with patch.multiple(
            m,
            LEDGER_SHA256=hashlib.sha256(blob).hexdigest(),
            BASELINE_COUNT=len(self.rows) if count is None else count,
            BASELINE_SSTS=ssts,
            BASELINE_BYTES=sum(row["Size"] for row in self.rows) if size is None else size,
        ):
            yield

    def load(self, rows=None):
        blob = ledger_bytes(self.rows if rows is None else rows)
        with self.ledger_constants(blob):
            return m.load_ledger(blob)


class LedgerTests(LedgerFixture):
    def test_exact_compressed_ledger_accepted(self):
        ledger = self.load()
        self.assertEqual(set(ledger), {row["Key"] for row in self.rows})
        self.assertEqual(ledger[self.rows[0]["Key"]].version_id, "version-current")

    def test_compressed_digest_mismatch_refused(self):
        blob = ledger_bytes(self.rows)
        with self.ledger_constants(blob), self.assertRaises(m.Refusal):
            m.load_ledger(blob + b"corruption")

    def test_duplicate_wrong_prefix_and_parent_keys_refused(self):
        variants = [self.rows + [self.rows[0]]]
        for key in (
            "ipfs-remote-mount/rhea/pebbleds/000001.sst",
            "rhea-other/pebbleds/000001.sst",
            "rhea/../production",
            "/rhea/pebbleds/000001.sst",
        ):
            rows = copy.deepcopy(self.rows)
            rows[-1]["Key"] = key
            variants.append(rows)
        for rows in variants:
            with self.subTest(key=rows[-1]["Key"]), self.assertRaises(m.Refusal):
                self.load(rows)

    def test_mismatched_ledger_totals_refused(self):
        blob = ledger_bytes(self.rows)
        for change in ({"count": 99}, {"size": 1}, {"ssts": 99}):
            with self.subTest(change=change), self.ledger_constants(blob, **change):
                with self.assertRaises(m.Refusal):
                    m.load_ledger(blob)

    def test_null_version_and_conflicting_alias_refused(self):
        for change in ({"VersionId": "null"}, {"version_id": "different"}):
            rows = copy.deepcopy(self.rows)
            rows[0].update(change)
            with self.subTest(change=change), self.assertRaises(m.Refusal):
                self.load(rows)


class CloudTests(LedgerFixture):
    def setUp(self):
        super().setUp()
        self.ledger = self.load()
        self.s3 = Mock()
        self.sts = Mock()
        self.sts.get_caller_identity.return_value = IdentityTests().identity()
        self.s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        self.versions = [dict(row, IsLatest=True) for row in self.rows]
        self.s3.get_paginator.return_value.paginate.side_effect = self.pages
        self.s3.head_object.side_effect = self.head
        self.s3.get_object.return_value = {
            "Body": io.BytesIO(b"MANIFEST-47475278\n"),
            "VersionId": "version-current",
        }

    def pages(self, **kwargs):
        return [{"Versions": copy.deepcopy(self.versions), "DeleteMarkers": []}]

    def head(self, **kwargs):
        row = next(row for row in self.rows if row["Key"] == kwargs["Key"])
        return {
            "VersionId": row["VersionId"],
            "ContentLength": row["Size"],
            "ETag": row["ETag"],
        }

    def verify(self):
        return m.verify_cloud(self.s3, self.sts, self.ledger)

    def test_independent_sts_version_listing_and_versioned_heads(self):
        self.verify()
        self.sts.get_caller_identity.assert_called_once_with()
        self.s3.get_bucket_versioning.assert_called_once_with(Bucket=m.BUCKET)
        self.s3.get_paginator.assert_called_with("list_object_versions")
        self.s3.get_paginator.return_value.paginate.assert_called_with(
            Bucket=m.BUCKET, Prefix="rhea/"
        )
        for key in m.CRITICAL_KEYS:
            calls = [call.kwargs for call in self.s3.head_object.call_args_list]
            self.assertIn({"Bucket": m.BUCKET, "Key": key}, calls)
            self.assertIn(
                {"Bucket": m.BUCKET, "Key": key, "VersionId": self.ledger[key].version_id},
                calls,
            )

    def test_nonversioned_and_suspended_buckets_refused(self):
        for value in ({}, {"Status": "Suspended"}):
            self.s3.get_bucket_versioning.return_value = value
            with self.subTest(value=value), self.assertRaises(m.Refusal):
                self.verify()

    def test_modified_original_sst_refused(self):
        self.versions[-1]["VersionId"] = "changed-original-table"
        with self.assertRaises(m.Refusal):
            self.verify()

    def test_unexpected_production_key_in_listing_refused(self):
        self.versions[-1]["Key"] = "ipfs-remote-mount/rhea/pebbleds/000001.sst"
        with self.assertRaises(m.Refusal):
            self.verify()

    def test_listing_pagination_and_nonlatest_history(self):
        history = dict(self.versions[0], VersionId="older-version", IsLatest=False)
        self.s3.get_paginator.return_value.paginate.side_effect = None
        self.s3.get_paginator.return_value.paginate.return_value = [
            {"Versions": self.versions[:2] + [history]},
            {"Versions": self.versions[2:]},
        ]
        self.verify()

    def test_deleted_original_and_added_baseline_keys_refused(self):
        for variants in (self.versions[:-1], self.versions + [dict(self.versions[-1], Key="rhea/new")]):
            self.versions = variants
            with self.subTest(versions=len(variants)), self.assertRaises(m.Refusal):
                self.verify()

    def test_latest_delete_marker_refused(self):
        self.s3.get_paginator.return_value.paginate.side_effect = None
        self.s3.get_paginator.return_value.paginate.return_value = [{
            "Versions": self.versions[:-1],
            "DeleteMarkers": [{"Key": self.rows[-1]["Key"], "VersionId": "deleted", "IsLatest": True}],
        }]
        with self.assertRaises(m.Refusal):
            self.verify()

    def test_critical_latest_head_mismatch_refused(self):
        original = self.head

        def changed(**kwargs):
            result = original(**kwargs)
            if "VersionId" not in kwargs:
                result["VersionId"] = "replaced-after-list"
            return result

        self.s3.head_object.side_effect = changed
        with self.assertRaises(m.Refusal):
            self.verify()

    def test_critical_pinned_head_size_mismatch_refused(self):
        original = self.head

        def changed(**kwargs):
            result = original(**kwargs)
            if "VersionId" in kwargs:
                result["ContentLength"] += 1
            return result

        self.s3.head_object.side_effect = changed
        with self.assertRaises(m.Refusal):
            self.verify()

    def test_current_requires_exact_frozen_manifest_and_lf(self):
        for body in (b"MANIFEST-47475278", b"MANIFEST-47475279\n", b"MANIFEST-47475278\n\n"):
            self.s3.get_object.return_value["Body"] = io.BytesIO(body)
            with self.subTest(body=body), self.assertRaises(m.Refusal):
                self.verify()

    def test_root_credentials_refused_before_s3(self):
        self.sts.get_caller_identity.return_value = IdentityTests().identity("root")
        with self.assertRaises(m.Refusal):
            self.verify()
        self.s3.get_bucket_versioning.assert_not_called()


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.value = clean_observation(m.PROFILES["resume-fixture"])

    def test_clean_explicit_queue_allowed(self):
        m.clean_queue(self.value["stats"], self.value["queue"])

    def test_dirty_pending_in_progress_errors_and_out_of_space_refused(self):
        for key, value in (
            ("uploadsQueued", 1),
            ("uploadsInProgress", 1),
            ("erroredFiles", 1),
            ("outOfSpace", True),
        ):
            observed = copy.deepcopy(self.value)
            observed["stats"]["diskCache"][key] = value
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                m.clean_queue(observed["stats"], observed["queue"])

    def test_queue_items_refused_despite_clean_counters(self):
        self.value["queue"]["queue"] = [{"id": 3, "name": "staged.sst"}]
        with self.assertRaises(m.Refusal):
            m.clean_queue(self.value["stats"], self.value["queue"])

    def test_missing_or_malformed_telemetry_refused(self):
        for stats, queue in (({}, {"queue": []}), (self.value["stats"], {}), (self.value["stats"], {"queue": None})):
            with self.subTest(stats=stats, queue=queue), self.assertRaises(m.Refusal):
                m.clean_queue(stats, queue)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.profile = m.PROFILES["resume-fixture"]
        self.host = FakeHost()
        self.controller = m.Controller(self.host)

    def mutations(self):
        return [event for event in self.host.events if event[0] in {"stage", "launch", "halt", "lock"}]

    def test_preflight_read_only(self):
        self.controller.preflight(self.profile)
        self.assertTrue(any(event[0] == "guard" for event in self.host.events))
        self.assertEqual(self.mutations(), [])

    def test_malicious_profile_refused_before_host_access(self):
        malicious = replace(
            self.profile, remote="rhea_pebble_lab:ipfs-remote-mount/rhea"
        )
        with self.assertRaises(m.Refusal):
            self.controller.start(malicious, apply=True)
        self.assertEqual(self.host.events, [])

    def test_start_without_apply_runs_guards_and_never_stages(self):
        self.controller.start(self.profile)
        self.assertTrue(any(event[0] == "guard" for event in self.host.events))
        self.assertFalse(self.host.active)
        self.assertEqual(self.mutations(), [])

    def test_simulated_staging_and_apply_only_under_lock(self):
        self.controller.start(self.profile, apply=True)
        self.assertTrue(self.host.active)
        events = [event[0] for event in self.host.events]
        self.assertLess(events.index("stage"), events.index("launch"))
        self.assertLess(events.index("admit"), events.index("launch"))
        self.assertTrue(next(event[2] for event in self.host.events if event[0] == "admit"))
        self.assertTrue(all(event[2] for event in self.host.events if event[0] in {"stage", "launch"}))
        self.assertTrue(any(event[0] == "guard" and event[-1] is True for event in self.host.events))

    def test_failed_guard_never_stages(self):
        self.host.guard_error = m.Refusal("simulated concurrent lab writer")
        with self.assertRaises(m.Refusal):
            self.controller.start(self.profile, apply=True)
        self.assertFalse(any(event[0] in {"stage", "launch"} for event in self.host.events))

    def test_unexpected_missing_dependency_never_stages(self):
        self.host.guard_error = FileNotFoundError("offline fixture: missing systemctl")
        with self.assertRaises((m.Refusal, FileNotFoundError)):
            self.controller.start(self.profile, apply=True)
        self.assertFalse(any(event[0] in {"stage", "launch"} for event in self.host.events))

    def test_status_reports_both_rc_views_without_mutation(self):
        self.host.active = True
        result = self.controller.status(self.profile)
        self.assertIn("stats", result)
        self.assertIn("queue", result)
        self.assertTrue(any(event[0] == "observe" for event in self.host.events))
        self.assertEqual(self.mutations(), [])

    def test_stop_without_apply_never_halts(self):
        self.host.active = True
        self.controller.stop(self.profile)
        self.assertTrue(self.host.active)
        self.assertTrue(any(event[0] == "observe" for event in self.host.events))
        self.assertEqual(self.mutations(), [])

    def test_stop_refuses_dirty_queue_with_or_without_apply(self):
        self.host.active = True
        self.host.observation["queue"]["queue"] = [{"id": 4, "name": "pending.sst"}]
        for apply in (False, True):
            with self.subTest(apply=apply), self.assertRaises(m.Refusal):
                self.controller.stop(self.profile, apply=apply)
        self.assertFalse(any(event[0] == "halt" for event in self.host.events))

    def test_stop_rechecks_queue_inside_lock(self):
        self.host.active = True
        self.host.dirty_on_lock = True
        with self.assertRaises(m.Refusal):
            self.controller.stop(self.profile, apply=True)
        self.assertTrue(self.host.active)
        self.assertFalse(any(event[0] == "halt" for event in self.host.events))

    def test_simulated_clean_stop_preserves_cache_and_never_stages(self):
        self.host.active = True
        self.controller.stop(self.profile, apply=True)
        self.assertFalse(self.host.active)
        halt = [event for event in self.host.events if event[0] == "halt"]
        self.assertEqual(halt, [("halt", self.profile.name, True)])
        self.assertFalse(any(event[0] == "stage" for event in self.host.events))


class RheaCompatibilityTests(unittest.TestCase):
    def test_global_sts_signing_region_is_independent_of_wasabi_s3_region(self):
        self.assertEqual(m.REGION, "ca-central-1")
        self.assertEqual(m.STS_SIGNING_REGION, "us-east-1")
        self.assertNotEqual(m.STS_SIGNING_REGION, m.REGION)

    def test_undecorated_remote_accepted(self):
        profile = m.PROFILES["full-clone"]
        value = clean_observation(profile)
        m.validate_stats(profile, value)
        self.assertTrue(m.remote_matches(profile, profile.remote))

    def test_decorated_remote_accepted(self):
        profile = m.PROFILES["full-clone"]
        remote = profile.remote.replace("rhea_pebble_lab:", "rhea_pebble_lab{_9Ic9}:")
        value = clean_observation(profile)
        value["stats"]["fs"] = remote
        m.validate_stats(profile, value)
        self.assertTrue(m.remote_matches(profile, remote))

    def test_decorated_wrong_bucket_refused(self):
        profile = m.PROFILES["full-clone"]
        value = clean_observation(profile)
        value["stats"]["fs"] = "rhea_pebble_lab{_9Ic9}:ipfs-remote-mount/rhea"
        with self.assertRaises(m.Refusal):
            m.validate_stats(profile, value)

    def test_decorated_wrong_prefix_refused(self):
        profile = m.PROFILES["full-clone"]
        value = clean_observation(profile)
        value["stats"]["fs"] = f"rhea_pebble_lab{{_9Ic9}}:{m.BUCKET}/rhea-other"
        with self.assertRaises(m.Refusal):
            m.validate_stats(profile, value)

    def test_idle_inuse_one_does_not_block_clean_queue(self):
        value = clean_observation(m.PROFILES["full-clone"])
        value["stats"]["inUse"] = 1
        m.clean_queue(value["stats"], value["queue"])

    def test_halt_uses_clean_authenticated_rc_quit_without_systemctl_stop(self):
        host = m.RealHost()
        host.systemctl = "/usr/bin/systemctl"
        profile = m.PROFILES["full-clone"]
        with patch.object(host, "no_open_users") as users, patch.object(
            host, "observe", return_value=clean_observation(profile)
        ), patch.object(host, "rc", return_value={}) as rc, patch.object(
            host, "service", return_value={"ActiveState": "inactive", "SubState": "dead"}
        ), patch.object(
            host, "run", return_value="Result=success\nExecMainCode=1\nExecMainStatus=0\n"
        ) as run, patch.object(Path, "read_text", return_value=""):
            host.halt(profile)
        users.assert_called_once_with(profile)
        rc.assert_called_once_with(profile, "core/quit", {"exitCode": 0})
        self.assertFalse(any("stop" in call.args[0] for call in run.call_args_list))


class CompatibilityTests(LocalHostTests):
    def test_exact_and_decorated_names_pass_stats_and_paths(self):
        for profile in m.PROFILES.values():
            self.profile = profile
            for remote in (profile.remote, profile.remote.replace(":", "{_abc123}:", 1)):
                with self.subTest(remote=remote):
                    observation = clean_observation(profile)
                    observation["stats"]["fs"] = remote
                    m.validate_stats(profile, observation)
                    row = {
                        "target": str(profile.mountpoint), "source": remote,
                        "type": "fuse.rclone", "root": "/", "options": ["rw"],
                    }
                    with self.simulated_paths():
                        self.host.paths(profile, running=True, rows=[row])

    def test_wrong_bucket_and_prefix_fail_stats_and_paths(self):
        profile = self.profile
        variants = (
            profile.remote.replace(m.BUCKET, "ipfs-remote-mount"),
            profile.remote + "-wrong-prefix",
        )
        for remote in variants:
            with self.subTest(remote=remote):
                observation = clean_observation(profile)
                observation["stats"]["fs"] = remote
                with self.assertRaises(m.Refusal):
                    m.validate_stats(profile, observation)
                row = {
                    "target": str(profile.mountpoint), "source": remote,
                    "type": "fuse.rclone", "root": "/", "options": ["rw"],
                }
                with self.simulated_paths(), self.assertRaises(m.Refusal):
                    self.host.paths(profile, running=True, rows=[row])

    def test_vfs_instance_inuse_one_does_not_prevent_clean_stop(self):
        observation = clean_observation(self.profile)
        observation["stats"]["inUse"] = 1
        m.clean_queue(observation["stats"], observation["queue"])
        observation["stats"]["diskCache"]["uploadsQueued"] = 1
        with self.assertRaises(m.Refusal):
            m.clean_queue(observation["stats"], observation["queue"])

    def test_halt_uses_authenticated_graceful_quit_and_checks_exit(self):
        self.host.systemctl = "/offline/systemctl"
        outcome = "Result=success\nExecMainCode=1\nExecMainStatus=0\n"
        with patch.object(self.host, "no_open_users"), patch.object(
            self.host, "observe", return_value=clean_observation(self.profile)
        ), patch.object(self.host, "rc", return_value={}) as rc, patch.object(
            self.host, "service", return_value={"ActiveState": "inactive", "SubState": "dead"}
        ), patch.object(self.host, "run", return_value=outcome) as run, patch.object(
            Path, "read_text", return_value=""
        ):
            self.host.halt(self.profile)
            rc.assert_called_once_with(self.profile, "core/quit", {"exitCode": 0})
            self.assertEqual(run.call_args.args[0][1], "show")


class AdmissionJournalTests(unittest.TestCase):
    def setUp(self):
        self.host = m.RealHost()
        self.profile = m.PROFILES["full-clone"]
        self.host.fingerprints = ("a" * 64, "b" * 64, "c" * 64)
        self.record = dict(m.admission_binding(self.profile, self.host.fingerprints),
                           identity=IdentityTests().identity(), admitted_unix=1)
        self.host.admission_candidate = self.record

    @contextmanager
    def journal_directory(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "admissions"
            # These tests simulate a root-owned protected store on any test UID.
            real_fstat = os.fstat

            def root_stat(fd):
                info = real_fstat(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                       st_uid=0, st_gid=0)

            with patch.object(m, "ADMISSIONS", directory), patch.object(m, "secure_path"), patch.object(
                m.os, "fstat", side_effect=root_stat
            ):
                yield directory / "full-clone.json"

    def test_journal_is_atomic_durable_private_and_unchanged_on_repeat(self):
        with self.journal_directory() as path:
            self.assertIsNone(self.host.read_admission(self.profile))
            self.host.locked = True
            real_fsync = os.fsync
            with patch.object(m.os, "fsync", wraps=real_fsync) as synced:
                self.host.admit(self.profile)
            self.assertEqual(synced.call_count, 3)  # File, containing directory, and new directory's parent.
            self.assertEqual(self.host.read_admission(self.profile), self.record)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            before = path.read_bytes()
            self.host.admit(self.profile)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_missing_lock_or_fresh_admission_evidence_refused(self):
        with self.journal_directory(), self.assertRaisesRegex(m.Refusal, "writer lock"):
            self.host.admit(self.profile)
        self.host.locked = True
        self.host.admission_candidate = None
        with self.journal_directory(), self.assertRaisesRegex(m.Refusal, "fresh baseline"):
            self.host.admit(self.profile)

    def test_journal_binds_profile_paths_inputs_and_identity(self):
        for key, value in (
            ("schema", True), ("profile", "resume-fixture"), ("remote", "production:rhea"),
            ("cache", "/data/wrong"), ("mountpoint", "/mnt/wrong"),
            ("config_sha256", "d" * 64), ("ledger_sha256", "d" * 64),
            ("unit_sha256", "d" * 64),
            ("rclone_sha256", "d" * 64), ("identity", IdentityTests().identity("root")),
            ("admitted_unix", True),
        ):
            with self.subTest(key=key), self.assertRaises(m.Refusal):
                m.validate_admission(dict(self.record, **{key: value}), self.profile, self.host.fingerprints)

    def test_malformed_duplicate_oversized_and_extra_fields_refused(self):
        values = (
            b"{", b"[]", b'{"schema":1,"schema":1}',
            b" " * (m.ADMISSION_MAX_BYTES + 1),
            json.dumps(dict(self.record, certified=True)).encode(),
        )
        with self.journal_directory() as path:
            path.parent.mkdir(mode=0o700)
            for value in values:
                path.write_bytes(value)
                path.chmod(0o600)
                with self.subTest(length=len(value)), self.assertRaises(m.Refusal):
                    self.host.read_admission(self.profile)

    def test_existing_invalid_journal_is_not_overwritten(self):
        with self.journal_directory() as path:
            path.parent.mkdir(mode=0o700)
            path.write_bytes(b"invalid journal")
            self.host.locked = True
            with self.assertRaises(m.Refusal):
                self.host.admit(self.profile)
            self.assertEqual(path.read_bytes(), b"invalid journal")

    def test_symlink_and_hardlinked_journal_rejected(self):
        with self.journal_directory() as path:
            path.parent.mkdir(mode=0o700)
            source = path.parent / "original"
            source.write_text(json.dumps(self.record))
            path.symlink_to(source)
            with self.assertRaises(OSError):  # O_NOFOLLOW remains active even with simulated path metadata.
                self.host.read_admission(self.profile)
            path.unlink()
            os.link(source, path)
            with self.assertRaisesRegex(m.Refusal, "private regular"):
                self.host.read_admission(self.profile)


class RealGuardLifecycleTests(LedgerFixture):
    def setUp(self):
        super().setUp()
        self.host = m.RealHost()
        self.profile = m.PROFILES["full-clone"]
        self.controller = m.Controller(self.host)
        self.s3, self.sts = Mock(), Mock()
        self.identity = IdentityTests().identity()
        self.sts.get_caller_identity.return_value = self.identity
        self.s3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        self.versions = [dict(row, IsLatest=True) for row in self.rows]
        self.s3.get_paginator.return_value.paginate.return_value = [{"Versions": self.versions}]
        self.s3.head_object.side_effect = lambda **kwargs: dict(
            next(row for row in self.rows if row["Key"] == kwargs["Key"]),
            ContentLength=next(row["Size"] for row in self.rows if row["Key"] == kwargs["Key"]),
        )
        self.s3.get_object.side_effect = lambda **kwargs: {
            "VersionId": "version-current", "Body": io.BytesIO(m.CURRENT),
        }
        self.active = True
        self.observation = clean_observation(self.profile)
        self.observation["pid"] = 999

    @contextmanager
    def guarded_host(self, admitted=True):
        blob = ledger_bytes(self.rows)
        binary = b"offline pinned rclone"
        config = ConfigTests().config().encode()
        fingerprints = tuple(hashlib.sha256(value).hexdigest() for value in (binary, config, blob))
        journal = dict(m.admission_binding(self.profile, fingerprints), identity=self.identity, admitted_unix=1)
        states = {name: {"LoadState": "loaded", "ActiveState": "inactive"} for name in m.PROD_OFF}
        states[m.PROD_MOUNT] = {"LoadState": "loaded", "ActiveState": "active", "SubState": "running"}
        states[m.READER] = {"ActiveState": "inactive"}
        protected = {m.RCLONE: binary, m.CONFIG: config, m.LEDGER: blob}
        with self.ledger_constants(blob), patch.object(m, "RCLONE_SHA256", fingerprints[0]), patch.object(
            self.host, "dependencies"
        ), patch.object(self.host, "service", side_effect=lambda name: states[name]), patch.object(
            self.host, "running", side_effect=lambda p: self.active if p == self.profile else False
        ), patch.object(Path, "read_text", return_value=""), patch.object(self.host, "paths") as paths, patch.object(
            self.host, "competitors"
        ), patch.object(m, "read_protected", side_effect=lambda path, **kwargs: protected[path]), patch.object(
            self.host, "read_admission", return_value=journal if admitted else None
        ), patch.object(self.host, "cloud", return_value=(self.s3, self.sts)), patch.object(
            self.host, "observe", side_effect=lambda p: copy.deepcopy(self.observation)
        ), patch.object(self.host, "lock", return_value=nullcontext()), patch.object(
            self.host, "halt", side_effect=lambda p: setattr(self, "active", False)
        ) as halt:
            yield paths, halt

    def mutate_latest(self):
        self.versions[1]["VersionId"] = "new-manifest-version"
        self.versions.append({"Key": "rhea/pebbleds/MANIFEST-47475290", "IsLatest": True,
                              "VersionId": "new-manifest", "Size": 10, "ETag": '"new"'})
        self.s3.get_paginator.return_value.paginate.return_value[0]["DeleteMarkers"] = [
            {"Key": "rhea/pebbleds/47475277.log", "IsLatest": True, "VersionId": "deleted-wal"},
        ]

    def test_unadmitted_first_start_still_rejects_mutated_baseline(self):
        self.active = False
        self.mutate_latest()
        with self.guarded_host(admitted=False), patch.object(self.host, "stage") as stage:
            with self.assertRaises(m.Refusal):
                self.controller.start(self.profile, apply=True)
            stage.assert_not_called()

    def test_admitted_status_and_clean_stop_accept_new_versions_and_delete_markers(self):
        self.mutate_latest()
        with self.guarded_host() as (paths, halt):
            result = self.controller.status(self.profile)
            self.assertEqual(result["pid"], 999)
            self.assertFalse(paths.call_args.kwargs["admission"])
            self.assertTrue(self.controller.stop(self.profile, apply=True)["applied"])
            halt.assert_called_once_with(self.profile)
        self.s3.get_paginator.assert_not_called()
        self.s3.head_object.assert_not_called()

    def test_dirty_errors_and_out_of_space_remain_visible_but_prevent_stop(self):
        self.mutate_latest()
        self.observation["stats"]["diskCache"].update(uploadsQueued=1, erroredFiles=1, outOfSpace=True)
        self.observation["queue"]["queue"] = [{"id": 1, "name": "pebbleds/000001.sst"}]
        with self.guarded_host() as (paths, halt):
            result = self.controller.status(self.profile)
            self.assertTrue(result["stats"]["diskCache"]["outOfSpace"])
            self.assertEqual(len(result["queue"]["queue"]), 1)
            with self.assertRaisesRegex(m.Refusal, "uploads pending"):
                self.controller.stop(self.profile, apply=True)
            halt.assert_not_called()
            self.assertTrue(all(call.kwargs["admission"] is False for call in paths.call_args_list))

    def test_admitted_restart_skips_original_latest_inventory(self):
        self.active = False
        self.mutate_latest()
        with self.guarded_host(), patch.object(self.host, "stage"), patch.object(self.host, "admit"), patch.object(
            self.host, "launch", side_effect=lambda p: setattr(self, "active", True)
        ):
            self.assertTrue(self.controller.start(self.profile, apply=True)["applied"])
        self.s3.get_paginator.assert_not_called()

    def test_first_admission_rejects_unaccounted_cache_but_continuation_preserves_it(self):
        self.active = False
        with patch.object(Path, "exists", return_value=True), patch.object(
            Path, "iterdir", return_value=iter([Path("vfsMeta/pending-file")])
        ), self.guarded_host(admitted=False):
            with self.assertRaisesRegex(m.Refusal, "empty cache"):
                self.controller.preflight(self.profile)
        with patch.object(Path, "iterdir") as cache_contents, self.guarded_host(admitted=True):
            self.controller.preflight(self.profile)
            cache_contents.assert_not_called()

    def test_active_mount_requires_valid_journal_and_exact_admitted_identity(self):
        with self.guarded_host(admitted=False), self.assertRaisesRegex(m.Refusal, "no valid admission"):
            self.controller.status(self.profile)
        with self.guarded_host():
            self.sts.get_caller_identity.return_value = dict(self.identity, UserId="OTHER_USER_ID")
            with self.assertRaisesRegex(m.Refusal, "identity changed"):
                self.controller.status(self.profile)


class QueueExpiryTests(unittest.TestCase):
    def setUp(self):
        self.profile = m.PROFILES["full-clone"]
        self.observation = clean_observation(self.profile)
        self.observation["pid"] = 999
        self.observation["stats"]["diskCache"]["uploadsQueued"] = 1
        self.row = {"id": 7, "name": "pebbleds/marker.format-version.000002.003", "size": 0, "uploading": False}
        self.observation["queue"]["queue"] = [self.row]
        self.selection = dict(item_id=7, name=self.row["name"], size=0, pid=999, expiry="expedite")
        self.host = Mock()
        self.host.running.return_value = True
        self.host.observe.side_effect = lambda p: copy.deepcopy(self.observation)
        self.host.lock.side_effect = lambda: nullcontext()
        self.host.service.return_value = {"MainPID": "999"}
        self.controller = m.Controller(self.host)

    def test_dry_run_validates_closed_tuple_without_mutation(self):
        result = self.controller.queue_expiry(self.profile, **self.selection)
        self.assertFalse(result["applied"])
        self.host.no_open_users.assert_called_once_with(self.profile, expected_pid=999)
        self.host.rc.assert_not_called()
        self.host.lock.assert_not_called()

    def test_expedite_and_defer_use_only_fixed_values_and_pinned_pid(self):
        for choice in m.QUEUE_EXPIRIES:
            with self.subTest(choice=choice):
                args = dict(self.selection, expiry=choice)
                self.assertTrue(self.controller.queue_expiry(self.profile, apply=True, **args)["applied"])
                self.host.rc.assert_called_with(self.profile, "vfs/queue-set-expiry",
                                               {"id": 7, "expiry": m.QUEUE_EXPIRIES[choice]}, expected_pid=999)

    def test_bad_paths_ids_sizes_pids_or_uploading_rows_refused(self):
        variants = (
            {"name": "../production/CURRENT"}, {"name": "pebbleds/../CURRENT"},
            {"name": "CURRENT"}, {"name": "pebbleds/LOCK"}, {"item_id": True},
            {"item_id": 8}, {"size": 1}, {"pid": 1000}, {"expiry": "arbitrary"},
        )
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(m.Refusal):
                self.controller.queue_expiry(self.profile, apply=True, **dict(self.selection, **changed))
        self.row["uploading"] = True
        with self.assertRaises(m.Refusal):
            self.controller.queue_expiry(self.profile, apply=True, **self.selection)
        self.host.rc.assert_not_called()

    def test_recheck_after_lock_refuses_changed_tuple(self):
        first = copy.deepcopy(self.observation)
        changed = copy.deepcopy(first)
        changed["queue"]["queue"][0]["size"] = 100
        self.host.observe.side_effect = [first, changed]
        with self.assertRaises(m.Refusal):
            self.controller.queue_expiry(self.profile, apply=True, **self.selection)
        self.host.rc.assert_not_called()

    def test_duplicate_id_or_name_is_ambiguous(self):
        self.observation["queue"]["queue"].append(dict(self.row, id=8))
        with self.assertRaisesRegex(m.Refusal, "ambiguous"):
            self.controller.queue_expiry(self.profile, apply=True, **self.selection)
        self.host.rc.assert_not_called()

    def test_open_user_prevents_mutation(self):
        self.host.no_open_users.side_effect = m.Refusal("process still uses lab mount")
        with self.assertRaises(m.Refusal):
            self.controller.queue_expiry(self.profile, apply=True, **self.selection)
        self.host.rc.assert_not_called()

    def test_rc_rejects_changed_pid_before_connecting(self):
        host = m.RealHost()
        with patch.object(host, "service"), patch.object(host, "unit_identity", return_value=1000), patch.object(
            m.socket, "socket"
        ) as connect:
            with self.assertRaisesRegex(m.Refusal, "MainPID changed"):
                host.rc(self.profile, "vfs/queue-set-expiry", {"id": 7, "expiry": -1_000_000_000}, expected_pid=999)
            connect.assert_not_called()

    def test_rc_rejects_unscoped_expiry_parameters_and_missing_pid(self):
        host = m.RealHost()
        for parameters, pid in (({"id": 7, "expiry": 0}, 999), ({"id": 7, "expiry": -1_000_000_000}, None),
                                ({"id": 7, "expiry": 86_400, "fs": "production:rhea"}, 999)):
            with self.subTest(parameters=parameters, pid=pid), self.assertRaises(m.Refusal):
                host.rc(self.profile, "vfs/queue-set-expiry", parameters, expected_pid=pid)


if __name__ == "__main__":
    unittest.main()

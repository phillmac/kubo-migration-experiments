#!/usr/bin/env python3
"""Guard the two fixed Rhea lab mounts. Never invokes Kubo or migration tools.

Live commands are for a separately authorized Rhea operator. Development tests
inject a host and S3 clients; importing this module performs no host/cloud I/O.
"""
from __future__ import annotations

import argparse
import configparser
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import gzip
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time
from urllib.parse import urlencode

BUCKET = "rhea-pebble-lab-20261101-39037c6f01"
REGION = "ca-central-1"
IDENTITY = "rhea-pebble-lab-20261101"
REMOTE = "rhea_pebble_lab"
S3_ENDPOINT = "https://s3.ca-central-1.wasabisys.com"
STS_ENDPOINT = "https://sts.wasabisys.com"
CONFIG = Path("/root/.config/rclone/rhea-pebble-lab-20261101.conf")
RCLONE = Path(
    "/root/.local/share/rhea-wasabi-lab-admin-20261101/rclone-v1.68.1"
)
RCLONE_SHA256 = "3afdc72c395651badd72426cc218b0420249ceb10960c03b539939e56e60bf2e"
LEDGER = Path(
    "/root/.local/share/rhea-wasabi-lab-admin-20261101/"
    "wasabi-lab-baseline-version-ledger-20261102.jsonl.gz"
)
LEDGER_SHA256 = "38f7a0179aa7d7e4e166ffbd5818a224d0103e57e318706c578aa3506245fe96"
BASELINE_COUNT = 93_707
BASELINE_SSTS = 93_697
BASELINE_BYTES = 7_786_625_086_413
CURRENT = b"MANIFEST-47475278\n"
CRITICAL_KEYS = (
    "rhea/pebbleds/CURRENT",
    "rhea/pebbleds/MANIFEST-47475278",
    "rhea/version",
    "rhea/datastore_spec",
)
MIN_FREE = 2 * 1024**4
RUNTIME = Path("/run/rhea-wasabi-lab")
UNIT_DIR = Path("/run/systemd/system")
PROD_OFF = (
    "rhea-ipfs-wasabi-kubo.service",
    "rhea-broken-pin-walk-20261026.service",
)
PROD_MOUNT = "rhea-ipfs-wasabi-rclone-mount.service"
READER = "rhea-pebble-lab-reader-fast-mount-20261102.service"
CLEAN_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C",
    "LC_ALL": "C",
}


class Refusal(RuntimeError):
    """A sanitized, operator-readable admission failure."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Refusal(message)


@dataclass(frozen=True)
class Profile:
    name: str
    remote: str
    mountpoint: Path
    cache: Path
    max_cache: str
    writeback: str
    unit: str

    @property
    def rc_socket(self) -> Path:
        return RUNTIME / f"{self.name}.sock"


PROFILES = {
    "full-clone": Profile(
        "full-clone",
        f"{REMOTE}:{BUCKET}/rhea",
        Path("/mnt/rhea-pebble-lab-writable-20261102"),
        Path("/data/rhea-pebble-lab-real-cache-20261102"),
        "96Gi",
        "2h",
        "rhea-pebble-lab-full-clone-20261102.service",
    ),
    "resume-fixture": Profile(
        "resume-fixture",
        f"{REMOTE}:{BUCKET}/__rhea_pebble_resume_probe_20261102",
        Path("/home/ubuntu/pebble-recovery-analysis/kubo-lab-rhea-resume-20261102/run"),
        Path("/data/kubo-lab-rhea-resume-cache-20261102"),
        "512Mi",
        "30m",
        "rhea-pebble-lab-resume-fixture-20261102.service",
    ),
}


def get_profile(value: str | Profile) -> Profile:
    name = value.name if isinstance(value, Profile) else value
    require(isinstance(name, str) and name in PROFILES, "unknown profile")
    expected = PROFILES[name]
    require(not isinstance(value, Profile) or value == expected, "profile substitution")
    return expected


@dataclass(frozen=True)
class LedgerEntry:
    key: str
    version_id: str
    size: int
    etag: str


def _field(row: dict, upper: str, lower: str):
    require(upper in row or lower in row, "ledger field missing")
    if upper in row and lower in row:
        require(row[upper] == row[lower], "conflicting ledger fields")
    return row[upper] if upper in row else row[lower]


def load_ledger(blob: bytes) -> dict[str, LedgerEntry]:
    require(hashlib.sha256(blob).hexdigest() == LEDGER_SHA256, "ledger digest mismatch")
    result = {}
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(blob)) as stream:
            for line in stream:
                require(len(line) < 16_384, "oversized ledger row")
                row = json.loads(line)
                key = _field(row, "Key", "key")
                version = _field(row, "VersionId", "version_id")
                size = _field(row, "Size", "size")
                etag = _field(row, "ETag", "etag")
                require(
                    isinstance(key, str)
                    and key.startswith("rhea/")
                    and not any(x in ("", ".", "..") for x in key.split("/"))
                    and not any(ord(x) < 32 for x in key),
                    "invalid baseline key",
                )
                require(key not in result, "duplicate baseline key")
                require(isinstance(version, str) and version not in ("", "null"), "invalid VersionId")
                require(type(size) is int and size >= 0, "invalid object size")
                require(isinstance(etag, str) and bool(etag), "missing ETag")
                result[key] = LedgerEntry(key, version, size, etag)
                require(len(result) <= BASELINE_COUNT, "unexpected ledger count")
    except Refusal:
        raise
    except Exception:
        raise Refusal("invalid compressed baseline ledger") from None
    require(len(result) == BASELINE_COUNT, "baseline object count mismatch")
    require(sum(x.size for x in result.values()) == BASELINE_BYTES, "baseline byte count mismatch")
    require(sum(k.endswith(".sst") for k in result) == BASELINE_SSTS, "baseline SST count mismatch")
    require(all(k in result for k in CRITICAL_KEYS), "baseline critical key missing")
    return result


def parse_config(text: str) -> tuple[str, str]:
    """Accept only explicit lab credentials. Never return them to the CLI."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
        require(not parser.defaults(), "rclone defaults forbidden")
        require(parser.sections() == [REMOTE], "unexpected rclone remote")
        values = dict(parser[REMOTE])
    except Refusal:
        raise
    except Exception:
        raise Refusal("invalid lab rclone config") from None
    allowed = {
        "type", "provider", "access_key_id", "secret_access_key", "region",
        "endpoint", "env_auth", "acl", "no_check_bucket", "force_path_style",
        "location_constraint",
    }
    require(not (values.keys() - allowed), "unsupported rclone configuration option")
    require(values.get("type") == "s3" and values.get("provider") == "Wasabi", "wrong S3 provider")
    require(values.get("region") == REGION, "wrong S3 region")
    require(values.get("endpoint") in (S3_ENDPOINT, S3_ENDPOINT.removeprefix("https://")), "wrong S3 endpoint")
    require(values.get("env_auth", "false").lower() == "false", "environment credentials forbidden")
    require(values.get("acl", "private") == "private", "nonprivate ACL forbidden")
    require(values.get("location_constraint", REGION) == REGION, "wrong location constraint")
    for option in ("force_path_style", "no_check_bucket"):
        require(values.get(option, "true").lower() == "true", "unsafe S3 option")
    access, secret = values.get("access_key_id", ""), values.get("secret_access_key", "")
    require(bool(re.fullmatch(r"[A-Za-z0-9]{16,128}", access)), "explicit access key required")
    require(bool(secret) and all(32 < ord(c) < 127 for c in secret), "explicit secret required")
    return access, secret


def validate_identity(response: dict) -> None:
    account = response.get("Account")
    require(isinstance(account, str) and bool(re.fullmatch(r"\d{12}", account)), "invalid STS account")
    require(response.get("Arn") == f"arn:aws:iam::{account}:user/{IDENTITY}", "STS identity is not the lab IAM user")
    user_id = response.get("UserId")
    require(isinstance(user_id, str) and bool(user_id) and user_id != account and ":" not in user_id, "root or session identity forbidden")


def _matches(entry: LedgerEntry, value: dict, size_field: str) -> bool:
    return (
        value.get("VersionId") == entry.version_id
        and value.get(size_field) == entry.size
        and value.get("ETag") == entry.etag
        and not value.get("DeleteMarker", False)
    )


def verify_cloud(s3, sts, ledger: dict[str, LedgerEntry]) -> None:
    """Only independent, read-only versioned S3/STS API calls; never rclone."""
    validate_identity(sts.get_caller_identity())
    require(s3.get_bucket_versioning(Bucket=BUCKET).get("Status") == "Enabled", "bucket versioning is not enabled")
    latest = set()
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=BUCKET, Prefix="rhea/"):
        require(not any(x.get("IsLatest") for x in page.get("DeleteMarkers", [])), "baseline has a latest delete marker")
        for value in page.get("Versions", []):
            if value.get("IsLatest") is not True:
                continue
            key = value.get("Key")
            require(key in ledger and key not in latest, "unexpected or duplicate latest baseline key")
            require(_matches(ledger[key], value, "Size"), "original baseline object changed")
            latest.add(key)
    require(latest == ledger.keys(), "baseline latest inventory mismatch")
    for key in CRITICAL_KEYS:
        entry = ledger[key]
        for kwargs in ({}, {"VersionId": entry.version_id}):
            head = s3.head_object(Bucket=BUCKET, Key=key, **kwargs)
            require(_matches(entry, head, "ContentLength"), "critical object HEAD mismatch")
    entry = ledger[CRITICAL_KEYS[0]]
    response = s3.get_object(Bucket=BUCKET, Key=entry.key, VersionId=entry.version_id)
    require(response.get("VersionId") == entry.version_id, "CURRENT GET VersionId mismatch")
    body = response["Body"]
    try:
        require(body.read(len(CURRENT) + 1) == CURRENT, "frozen CURRENT content mismatch")
    finally:
        body.close()


def remote_matches(profile: Profile, value: str) -> bool:
    p = get_profile(profile)
    if not isinstance(value, str):
        return False
    suffix = p.remote.split(":", 1)[1]
    pattern = re.escape(REMOTE) + r"(?:\{_[A-Za-z0-9_-]{1,64}\})?:" + re.escape(suffix)
    return re.fullmatch(pattern, value) is not None


def validate_stats(profile: Profile, observation: dict) -> None:
    require(isinstance(observation, dict), "invalid RC response")
    stats, queue = observation.get("stats"), observation.get("queue")
    require(isinstance(stats, dict) and isinstance(queue, dict), "missing RC stats or queue")
    require(remote_matches(profile, stats.get("fs")), "RC filesystem substitution")
    disk = stats.get("diskCache")
    require(isinstance(disk, dict), "missing disk cache statistics")
    for key in ("uploadsQueued", "uploadsInProgress", "erroredFiles"):
        require(type(disk.get(key)) is int and disk[key] >= 0, "invalid cache counters")
    require(type(disk.get("outOfSpace")) is bool, "missing out-of-space evidence")
    require(isinstance(queue.get("queue"), list), "missing VFS queue evidence")


def clean_queue(stats: dict, queue: dict) -> None:
    disk = stats.get("diskCache", {})
    require(
        all(type(disk.get(k)) is int and disk[k] == 0 for k in ("uploadsQueued", "uploadsInProgress", "erroredFiles"))
        and disk.get("outOfSpace") is False
        and queue.get("queue") == [],
        "refuse stop: uploads pending, in progress, errored, or out of space",
    )


def secure_path(path: Path, *, leaf_mode: int | None = None, missing: bool = False) -> None:
    """No symlinks, untrusted owners, writable ancestors, or hardlinked files."""
    require(path.is_absolute() and ".." not in path.parts, "noncanonical path")
    for component in (*reversed(path.parents), path):
        try:
            info = component.lstat()
        except FileNotFoundError:
            require(missing, "required path missing")
            continue
        require(not stat.S_ISLNK(info.st_mode), "symlink path substitution")
        require(info.st_uid == 0 and info.st_gid == 0, "path is not root owned")
        require(info.st_mode & 0o022 == 0, "path writable by non-root")
        if component != path:
            require(stat.S_ISDIR(info.st_mode), "nondirectory path ancestor")
        elif leaf_mode is not None:
            require(stat.S_IMODE(info.st_mode) == leaf_mode, "incorrect private path mode")
        if stat.S_ISREG(info.st_mode):
            require(info.st_nlink == 1, "hardlinked protected file")


def read_protected(path: Path, *, mode: int | None = None) -> bytes:
    secure_path(path, leaf_mode=mode)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "not a private regular file")
        require(info.st_uid == 0 and info.st_gid == 0 and info.st_mode & 0o022 == 0, "untrusted protected file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read()
    finally:
        os.close(fd)


def mount_rows(text: str) -> list[dict]:
    def unescape(value: str) -> str:
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)

    rows = []
    for line in text.splitlines():
        fields = line.split()
        require("-" in fields and len(fields) >= 10, "invalid mountinfo")
        dash = fields.index("-")
        require(dash >= 6 and len(fields) > dash + 3, "invalid mountinfo fields")
        rows.append({
            "root": unescape(fields[3]), "target": unescape(fields[4]),
            "options": fields[5].split(","), "type": fields[dash + 1],
            "source": unescape(fields[dash + 2]),
        })
    return rows


def mount_command(profile: Profile) -> list[str]:
    p = get_profile(profile)
    return [
        str(RCLONE), "mount", p.remote, str(p.mountpoint),
        "--config", str(CONFIG), "--cache-dir", str(p.cache),
        "--vfs-cache-mode", "full", "--vfs-cache-max-size", p.max_cache,
        "--vfs-write-back", p.writeback, "--vfs-cache-max-age", "168h",
        "--vfs-cache-poll-interval", "1m", "--buffer-size", "16Mi",
        "--transfers", "2", "--checkers", "4", "--s3-no-check-bucket",
        "--umask", "077", "--dir-perms", "0700", "--file-perms", "0600",
        "--default-permissions", "--rc", "--rc-addr", "unix://" + str(p.rc_socket),
        "--rc-no-auth", "--log-level", "ERROR",
    ]


def render_unit(profile: Profile) -> str:
    p = get_profile(profile)
    # Every argument is from the fixed registry; no shell or credential contents.
    command = " ".join(mount_command(p))
    return f"""# Generated by rhea_wasabi_lab_mount.py; use wrapper admission checks.
[Unit]
Description=Guarded Rhea Wasabi lab {p.name}
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C {command}
Restart=no
KillMode=control-group
KillSignal=SIGTERM
TimeoutStartSec=90
TimeoutStopSec=120
SendSIGKILL=no
MemoryMax={'8G' if p.name == 'full-clone' else '2G'}
MemorySwapMax=0
TasksMax=128
CPUQuota=200%
IOWeight=100
Nice=10
LimitNOFILE=65536
PrivateTmp=no
PrivateMounts=no
StandardOutput=null
StandardError=null
"""


class RealHost:
    """Live adapter. Only called by an explicit CLI command on Rhea as root."""

    def __init__(self):
        self.systemctl = None
        self.fusermount = None
        self.fingerprints = None

    def run(self, args: list[str], timeout: int = 120) -> str:
        try:
            completed = subprocess.run(
                args, check=True, capture_output=True, text=True, timeout=timeout,
                env=CLEAN_ENV, stdin=subprocess.DEVNULL,
            )
            return completed.stdout
        except (OSError, subprocess.SubprocessError):
            raise Refusal("host command failed (details suppressed)") from None

    def dependencies(self) -> None:
        require(os.geteuid() == 0, "root required on Rhea")
        require(socket.gethostname().split(".")[0].lower() == "rhea", "Rhea host required")
        require(
            not any(key.startswith(("AWS_", "BOTO_", "RCLONE_")) for key in os.environ),
            "ambient cloud or rclone environment forbidden",
        )
        self.systemctl = shutil.which("systemctl", path=CLEAN_ENV["PATH"])
        self.fusermount = shutil.which("fusermount3", path=CLEAN_ENV["PATH"])
        require(bool(self.systemctl) and bool(self.fusermount), "required systemctl or fusermount3 missing")
        for path in (Path(self.systemctl).resolve(), Path(self.fusermount).resolve(), Path("/usr/bin/env")):
            secure_path(path)
        require(Path("/dev/fuse").is_char_device(), "FUSE device unavailable")

    def service(self, name: str) -> dict[str, str]:
        if self.systemctl is None:
            self.dependencies()
        fields = (
            "Id,LoadState,ActiveState,SubState,User,Group,MainPID,ControlGroup,"
            "FragmentPath,DropInPaths,NeedDaemonReload"
        )
        output = self.run([self.systemctl, "show", name, f"--property={fields}"])
        values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        require(values.get("Id") == name, "systemd service identity mismatch")
        return values

    def running(self, profile: Profile) -> bool:
        p = get_profile(profile)
        state = self.service(p.unit)
        require(state.get("ActiveState") in ("active", "inactive"), "lab service not stably active/inactive")
        if state.get("LoadState") == "loaded":
            self.unit_identity(p, state, active=state["ActiveState"] == "active")
        else:
            require(state.get("LoadState") == "not-found" and state["ActiveState"] == "inactive", "unexpected lab unit load state")
        return state["ActiveState"] == "active"

    def unit_identity(self, p: Profile, state: dict, *, active: bool) -> int:
        unit = UNIT_DIR / p.unit
        require(state.get("FragmentPath") == str(unit) and not state.get("DropInPaths"), "substituted lab unit or drop-in")
        require(state.get("NeedDaemonReload") == "no", "systemd unit needs reload")
        require(read_protected(unit, mode=0o600).decode() == render_unit(p), "lab unit content mismatch")
        if not active:
            return 0
        require(state.get("User") == "root" and state.get("Group") == "root", "lab service must be root")
        require(state.get("SubState") == "running", "lab service not running")
        group = f"/system.slice/{p.unit}"
        require(state.get("ControlGroup") == group, "lab control group mismatch")
        require(state.get("MainPID", "").isdigit() and int(state["MainPID"]) > 1, "missing lab MainPID")
        pid = int(state["MainPID"])
        proc = Path("/proc") / str(pid)
        require((proc / "exe").resolve() == RCLONE, "lab process executable mismatch")
        require((proc / "cmdline").read_bytes().split(b"\0")[:-1] == [x.encode() for x in mount_command(p)], "lab process arguments mismatch")
        require(any(line.rsplit(":", 1)[-1] == group for line in (proc / "cgroup").read_text().splitlines()), "lab process control group mismatch")
        uid = next((line.split()[1:] for line in (proc / "status").read_text().splitlines() if line.startswith("Uid:")), [])
        require(uid == ["0"] * 4, "lab process is not root")
        return pid

    def paths(self, p: Profile, running: bool, rows: list[dict]) -> None:
        secure_path(RUNTIME, leaf_mode=0o700, missing=True)
        secure_path(p.cache, leaf_mode=0o700, missing=True)
        require(not p.cache.exists() or p.cache.is_dir(), "cache is not a directory")
        secure_path(p.mountpoint.parent, missing=True)
        matches = [r for r in rows if r["target"] == str(p.mountpoint)]
        require(len(matches) == (1 if running else 0), "unexpected or missing target mount")
        if running:
            row = matches[0]
            require(row["type"] == "fuse.rclone" and remote_matches(p, row["source"]) and row["root"] == "/" and "rw" in row["options"], "mounted source/type/options mismatch")
        else:
            secure_path(p.mountpoint, leaf_mode=0o700, missing=True)
            require(not p.mountpoint.exists() or (p.mountpoint.is_dir() and not any(p.mountpoint.iterdir())), "unmounted target is not empty")
            require(not p.rc_socket.exists() and not p.rc_socket.is_symlink(), "stale or substituted RC socket")
        for row in rows:
            target = Path(row["target"])
            for protected in (p.mountpoint, p.cache, RUNTIME, CONFIG, RCLONE, LEDGER):
                # Normal host filesystem roots are allowed; deeper bind mounts are not.
                if target in (Path("/"), Path("/data"), Path("/home"), Path("/mnt"), Path("/run")):
                    continue
                if target == p.mountpoint and running:
                    continue
                require(not (target == protected or target in protected.parents or protected in target.parents), "mount overlaps protected path")
        base = p.cache
        while not base.exists():
            base = base.parent
        space = os.statvfs(base)
        require(space.f_bavail * space.f_frsize >= MIN_FREE, "less than 2 TiB cache filesystem free")

    def competitors(self, p: Profile, running: bool, rows: list[dict]) -> None:
        own_pid = self.unit_identity(p, self.service(p.unit), active=True) if running else None
        for row in rows:
            if BUCKET in row["source"] or row["source"].startswith(REMOTE + ":"):
                if running and row["target"] == str(p.mountpoint):
                    continue
                require(p.name == "resume-fixture" and row["type"] == "fuse.rclone" and "ro" in row["options"], "concurrent lab writer mount")
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit() or int(proc.name) in (os.getpid(), own_pid):
                continue
            try:
                args = (proc / "cmdline").read_bytes().split(b"\0")[:-1]
            except FileNotFoundError:
                continue
            if not args:
                continue
            related = any(BUCKET.encode() in a or str(CONFIG).encode() == a or str(p.cache).encode() == a for a in args)
            if related:
                require(p.name == "resume-fixture" and b"--read-only" in args and b"mount" in args, "concurrent lab writer process")

    def cloud(self, credentials: tuple[str, str]):
        try:
            import boto3
            import botocore.session
            from botocore.config import Config
        except ImportError:
            raise Refusal("required boto3/botocore dependency missing") from None
        # Explicit credentials, endpoints, and disabled proxies avoid host credentials.
        settings = Config(
            signature_version="s3v4", connect_timeout=10, read_timeout=30,
            retries={"max_attempts": 2, "mode": "standard"}, proxies={},
        )
        isolated = botocore.session.Session()
        isolated.set_config_variable("config_file", os.devnull)
        isolated.set_config_variable("credentials_file", os.devnull)
        session = boto3.Session(
            aws_access_key_id=credentials[0], aws_secret_access_key=credentials[1],
            region_name=REGION, botocore_session=isolated,
        )
        return (
            session.client("s3", endpoint_url=S3_ENDPOINT, config=settings),
            session.client("sts", endpoint_url=STS_ENDPOINT, config=settings.merge(Config(signature_version="v4"))),
        )

    def guard(self, profile: Profile, running: bool) -> None:
        p = get_profile(profile)
        self.dependencies()
        for name in PROD_OFF:
            state = self.service(name)
            require(state.get("LoadState") == "loaded" and state.get("ActiveState") == "inactive", "production Kubo/pin walker must stay inactive")
        state = self.service(PROD_MOUNT)
        require(state.get("LoadState") == "loaded" and state.get("ActiveState") == "active" and state.get("SubState") == "running", "production rclone must remain active")
        if p.name == "full-clone":
            require(self.service(READER).get("ActiveState") == "inactive", "stop read-only lab reader separately first")
        for other in PROFILES.values():
            if other != p:
                require(not self.running(other), "another lab profile is active")
        require(self.running(p) == running, "lab state changed during admission")
        rows = mount_rows(Path("/proc/self/mountinfo").read_text())
        self.paths(p, running, rows)
        self.competitors(p, running, rows)
        binary = read_protected(RCLONE)
        require(hashlib.sha256(binary).hexdigest() == RCLONE_SHA256, "pinned rclone digest mismatch")
        config = read_protected(CONFIG, mode=0o600)
        ledger_blob = read_protected(LEDGER)
        fingerprints = tuple(hashlib.sha256(b).hexdigest() for b in (binary, config, ledger_blob))
        require(self.fingerprints in (None, fingerprints), "protected input changed during operation")
        self.fingerprints = fingerprints
        ledger = load_ledger(ledger_blob)
        credentials = parse_config(config.decode())
        s3, sts = self.cloud(credentials)
        try:
            verify_cloud(s3, sts, ledger)
        finally:
            s3.close()
            sts.close()

    def rc(self, profile: Profile, method: str, parameters: dict | None = None) -> dict:
        p = get_profile(profile)
        require(method in ("vfs/stats", "vfs/queue", "core/quit"), "RC method forbidden")
        if method == "core/quit":
            require(parameters == {"exitCode": 0}, "nonzero quit forbidden")
        else:
            require(not parameters, "unexpected RC parameters")
        pid = self.unit_identity(p, self.service(p.unit), active=True)
        secure_path(RUNTIME, leaf_mode=0o700)
        info = p.rc_socket.lstat()
        require(
            stat.S_ISSOCK(info.st_mode) and info.st_uid == info.st_gid == 0
            and info.st_mode & 0o077 == 0,
            "RC socket is not root protected",
        )
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(15)
        try:
            connection.connect(str(p.rc_socket))
            peer = connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            require(struct.unpack("3i", peer) == (pid, 0, 0),
                    "RC socket peer is not the lab MainPID")
            http = http.client.HTTPConnection("localhost", timeout=15)
            http.sock = connection
            http.request(
                "POST", "/" + method, body=urlencode(parameters or {}),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response = http.getresponse()
            require(response.status == 200, "RC request failed")
            body = response.read(4 * 1024**2 + 1)
            require(len(body) <= 4 * 1024**2, "RC response exceeds bound")
            result = json.loads(body)
            require(isinstance(result, dict), "invalid RC response")
            return result
        finally:
            connection.close()

    def observe(self, profile: Profile) -> dict:
        p = get_profile(profile)
        pid = self.unit_identity(p, self.service(p.unit), active=True)
        result = {"stats": self.rc(p, "vfs/stats"), "queue": self.rc(p, "vfs/queue")}
        validate_stats(p, result)
        require(self.service(p.unit).get("MainPID") == str(pid),
                "lab service restarted during RC observation")
        return result

    def no_open_users(self, profile: Profile) -> None:
        p = get_profile(profile)
        pid = self.unit_identity(p, self.service(p.unit), active=True)
        prefix = str(p.mountpoint)
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit() or int(proc.name) in (os.getpid(), pid):
                continue
            try:
                refs = [proc / "cwd", proc / "root", *list((proc / "fd").iterdir())]
                for ref in refs:
                    try:
                        target = os.readlink(ref).removesuffix(" (deleted)")
                    except FileNotFoundError:
                        continue
                    require(not (target == prefix or target.startswith(prefix + "/")), "refuse stop: process still uses lab mount")
                maps = (proc / "maps").read_text()
                require(not any(prefix in line for line in maps.splitlines()), "refuse stop: process maps lab files")
            except FileNotFoundError:
                continue

    @contextmanager
    def lock(self):
        self.mkdir_private(RUNTIME)
        lock_path = RUNTIME / "writer.lock"
        secure_path(lock_path, leaf_mode=0o600, missing=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o600, "unsafe writer lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal("another lab wrapper operation holds writer lock") from None
            yield
        finally:
            os.close(fd)

    def mkdir_private(self, path: Path) -> None:
        secure_path(path, leaf_mode=0o700, missing=True)
        if not path.exists():
            if not path.parent.exists():
                self.mkdir_private(path.parent)
            path.mkdir(mode=0o700)
        secure_path(path, leaf_mode=0o700)

    def stage(self, profile: Profile) -> None:
        p = get_profile(profile)
        for directory in (p.mountpoint, p.cache, RUNTIME):
            self.mkdir_private(directory)
        secure_path(UNIT_DIR)
        destination = UNIT_DIR / p.unit
        expected = render_unit(p).encode()
        if destination.exists():
            require(read_protected(destination, mode=0o600) == expected, "refuse replacing unexpected unit")
        else:
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(expected)
                stream.flush()
                os.fsync(stream.fileno())
        self.run([self.systemctl, "daemon-reload"])

    def launch(self, profile: Profile) -> None:
        p = get_profile(profile)
        self.run([self.systemctl, "start", p.unit])
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            state = self.service(p.unit)
            require(state.get("ActiveState") in ("active", "activating"),
                    "lab service failed during start")
            rows = mount_rows(Path("/proc/self/mountinfo").read_text())
            mounted = any(
                row["target"] == str(p.mountpoint) and row["type"] == "fuse.rclone"
                and remote_matches(p, row["source"]) for row in rows
            )
            if state.get("ActiveState") == "active" and mounted and p.rc_socket.exists():
                self.unit_identity(p, state, active=True)
                return
            time.sleep(0.1)
        raise Refusal("lab mount did not become host visible before deadline")

    def halt(self, profile: Profile) -> None:
        p = get_profile(profile)
        self.no_open_users(p)
        observation = self.observe(p)
        clean_queue(observation["stats"], observation["queue"])
        self.rc(p, "core/quit", {"exitCode": 0})
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            state = self.service(p.unit)
            if state.get("ActiveState") == "inactive":
                require(state.get("SubState") == "dead", "lab service did not exit cleanly")
                outcome = self.run([
                    self.systemctl, "show", p.unit,
                    "--property=Result,ExecMainCode,ExecMainStatus",
                ])
                values = dict(line.split("=", 1) for line in outcome.splitlines() if "=" in line)
                require(values.get("Result") == "success"
                        and values.get("ExecMainCode") == "1"
                        and values.get("ExecMainStatus") == "0", "lab process exit failed")
                break
            require(state.get("ActiveState") in ("active", "deactivating"),
                    "lab service failed during graceful quit")
            time.sleep(0.1)
        else:
            raise Refusal("lab service did not exit after graceful quit")
        rows = mount_rows(Path("/proc/self/mountinfo").read_text())
        require(not any(r["target"] == str(p.mountpoint) for r in rows),
                "lab mount remains after stop")
        # Never remove cache, force unmount, discard writes, or expedite uploads.


class Controller:
    def __init__(self, host=None):
        self.host = RealHost() if host is None else host

    def preflight(self, profile: str | Profile) -> dict:
        p = get_profile(profile)
        running = self.host.running(p)
        self.host.guard(p, running=running)
        return {"profile": p.name, "preflight": "passed", "running": running}

    def start(self, profile: str | Profile, apply: bool = False) -> dict:
        p = get_profile(profile)
        require(not self.host.running(p), "lab profile already active")
        self.host.guard(p, running=False)
        result = {"profile": p.name, "action": "start", "applied": False, "unit": render_unit(p)}
        if apply:
            with self.host.lock():
                self.host.guard(p, running=False)
                self.host.stage(p)
                self.host.guard(p, running=False)
                self.host.launch(p)
                # On failure, leave service/cache untouched for operator diagnosis.
                self.host.guard(p, running=True)
                observation = self.host.observe(p)
                validate_stats(p, observation)
                result["applied"] = True
                result.update(observation)
        return result

    def status(self, profile: str | Profile) -> dict:
        p = get_profile(profile)
        running = self.host.running(p)
        self.host.guard(p, running=running)
        result = {"profile": p.name, "running": running}
        if running:
            observation = self.host.observe(p)
            validate_stats(p, observation)
            result.update(observation)
        return result

    def stop(self, profile: str | Profile, apply: bool = False) -> dict:
        p = get_profile(profile)
        running = self.host.running(p)
        self.host.guard(p, running=running)
        result = {"profile": p.name, "action": "stop", "applied": False, "running": running}
        if not running:
            return result
        observation = self.host.observe(p)
        validate_stats(p, observation)
        clean_queue(observation["stats"], observation["queue"])
        if apply:
            with self.host.lock():
                self.host.guard(p, running=True)
                observation = self.host.observe(p)
                validate_stats(p, observation)
                clean_queue(observation["stats"], observation["queue"])
                self.host.halt(p)
                self.host.guard(p, running=False)
                result["applied"] = True
                result["running"] = False
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "start", "status", "stop"))
    parser.add_argument("--profile", required=True, choices=tuple(PROFILES))
    parser.add_argument("--apply", action="store_true", help="required for start/stop mutations")
    args = parser.parse_args(argv)
    if args.apply and args.command not in ("start", "stop"):
        parser.error("--apply is only valid for start/stop")
    try:
        controller = Controller()
        method = getattr(controller, args.command)
        result = method(args.profile, apply=args.apply) if args.command in ("start", "stop") else method(args.profile)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except Refusal as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
    except Exception:
        # SDK, parser, kernel and subprocess exceptions can contain secret material.
        print("FAIL_CLOSED: unexpected dependency, host, or cloud failure (details suppressed)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

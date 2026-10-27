#!/usr/bin/env python3
"""Synthetic-only Kubo/Pebble rehearsal. Never accepts an existing repository.

Run inside a network namespace with only loopback, using checksum-verified
binaries. No downloads, daemon, production data, credentials, or migrations
are performed implicitly. A successful bridge test is NOT production approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time


class Refusal(RuntimeError):
    pass


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def interfaces(text):
    return {line.split(":", 1)[0].strip() for line in text.splitlines()[2:] if ":" in line}


def require_isolation(text=None):
    names = interfaces(Path("/proc/net/dev").read_text() if text is None else text)
    if names != {"lo"}:
        raise Refusal("Requires a private network namespace with loopback only")


def verify_binary(path, sha256):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not os.access(str(path), os.X_OK):
        raise Refusal("Binary must be an executable regular file, not a symlink")
    if not re.fullmatch(r"[0-9a-f]{64}", sha256 or "") or digest(path) != sha256:
        raise Refusal("Binary SHA-256 mismatch or missing digest")
    return path.resolve()


def guard_repo(lab, repo):
    lab, repo = Path(lab).resolve(), Path(repo)
    if repo.is_symlink() or repo.resolve().parent != lab:
        raise Refusal("Repository must be a direct, nonsymlink lab child")
    for path in repo.rglob("*"):
        if path.is_symlink() or (not path.is_dir() and not path.is_file()) or (path.is_file() and path.stat().st_nlink != 1):
            raise Refusal("Symlink, hardlink or special file in synthetic repository")
    if (repo / "api").exists():
        raise Refusal("Unexpected API file: refusing daemon redirection")
    config = repo / "config"
    if config.exists():
        data = json.loads(config.read_text())
        def walk(node):
            if isinstance(node, dict):
                if node.get("type") not in (None, "measure", "mount", "pebbleds"):
                    raise Refusal("Only local pebbleds wrappers are allowed")
                if node.get("type") == "pebbleds":
                    p = Path(node.get("path", ""))
                    if not str(p) or str(p) == "." or p.is_absolute() or ".." in p.parts:
                        raise Refusal("Datastore path escapes synthetic repository")
                    try:
                        (repo / p).resolve().relative_to(repo.resolve())
                    except ValueError:
                        raise Refusal("Datastore path escapes lab")
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(data.get("Datastore", {}).get("Spec", {}))


def tree_hashes(root):
    root = Path(root)
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob("*")) if p.is_file()}


class Lab:
    def __init__(self, base):
        original = Path(base).absolute()
        base = original.resolve(strict=True)
        if base != original or not base.name.startswith("kubo-scratch-"):
            raise Refusal("Use a nonsymlink kubo-scratch-* scratch parent")
        if any(p.startswith(".ipfs") or p in ("ipfs-cache", "pebbleds") for p in base.parts):
            raise Refusal("Scratch parent must not be inside an IPFS repository/cache")
        mount_type = None
        longest = -1
        for line in Path("/proc/self/mountinfo").read_text().splitlines():
            left, right = line.split(" - ", 1)
            mountpoint = Path(left.split()[4].replace("\\040", " ").replace("\\134", "\\"))
            if mountpoint == base or mountpoint in base.parents:
                if len(str(mountpoint)) > longest:
                    mount_type, longest = right.split()[0], len(str(mountpoint))
        if mount_type not in ("ext4", "xfs", "btrfs", "zfs", "overlay", "tmpfs"):
            raise Refusal("Scratch must be a recognised local filesystem, not FUSE/network")
        if shutil.disk_usage(str(base)).free < 2 * 1024 ** 3:
            raise Refusal("At least 2 GiB free is required for the small synthetic test")
        self.root = Path(tempfile.mkdtemp(prefix="kubo-lab-", dir=str(base)))
        (self.root / "home").mkdir()
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        self.events = []

    def run(self, binary, repo, *args, allow_failure=False):
        guard_repo(self.root, repo)
        require_isolation()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root / "home"),
               "IPFS_PATH": str(repo), "GOMAXPROCS": "2", "GOMEMLIMIT": "512MiB",
               "LANG": "C.UTF-8"}
        cmd = [str(binary), "--offline"] + list(args)
        started = time.monotonic()
        proc = subprocess.Popen(cmd, cwd=str(self.root), env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True)
        pgid = proc.pid
        try:
            out, err = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            os.killpg(pgid, signal.SIGTERM)
            try:
                out, err = proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                out, err = proc.communicate(timeout=3)
            raise Refusal("Synthetic command timed out; no retry")
        finally:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                pass
            else:
                os.killpg(pgid, signal.SIGKILL)
                raise Refusal("Unexpected surviving command descendants")
        event = {"binary_sha256": digest(binary), "repo": Path(repo).name,
                 "args": list(args), "returncode": proc.returncode,
                 "elapsed_seconds": round(time.monotonic() - started, 3),
                 "stdout_sha256": hashlib.sha256(out).hexdigest(),
                 "stderr": err.decode("utf-8", "replace")[-6000:]}
        self.events.append(event)
        (self.evidence / "commands.json").write_text(json.dumps(self.events, indent=2) + "\n")
        if len(out) > 8 * 1024 * 1024 or len(err) > 8 * 1024 * 1024:
            raise Refusal("Unexpected output size")
        if proc.returncode and not allow_failure:
            raise Refusal("Synthetic command failed: " + event["stderr"])
        return proc.returncode, out

    def fingerprint(self, binary, repo, root, raw, payload, raw_payload):
        def get(*args):
            return self.run(binary, repo, *args)[1]
        if get("cat", root) != payload or get("block", "get", raw) != raw_payload:
            raise Refusal("Payload bytes changed")
        return {"recursive_pins": sorted(get("pin", "ls", "--type=recursive", "--quiet").decode().splitlines()),
                "direct_pins": sorted(get("pin", "ls", "--type=direct", "--quiet").decode().splitlines()),
                "mfs_root": get("files", "stat", "--hash", "/").decode().strip(),
                "file_root": root, "raw_cid": raw,
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "raw_sha256": hashlib.sha256(raw_payload).hexdigest()}

    def clone(self, source, name):
        dest = self.root / name
        guard_repo(self.root, source)
        shutil.copytree(str(source), str(dest), copy_function=shutil.copy2)
        guard_repo(self.root, dest)
        return dest


def migrate_schema(lab, binary, repo):
    """Explicit schema16->18 migration of a guarded synthetic copy only."""
    repo = Path(repo)
    guard_repo(lab.root, repo)
    before_version = (repo / "version").read_text().strip()
    if before_version != "16":
        raise Refusal("Schema migration requires an exact version16 fixture")
    before = json.loads((repo / "config").read_text())
    if "Identity" not in before or "Datastore" not in before:
        raise Refusal("Missing identity or datastore baseline")
    disk_spec = digest(repo / "datastore_spec")
    _, output = lab.run(binary, repo, "repo", "migrate", "--to=18")
    guard_repo(lab.root, repo)
    if (repo / "version").read_text().strip() != "18":
        raise Refusal("Migrator did not produce repository schema18")
    after = json.loads((repo / "config").read_text())
    if before["Identity"] != after.get("Identity"):
        raise Refusal("Migration changed synthetic identity")
    if before["Datastore"] != after.get("Datastore") or digest(repo / "datastore_spec") != disk_spec:
        raise Refusal("Migration changed datastore layout/configuration")
    return {"from": before_version, "to": "18", "identity_preserved": True,
            "datastore_preserved": True,
            "changed_config_sections": sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k)),
            "stdout": output.decode("utf-8", "replace")[-6000:]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Existing scratch parent; creates a NEW random child")
    for label in ("old", "bridge", "target"):
        parser.add_argument("--" + label, required=True, help="Verified Kubo executable")
        parser.add_argument("--" + label + "-sha256", required=True)
    parser.add_argument("--migrate-target", action="store_true", help="Explicitly run bundled schema16->18 migration on an additional synthetic clone")
    args = parser.parse_args()
    os.umask(0o077)
    def interrupted(signum, _frame):
        raise Refusal("Lab interrupted by signal %d" % signum)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    require_isolation()
    bins = {name: verify_binary(getattr(args, name), getattr(args, name + "_sha256"))
            for name in ("old", "bridge", "target")}
    lab = Lab(args.base)
    report = {"scope": "synthetic-local-pebbleds-only", "production_approved": False,
              "target_migration_verified": False, "lab_path": str(lab.root)}
    print("EVIDENCE=" + str(lab.evidence), flush=True)
    try:
        repo = lab.root / "seed"
        repo.mkdir()
        for name, expected in (("old", "0.31.0"), ("bridge", "0.34.1"), ("target", "0.43.1")):
            version = lab.run(bins[name], repo, "version", "--number")[1].decode().strip()
            if version != expected:
                raise Refusal("Unexpected binary version for " + name + ": " + version)
        lab.run(bins["old"], repo, "init", "--profile=pebbleds")
        payload = bytes(range(256)) * 8192
        raw_payload = b"synthetic unpinned raw block - migration lab\n"
        source = lab.root / "fixture.bin"
        source.write_bytes(payload)
        raw_source = lab.root / "raw.bin"
        raw_source.write_bytes(raw_payload)
        root = lab.run(bins["old"], repo, "add", "-Q", "--cid-version=0", "--raw-leaves=false", str(source))[1].decode().strip()
        raw = lab.run(bins["old"], repo, "block", "put", "--cid-codec=raw", "--mhtype=sha2-256", str(raw_source))[1].decode().strip()
        lab.run(bins["old"], repo, "files", "cp", "/ipfs/" + root, "/fixture.bin")
        baseline = lab.fingerprint(bins["old"], repo, root, raw, payload, raw_payload)
        sealed = tree_hashes(repo)
        report["seed_file_hashes"] = sealed
        report["seed_repo_version"] = (repo / "version").read_text().strip()
        bridge = lab.clone(repo, "bridge")
        after = lab.fingerprint(bins["bridge"], bridge, root, raw, payload, raw_payload)
        if baseline != after:
            raise Refusal("Bridge changed pins, MFS root or payloads")
        report["bridge_verified"] = True
        report["fingerprint"] = baseline
        report["bridge_repo_version"] = (bridge / "version").read_text().strip()
        report["bridge_format_markers"] = [str(p.relative_to(bridge)) for p in bridge.rglob("*format-version*")]
        target = lab.clone(bridge, "target-probe")
        code, _ = lab.run(bins["target"], target, "pin", "ls", "--type=recursive", "--quiet", allow_failure=True)
        report["target_probe_returncode"] = code
        if code == 0:
            target_fp = lab.fingerprint(bins["target"], target, root, raw, payload, raw_payload)
            if target_fp != baseline:
                raise Refusal("Target changed synthetic content/pins/MFS")
            report["target_migration_verified"] = True
        else:
            report["target_status"] = "blocked; inspect error and stage explicit offline migrations"
        if args.migrate_target:
            if code != 1 or "repo needs migration" not in lab.events[-1]["stderr"].lower():
                raise Refusal("Expected schema-version refusal was not established")
            migrated = lab.clone(bridge, "target-migrated")
            report["schema_migration"] = migrate_schema(lab, bins["target"], migrated)
            target_fp = lab.fingerprint(bins["target"], migrated, root, raw, payload, raw_payload)
            if target_fp != baseline:
                raise Refusal("Migrated target changed synthetic content/pins/MFS")
            report["target_migration_verified"] = True
            report["target_status"] = "explicit schema migration and fingerprint verified"
            report["target_repo_version"] = (migrated / "version").read_text().strip()
            report["target_format_markers"] = [str(p.relative_to(migrated)) for p in migrated.rglob("*format-version*")]
        rollback = lab.clone(repo, "rollback-control")
        if lab.fingerprint(bins["old"], rollback, root, raw, payload, raw_payload) != baseline:
            raise Refusal("Old-copy rollback control failed")
        report["rollback_control_verified"] = True
        if tree_hashes(repo) != sealed:
            raise Refusal("Sealed seed changed")
        report["seed_unchanged"] = True
        report["status"] = ("target-migration-complete; synthetic-only, not production acceptance" if args.migrate_target else "bridge-smoke-complete; not production acceptance")
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
        raise
    finally:
        (lab.evidence / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()

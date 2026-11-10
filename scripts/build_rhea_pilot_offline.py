#!/usr/bin/env python3
"""Build/test a NON-DEPLOYABLE pilot from locked sources and an offline cache.

No downloads, cache priming, deployment, host actions or DB path arguments.
Only the separately compiled Go test binary can create disposable databases.
Run on a development machine/container, never on Rhea or a jump box.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PILOT = Path("cmd/pebble-format-v1/pilot")
LOCK = PILOT / "inputs.lock.json"
PREFIX = b"//go:build ignore\n\n"
PEBBLE = "github.com/cockroachdb/pebble"
VERSION = "v1.1.3"
MAX_ZIP = 128 * 1024**2
MAX_EXPANDED = 512 * 1024**2


class Refusal(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise Refusal(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def parse(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def read_regular(path):
    # O_NOFOLLOW and a single opened descriptor: verify the bytes later copied,
    # not a pathname checked before another process swaps it.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular input required: " + str(path))
        data = stream.read(MAX_ZIP + 1)
    require(len(data) <= MAX_ZIP, "input too large: " + str(path))
    return data


def checked_relative(name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and str(path) == name and not path.is_absolute()
            and ".." not in path.parts and "\\" not in name and "\n" not in name,
            "unsafe source member")
    return path


def verify_sources(root=ROOT):
    raw = read_regular(root / LOCK)
    lock = parse(raw)
    require(raw == canonical(lock) and set(lock) == {"schema", "base_commit", "files"}
            and lock["schema"] == "rhea-pilot-inputs-v1"
            and lock["base_commit"] == "e5420cac0b20cb8e78e6ea785b4fcdad6787ae03",
            "invalid source lock")
    inputs = {}
    for name, pin in lock["files"].items():
        checked_relative(name)
        path = root / name
        require(path.resolve() == path.absolute(), "symlink in source ancestry: " + name)
        body = read_regular(path)
        require(re.fullmatch("[0-9a-f]{64}", pin) and sha(body) == pin, "source SHA256 mismatch: " + name)
        inputs[name] = body
    # New .go files in the historical package must also be reviewed/pinned.
    historical = {str(p.relative_to(root)) for p in (root / "cmd/pebble-format-v1/multistep").glob("*.go")}
    require(historical == {n for n in inputs if n.startswith("cmd/pebble-format-v1/multistep/")}, "historical Go source set changed")
    artifacts = {str(p.relative_to(root)) for p in (root / PILOT / "src").iterdir()}
    require(artifacts == {n for n in inputs if n.startswith(str(PILOT / "src") + "/")}, "pilot source set changed")
    return inputs, sha(raw)


def module_sums(raw):
    sums = {}
    for line in raw.decode("ascii").splitlines():
        module, version, digest = line.split()
        require((module, version) not in sums, "duplicate module checksum")
        require(re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", digest), "non-SHA256 module checksum")
        sums[module, version] = digest
    require((PEBBLE, VERSION) in sums and (PEBBLE, VERSION + "/go.mod") in sums, "exact Pebble checksum missing")
    return sums


def escape_module(name):
    return "".join("!" + c.lower() if c.isupper() else c for c in name)


def hash1(rows):
    """Go x/mod/sumdb/dirhash.Hash1: SHA256 of ordered SHA256 file rows."""
    summary = b"".join((sha(body) + "  " + name + "\n").encode() for name, body in sorted(rows.items()))
    return "h1:" + base64.b64encode(hashlib.sha256(summary).digest()).decode()


def unpack_module(raw, module, version, expected):
    require(len(raw) <= MAX_ZIP, "module ZIP exceeds bound")
    prefix = module + "@" + version + "/"
    files = {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(sum(e.file_size for e in entries) <= MAX_EXPANDED, "expanded module exceeds bound")
        for entry in entries:
            checked_relative(entry.filename)
            require(entry.filename.startswith(prefix) and entry.filename not in files
                    and not entry.is_dir() and not stat.S_ISLNK(entry.external_attr >> 16), "invalid module ZIP member")
            files[entry.filename] = archive.read(entry)
    require(hash1(files) == expected, "module source SHA256 (Go h1) mismatch: " + module + "@" + version)
    return {name[len(prefix):]: body for name, body in files.items()}


def materialize_modules(cache, scratch, sums):
    """Ignore expanded cache and ziphash claims; reconstruct only checked ZIPs.

    Verify all retained go.mod graph inputs too. Missing ZIPs fail closed. No
    cache file, symlink, alternate version or caller replacement enters Go.
    """
    modules = scratch / "modules"
    modules.mkdir()
    source = {}
    measured = {}
    # ZIP sums are the exact allowlist. go.mod-only older versions may be graph
    # inputs but cannot become compiled source without a pinned ZIP checksum.
    for (module, version), pin in sorted(sums.items()):
        if version.endswith("/go.mod"):
            v = version[:-7]
            p = cache / "cache/download" / escape_module(module) / "@v" / (v + ".mod")
            if not p.exists():
                continue
            raw = read_regular(p)
            require(hash1({"go.mod": raw}) == pin, "module go.mod SHA256 mismatch: " + module + "@" + v)
            dest = modules / "cache/download" / escape_module(module) / "@v" / (v + ".mod")
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
            dest.with_suffix(".info").write_bytes(canonical({"Version": v}))
            measured[module + "@" + version] = sha(raw)
            continue
        p = cache / "cache/download" / escape_module(module) / "@v" / (version + ".zip")
        # Extra checksums retained from the upstream release do not require all
        # optional tools/tests. All dependencies actually selected are checked
        # against this allowlist by Go's offline resolver and verified tree.
        if not p.exists():
            continue
        raw = read_regular(p)
        files = unpack_module(raw, module, version, pin)
        destination = modules / (escape_module(module) + "@" + version)
        destination.mkdir(parents=True)
        for name, body in files.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        modpin = sums.get((module, version + "/go.mod"))
        if "go.mod" in files and modpin:
            require(hash1({"go.mod": files["go.mod"]}) == modpin, "ZIP go.mod differs from pinned graph input")
        modbytes = files.get("go.mod")
        if modbytes is None:
            # Pre-module releases have a proxy-synthesized go.mod outside the
            # ZIP. Authenticate it independently; never invent graph bytes.
            modpath = p.with_suffix(".mod")
            require(modpin is not None, "synthetic go.mod checksum missing")
            modbytes = read_regular(modpath)
            require(hash1({"go.mod": modbytes}) == modpin, "synthetic go.mod SHA256 mismatch")
        graph = modules / "cache/download" / escape_module(module) / "@v"
        graph.mkdir(parents=True, exist_ok=True)
        (graph / (version + ".mod")).write_bytes(modbytes)
        # Write only authenticated ZIP/ziphash bytes. Go may use these to check
        # an already expanded tree; the caller's mutable tree is never read.
        (graph / (version + ".zip")).write_bytes(raw)
        (graph / (version + ".ziphash")).write_text(pin)
        (graph / (version + ".info")).write_bytes(canonical({"Version": version}))
        source[module, version] = destination
        measured[module + "@" + version] = {"source_sha256_h1": pin, "zip_sha256": sha(raw)}
    require((PEBBLE, VERSION) in source, "exact authenticated Pebble v1.1.3 ZIP missing; prime the cache separately")
    return modules, source, measured


def assemble(inputs, scratch, pebble):
    command = scratch / "command"
    package = command / "multistep"
    package.mkdir(parents=True)
    generated = {}
    for name, body in inputs.items():
        path = PurePosixPath(name)
        target = None
        if name.startswith("cmd/pebble-format-v1/multistep/") and path.name != "main.go":
            target = package / path.name
        elif name.startswith(str(PILOT / "src") + "/"):
            require(body.startswith(PREFIX), "source-only build constraint missing")
            body = body[len(PREFIX):]
            target = package / path.name
        if target:
            require(not target.exists(), "assembly source collision")
            target.write_bytes(body)
            generated[str(target.relative_to(command))] = sha(body)
    for name in ("go.mod", "go.sum"):
        (command / name).write_bytes(inputs[str(PILOT / "deps" / name)])
    (package / "offline-case.json").write_bytes(inputs[str(PILOT / "fixtures/offline-case.json")])
    (pebble / "demo_single_rewrite.go").write_bytes(inputs["cmd/pebble-format-v1/patches/demo_single_rewrite.go"])
    # Relative replacement, generated by the builder, never taken from a user
    # flag/environment/workspace. Historical go.mod/main.go remain unchanged.
    with (command / "go.mod").open("ab") as stream:
        stream.write(b"\nreplace github.com/cockroachdb/pebble => ../pebble-v1.1.3\n")
    return command, generated


def environment(scratch, modules):
    # Start from an allowlist. In particular no GOFLAGS/-overlay, credentials,
    # proxies, toolchain auto-fetch, workspace, cgo flags, shared build cache or
    # test-binary child selector is inherited.
    return {"PATH": "/usr/local/go/bin:/usr/bin:/bin", "LANG": "C", "TZ": "UTC",
            "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
            "GOVCS": "*:off", "GOENV": "off", "GOFLAGS": "", "CGO_ENABLED": "1",
            "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "GOMAXPROCS": "2",
            "GOMODCACHE": str(modules), "GOPATH": str(scratch / "gopath"),
            "GOCACHE": str(scratch / "build-cache"), "TMPDIR": str(scratch / "tmp")}


def run(argv, cwd, env, *, capture=False):
    print("+ " + " ".join(map(str, argv)), flush=True)
    return subprocess.run(list(map(str, argv)), cwd=cwd, env=env, check=True,
                          timeout=300, stdout=subprocess.PIPE if capture else None, text=capture)


def load_verifier(inputs, scratch):
    directory = scratch / "verifier"
    directory.mkdir()
    for name in ("verify_rhea_multi_sst_candidate.py", "verify_rhea_full_clone_bounded.py",
                 "verify_rhea_lab_format3.py", "enumerate_rhea_versions.py"):
        (directory / name).write_bytes(inputs["scripts/" + name])
    spec = importlib.util.spec_from_file_location("offline_pilot_verifier", directory / "verify_rhea_multi_sst_candidate.py")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier


def validate_abi(abi, verifier):
    expected = {"schema": "rhea-pilot-offline-abi-v1", "deployable": False,
                "writer_schema": verifier.WRITER_SCHEMA,
                "request_fields": ["maximum_units", "before", "initial_plan_sha256"],
                "maximum_units": verifier.MAX_UNITS, "format": "013",
                "limits": {"max_input_bytes": verifier.MAX_INPUT, "max_sst_write_bytes": verifier.MAX_OUTPUT,
                           "max_metadata_write_bytes": verifier.MAX_METADATA,
                           "min_cache_free_bytes": verifier.LIMITS["minimum_free_bytes"],
                           "max_cache_bytes": verifier.LIMITS["cache_bytes"]},
                "future_fixed_db": "/mnt/rhea-pebble-lab-writable-20261102/pebbleds",
                "future_fixed_evidence_root": "/root/.local/share/rhea-multi-sst-controller-v2",
                "live_gate": "unimplemented-unconditionally-refused"}
    require(canonical(abi) == canonical(expected), "Go ABI differs from Python verifier or disabled admission scope")


def build(go, cache, output):
    inputs, locksha = verify_sources()
    # No caller-specified toolchain flags, paths to DBs, source locks or patches.
    # Toolchain/container is a separately trusted build prerequisite, not an
    # authenticated live artifact. Record its version/hash in the build report.
    go = Path(go).resolve(strict=True)
    require(go.is_file(), "Go executable missing")
    sums = module_sums(inputs[str(PILOT / "deps/go.sum")])
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="rhea-pilot-build-") as temporary:
        scratch = Path(temporary)
        (scratch / "tmp").mkdir()
        modules, sources, measured = materialize_modules(cache, scratch, sums)
        pebble = scratch / "pebble-v1.1.3"
        shutil.copytree(sources[PEBBLE, VERSION], pebble)
        command, generated = assemble(inputs, scratch, pebble)
        env = environment(scratch, modules)
        version = run([go, "version"], command, env, capture=True).stdout.strip()
        require(re.fullmatch(r"go version go1\.24\.\d+ linux/amd64", version), "separately provisioned Linux/amd64 Go 1.24.x required")
        selected = run([go, "list", "-deps", "-test", "-mod=readonly", "-json", "./multistep"], command, env, capture=True).stdout
        decoder = json.JSONDecoder()
        while selected.strip():
            package, end = decoder.raw_decode(selected.lstrip())
            selected = selected.lstrip()[end:]
            module = package.get("Module")
            if module and not module.get("Main"):
                require((module["Path"], module.get("Version")) in sources,
                        "unlocked or unavailable compiled module: " + module["Path"])
                replacement = module.get("Replace")
                require(not replacement or (module["Path"] == PEBBLE and module["Version"] == VERSION
                        and replacement["Path"] == "../pebble-v1.1.3" and replacement["Dir"] == str(pebble)),
                        "unexpected replacement")
        run([go, "mod", "verify"], command, env)
        fixture = scratch / "disk-fixture.json"
        env["RHEA_PILOT_FIXTURE_OUTPUT"] = str(fixture)
        run([go, "test", "-mod=readonly", "-p=2", "-count=1", "-timeout=240s", "./multistep"], command, env)
        require(fixture.is_file(), "actual on-disk fixture not produced")
        # Do not run the successful fixture export twice. Race tests still seed
        # entirely new DBs but cannot replace the first run's evidence artifact.
        del env["RHEA_PILOT_FIXTURE_OUTPUT"]
        run([go, "test", "-mod=readonly", "-p=2", "-race", "-count=1", "-timeout=240s", "./multistep"], command, env)
        run([go, "vet", "-mod=readonly", "./multistep"], command, env)
        binary = scratch / "rhea-pilot-NON-DEPLOYABLE"
        run([go, "build", "-mod=readonly", "-p=2", "-trimpath", "-buildvcs=false", "-ldflags=-buildid=", "-o", binary, "./multistep"], command, env)
        abi = parse(run([binary, "--abi"], command, env, capture=True).stdout)
        verifier = load_verifier(inputs, scratch)
        validate_abi(abi, verifier)
        # Verify real compiled CLI refusal as well as the in-process Go tests.
        refused = subprocess.run([str(binary)], cwd=command, env=env, capture_output=True, timeout=15)
        require(refused.returncode == 2 and b"NON-DEPLOYABLE" in refused.stderr and not refused.stdout,
                "compiled pilot failed refusal gate")
        proof = verifier.validate_fixture_file(fixture)
        report = {"schema": "rhea-pilot-offline-build-v1", "deployable": False, "live_tested": False,
                  "on_disk_acceptance_passed": True, "python_fixture_proof": proof, "abi_parity": True,
                  "source_lock_sha256": locksha, "go_version": version, "go_executable_sha256": sha(go.read_bytes()),
                  "binary_sha256": sha(binary.read_bytes()), "fixture_sha256": sha(fixture.read_bytes()),
                  "module_sources": measured, "assembled_sources": generated,
                  "patched_pebble_file_sha256": sha((pebble / "demo_single_rewrite.go").read_bytes())}
        shutil.copyfile(binary, output / binary.name)
        (output / binary.name).chmod(0o700)
        shutil.copyfile(fixture, output / "sample-offline-fixture.json")
        (output / "sample-offline-fixture.json").chmod(0o600)
        (output / "abi.json").write_bytes(canonical(abi))
        (output / "build-report.json").write_bytes(canonical(report))
        print(json.dumps({"output": str(output), "binary_sha256": report["binary_sha256"],
                          "on_disk_acceptance_passed": True, "deployable": False}, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-sources", action="store_true", help="check locks only; never invokes Go")
    parser.add_argument("--go", type=Path)
    parser.add_argument("--module-cache", type=Path)
    parser.add_argument("--output", type=Path, help="new local build-artifact directory, never a DB path")
    args = parser.parse_args(argv)
    try:
        if args.check_sources:
            require(args.go is None and args.module_cache is None and args.output is None, "source check accepts no build arguments")
            inputs, digest = verify_sources()
            module_sums(inputs[str(PILOT / "deps/go.sum")])
            print(json.dumps({"sources_verified": len(inputs), "source_lock_sha256": digest, "deployable": False}))
        else:
            require(args.go is not None and args.module_cache is not None and args.output is not None,
                    "explicit --go, --module-cache and new --output required; prime cache separately")
            build(args.go, args.module_cache, args.output.absolute())
        return 0
    except (Refusal, OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        print("OFFLINE BUILD REFUSED: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Isolated exact-v1.1.3 build/test, using ONLY an already populated Go cache.

Never installs or downloads anything. All module/cache/source writes go in a
new /tmp directory. The original worktree and supplied module cache are read
only inputs. No built command is invoked against any database or host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def run(argv, *, cwd, env):
    print("+", " ".join(map(str, argv)), flush=True)
    subprocess.run(list(map(str, argv)), cwd=cwd, env=env, check=True, timeout=300)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=shutil.which("go"))
    parser.add_argument("--module-cache", type=Path, required=True,
                        help="existing complete module cache, copied before use; never downloaded")
    args = parser.parse_args()
    if not args.go or not Path(args.go).is_file():
        parser.error("Go toolchain unavailable; no installation/download is permitted by this harness")
    cached = args.module_cache / "github.com/cockroachdb/pebble@v1.1.3"
    if not (cached / "format_major_version.go").is_file():
        parser.error("exact Pebble v1.1.3 is missing from the supplied offline module cache")
    with tempfile.TemporaryDirectory(prefix="rhea-multi-sst-offline-") as directory:
        scratch = Path(directory)
        command = scratch / "command"
        shutil.copytree(ROOT / "cmd/pebble-format-v1", command)
        cache = scratch / "modules"
        shutil.copytree(args.module_cache, cache)
        # A copied cache may retain Go's read-only source directory modes.
        for path in [cache, *cache.rglob("*")]:
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o200 | (0o100 if path.is_dir() else 0))
        env = dict(os.environ, GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOWORK="off",
                   GOPRIVATE="", GONOPROXY="none", GONOSUMDB="none", GOVCS="*:off",
                   GOMODCACHE=str(cache), GOPATH=str(scratch / "gopath"), GOCACHE=str(scratch / "build-cache"),
                   GOENV="off", GOFLAGS="", RHEA_MULTI_FIXTURE_OUTPUT=str(scratch / "fixture.json"))
        # Drop credentials/proxy configuration from child environments. No SDK,
        # remote mount, rclone, SSH or host command is used anywhere here.
        env = {key: value for key, value in env.items()
               if not key.startswith(("AWS_", "RCLONE_")) and key.lower() not in
               {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
        run([args.go, "version"], cwd=command, env=env)
        run([args.go, "mod", "tidy"], cwd=command, env=env)
        run([args.go, "mod", "verify"], cwd=command, env=env)
        pebble = scratch / "pebble-v1.1.3"
        shutil.copytree(cache / "github.com/cockroachdb/pebble@v1.1.3", pebble)
        shutil.copyfile(command / "patches/demo_single_rewrite.go", pebble / "demo_single_rewrite.go")
        run([args.go, "mod", "edit", "-replace", "github.com/cockroachdb/pebble=" + str(pebble)], cwd=command, env=env)
        run([args.go, "mod", "tidy"], cwd=command, env=env)
        gofmt = Path(args.go).resolve().with_name("gofmt")
        # Formatting occurs only in the disposable copy. Formatting the worktree
        # itself remains a separate review gate when a Go toolchain is available.
        source = sorted((command / "multistep").glob("*.go"))
        run([gofmt, "-w", *source], cwd=command, env=env)
        run([args.go, "test", "-count=1", "./realstep", "./reallab", "./demo", "./multistep"], cwd=command, env=env)
        run([args.go, "test", "-race", "-count=1", "./multistep"], cwd=command, env=env)
        run([args.go, "vet", "./realstep", "./reallab", "./demo", "./multistep"], cwd=command, env=env)
        run([args.go, "build", "-trimpath", "-o", scratch / "multistep-disabled", "./multistep"], cwd=command, env=env)
        run([sys.executable, ROOT / "scripts/verify_rhea_multi_sst_candidate.py", "--offline-go-fixture",
             scratch / "fixture.json"], cwd=command, env=env)
        print(json.dumps({"offline_tests_passed": True, "live_tested": False,
                          "binary_sha256": hashlib.sha256((scratch / "multistep-disabled").read_bytes()).hexdigest()}))


if __name__ == "__main__":
    main()

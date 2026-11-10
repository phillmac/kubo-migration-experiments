"""Offline builder security and dependency tests; no Go/host/network needed."""
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pilot_builder", ROOT / "scripts/build_rhea_pilot_offline.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def zip_bytes(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return stream.getvalue()


class PilotSourceTests(unittest.TestCase):
    def test_actual_inputs_and_exact_dependency_pins(self):
        inputs, digest = b.verify_sources()
        self.assertEqual(len(digest), 64)
        sums = b.module_sums(inputs[str(b.PILOT / "deps/go.sum")])
        self.assertEqual(sums[b.PEBBLE, b.VERSION], "h1:GM5YY3Yb09KCGUQoyWdi3vsLErXHsmc3qRRWsX+tBqw=")
        self.assertEqual(sums[b.PEBBLE, b.VERSION + "/go.mod"], "h1:4exszw1r40423ZsmkG/09AFEG83I0uDgfujJdbL6kYU=")
        self.assertIn(b"os.Exit(2)", inputs["cmd/pebble-format-v1/multistep/main.go"])
        self.assertIn(b"maxSSTWriteBytes      uint64 = 512 * 1024 * 1024", inputs["cmd/pebble-format-v1/multistep/budget.go"])

    def copy_inputs(self, destination):
        lock = b.parse((ROOT / b.LOCK).read_bytes())
        for name in [str(b.LOCK), *lock["files"]]:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def test_source_mutation_addition_and_symlink_refused(self):
        for case in ("mutate", "add", "symlink"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.copy_inputs(root)
                path = root / "cmd/pebble-format-v1/multistep/main.go"
                if case == "mutate":
                    path.write_bytes(path.read_bytes() + b"\n// mutated\n")
                elif case == "add":
                    path.with_name("bypass.go").write_text("package main\n")
                else:
                    moved = path.with_name("main.other")
                    path.rename(moved)
                    path.symlink_to(moved)
                with self.assertRaises(b.Refusal):
                    b.verify_sources(root)

    def test_duplicate_noncanonical_and_wrong_parent_lock_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.copy_inputs(root)
            path = root / b.LOCK
            lock = b.parse(path.read_bytes())
            for raw in (b'{"schema":1,"schema":2}\n', json.dumps(lock, indent=2).encode(),
                        b.canonical(dict(lock, base_commit="0" * 40))):
                path.write_bytes(raw)
                with self.assertRaises(b.Refusal):
                    b.verify_sources(root)

    def test_assembly_preserves_historical_bytes_and_omits_disabled_main(self):
        inputs, _ = b.verify_sources()
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            pebble = scratch / "pebble-v1.1.3"
            pebble.mkdir()
            command, generated = b.assemble(inputs, scratch, pebble)
            self.assertFalse((command / "multistep/main.go").exists())
            main = (command / "multistep/pilot_main.go").read_bytes()
            self.assertEqual(main, inputs[str(b.PILOT / "src/pilot_main.go")][len(b.PREFIX):])
            self.assertNotIn(b"runBatch(", main)
            self.assertNotIn(b"Getenv", main)
            for name in ("batch.go", "budget.go", "journal.go", "unit.go", "state.go"):
                self.assertEqual((command / "multistep" / name).read_bytes(), inputs["cmd/pebble-format-v1/multistep/" + name])
            self.assertEqual((pebble / "demo_single_rewrite.go").read_bytes(), inputs["cmd/pebble-format-v1/patches/demo_single_rewrite.go"])
            self.assertEqual(generated["multistep/pilot_main.go"], b.sha(main))
            self.assertEqual((command / "multistep/offline-case.json").read_bytes(), inputs[str(b.PILOT / "fixtures/offline-case.json")])

    def test_only_reviewed_source_artifacts_can_be_injected(self):
        inputs, _ = b.verify_sources()
        inputs[str(b.PILOT / "src/pilot_main.go")] = b"package main\n"
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            pebble = scratch / "pebble-v1.1.3"
            pebble.mkdir()
            with self.assertRaises(b.Refusal):
                b.assemble(inputs, scratch, pebble)

    def test_child_env_drops_overlays_credentials_and_child_selectors(self):
        poisoned = {"GOFLAGS": "-overlay=/evil.json", "GOWORK": "/evil/go.work", "GOTOOLCHAIN": "auto",
                    "AWS_SECRET_ACCESS_KEY": "must-not-leak", "RCLONE_CONFIG": "/secret", "LD_PRELOAD": "/evil.so",
                    "RHEA_PILOT_TEST_CHILD": "1", "HTTP_PROXY": "https://example.invalid", "CC": "evilcc"}
        with patch.dict(os.environ, poisoned):
            env = b.environment(Path("/scratch"), Path("/scratch/modules"))
        self.assertEqual(env["GOPROXY"], "off")
        self.assertEqual(env["GOTOOLCHAIN"], "local")
        self.assertEqual(env["GOWORK"], "off")
        self.assertEqual(env["GOFLAGS"], "")
        self.assertFalse(set(poisoned).difference({"GOFLAGS", "GOWORK", "GOTOOLCHAIN"}) & set(env))

    def test_source_only_cli_does_not_invoke_go(self):
        with patch.object(b.subprocess, "run", side_effect=AssertionError("Go invoked")):
            self.assertEqual(b.main(["--check-sources"]), 0)
            self.assertEqual(b.main(["--check-sources", "--go", "/nonexistent"]), 2)
            self.assertEqual(b.main([]), 2)


class ModuleIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.prefix = b.PEBBLE + "@" + b.VERSION + "/"
        self.mod = b"module github.com/cockroachdb/pebble\n\ngo 1.20\n"
        self.files = {self.prefix + "go.mod": self.mod, self.prefix + "test.go": b"package pebble\n"}
        self.pin = b.hash1(self.files)

    def test_hash1_uses_sha256_of_ordered_sha256_rows(self):
        rows = {"z": b"z", "a": b"a"}
        summary = (hashlib.sha256(b"a").hexdigest() + "  a\n" + hashlib.sha256(b"z").hexdigest() + "  z\n").encode()
        self.assertEqual(b.hash1(rows), "h1:" + base64.b64encode(hashlib.sha256(summary).digest()).decode())

    def test_modified_zip_members_cannot_hide_behind_ziphash_claims(self):
        raw = zip_bytes(self.files)
        self.assertEqual(b.unpack_module(raw, b.PEBBLE, b.VERSION, self.pin)["go.mod"], self.mod)
        changed = dict(self.files)
        changed[self.prefix + "test.go"] += b"// evil\n"
        with self.assertRaisesRegex(b.Refusal, "SHA256"):
            b.unpack_module(zip_bytes(changed), b.PEBBLE, b.VERSION, self.pin)

    def test_duplicate_traversal_wrong_prefix_and_symlink_members_refused(self):
        for name in (self.prefix + "../escape.go", "/absolute.go", "wrong@v1.1.3/test.go"):
            with self.subTest(name=name), self.assertRaises(b.Refusal):
                b.unpack_module(zip_bytes({name: b"package main\n"}), b.PEBBLE, b.VERSION, self.pin)
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            entry = zipfile.ZipInfo(self.prefix + "link.go")
            entry.external_attr = 0o120777 << 16
            archive.writestr(entry, "elsewhere")
        with self.assertRaises(b.Refusal):
            b.unpack_module(stream.getvalue(), b.PEBBLE, b.VERSION, self.pin)

    def test_zip_expansion_bound(self):
        with patch.object(b, "MAX_EXPANDED", 5), self.assertRaises(b.Refusal):
            b.unpack_module(zip_bytes(self.files), b.PEBBLE, b.VERSION, self.pin)

    def cache_zip(self, cache, files=None):
        raw = zip_bytes(self.files if files is None else files)
        path = cache / "cache/download" / b.escape_module(b.PEBBLE) / "@v"
        path.mkdir(parents=True)
        (path / (b.VERSION + ".zip")).write_bytes(raw)
        (path / (b.VERSION + ".ziphash")).write_text("h1:forged-do-not-trust")
        (path / (b.VERSION + ".mod")).write_bytes(self.mod)
        return path

    def test_expanded_cache_is_ignored_and_verified_zip_reconstructed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache, scratch = root / "cache", root / "scratch"
            scratch.mkdir()
            self.cache_zip(cache)
            evil = cache / (b.PEBBLE + "@" + b.VERSION)
            evil.mkdir(parents=True)
            (evil / "test.go").write_text("package evil\n")
            sums = {(b.PEBBLE, b.VERSION): self.pin, (b.PEBBLE, b.VERSION + "/go.mod"): b.hash1({"go.mod": self.mod})}
            modules, sources, measured = b.materialize_modules(cache, scratch, sums)
            self.assertEqual((sources[b.PEBBLE, b.VERSION] / "test.go").read_bytes(), self.files[self.prefix + "test.go"])
            self.assertNotEqual(modules, cache)
            self.assertEqual(measured[b.PEBBLE + "@" + b.VERSION]["source_sha256_h1"], self.pin)
            self.assertEqual((evil / "test.go").read_text(), "package evil\n")

    def test_go_mod_mutation_and_missing_exact_zip_refuse(self):
        for case in ("mod-mutation", "missing-zip", "symlink-zip"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                cache, scratch = root / "cache", root / "scratch"
                scratch.mkdir()
                path = self.cache_zip(cache)
                if case == "mod-mutation":
                    (path / (b.VERSION + ".mod")).write_text("module evil\n")
                else:
                    zip_path = path / (b.VERSION + ".zip")
                    zip_path.unlink()
                    if case == "symlink-zip":
                        target = root / "elsewhere.zip"
                        target.write_bytes(zip_bytes(self.files))
                        zip_path.symlink_to(target)
                sums = {(b.PEBBLE, b.VERSION): self.pin, (b.PEBBLE, b.VERSION + "/go.mod"): b.hash1({"go.mod": self.mod})}
                with self.assertRaises((b.Refusal, OSError)):
                    b.materialize_modules(cache, scratch, sums)

    def test_pre_module_synthetic_go_mod_is_independently_pinned(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache, scratch = root / "cache", root / "scratch"
            scratch.mkdir()
            files = {self.prefix + "test.go": b"package pebble\n"}
            self.cache_zip(cache, files)
            sums = {(b.PEBBLE, b.VERSION): b.hash1(files), (b.PEBBLE, b.VERSION + "/go.mod"): b.hash1({"go.mod": self.mod})}
            modules, _, _ = b.materialize_modules(cache, scratch, sums)
            self.assertEqual((modules / "cache/download" / b.PEBBLE / "@v" / (b.VERSION + ".mod")).read_bytes(), self.mod)


class ABIParityTests(unittest.TestCase):
    def test_exact_python_verifier_limits_and_non_deployable_scope(self):
        inputs, _ = b.verify_sources()
        with tempfile.TemporaryDirectory() as temporary:
            verifier = b.load_verifier(inputs, Path(temporary))
            abi = {"schema": "rhea-pilot-offline-abi-v1", "deployable": False,
                   "writer_schema": verifier.WRITER_SCHEMA, "maximum_units": 2, "format": "013",
                   "request_fields": ["maximum_units", "before", "initial_plan_sha256"],
                   "limits": {"max_input_bytes": 256 * 1024**2, "max_sst_write_bytes": 512 * 1024**2,
                              "max_metadata_write_bytes": 64 * 1024**2, "min_cache_free_bytes": 2 * 1024**4,
                              "max_cache_bytes": 96 * 1024**3},
                   "future_fixed_db": "/mnt/rhea-pebble-lab-writable-20261102/pebbleds",
                   "future_fixed_evidence_root": "/root/.local/share/rhea-multi-sst-controller-v2",
                   "live_gate": "unimplemented-unconditionally-refused"}
            b.validate_abi(abi, verifier)
            for field, value in (("maximum_units", 3), ("deployable", True), ("format", "014"),
                                 ("future_fixed_db", "/tmp/db"), ("live_gate", "enabled")):
                changed = dict(abi, **{field: value})
                with self.assertRaises(b.Refusal):
                    b.validate_abi(changed, verifier)
            changed = copy.deepcopy(abi)
            changed["limits"]["max_sst_write_bytes"] += 1
            with self.assertRaises(b.Refusal):
                b.validate_abi(changed, verifier)


if __name__ == "__main__":
    unittest.main()

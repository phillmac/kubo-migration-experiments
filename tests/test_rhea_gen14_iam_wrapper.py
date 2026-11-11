"""Offline security tests for pinned Wasabi IAM wrapper (no credentials or SDK)."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
FILES = (
    "run_rhea_gen14_iam.sh",
    "rhea_gen14_iam_admin_acceptance.py",
    "rhea_multi_sst_marker_iam.py",
    "rhea_multi_sst_signed_admission.py",
    "rhea_gen14_create_iam_credentials.py",
)


class WrapperAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="iam-wrapper-offline-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "reviewed"
        self.directory.mkdir(mode=0o700)
        os.chmod(self.directory, 0o700)
        for filename in FILES:
            target = self.directory / filename
            shutil.copyfile(SCRIPTS / filename, target)
            os.chmod(target, 0o600)
        self.wrapper = self.directory / FILES[0]

    def run_mode(self, *args, additional_env=None):
        # No real admin process or credential bridge. Use empty environment.
        env = dict(additional_env or {})
        return subprocess.run(
            ["/usr/bin/env", "-i", "PATH=/usr/bin:/bin", *[f"{k}={v}" for k, v in env.items()],
             "/usr/bin/bash", str(self.wrapper), *args],
            capture_output=True, text=True, timeout=6, check=False,
        )

    def test_status_is_successful_but_offline(self):
        r = self.run_mode("status")
        self.assertEqual(r.returncode, 0, r.stderr)
        value = json.loads(r.stdout)
        self.assertEqual(value["status"], "OFFLINE_ONLY")
        self.assertEqual(value["credentials"], "NOT_ACCESSED")
        self.assertFalse(value["live_enabled"])
        self.assertFalse(value["actual_enforcement_proven"])

    def test_plan_has_fixed_disposable_scope(self):
        r = self.run_mode("plan")
        self.assertEqual(r.returncode, 0, r.stderr)
        result = json.loads(r.stdout)
        self.assertEqual(result["plan"]["target"]["bucket"],
                         "rhea-gen14-iam-test-20261111-48be1ecd7cc848fb")
        self.assertFalse(result["plan"]["live_enabled"])
        self.assertNotIn("rhea-pebble-lab-20261101-39037c6f01", r.stdout)

    def test_disabled_modes_refuse(self):
        for mode in ("accept", "cleanup", "lockout"):
            with self.subTest(mode=mode):
                r = self.run_mode(mode)
                self.assertEqual(r.returncode, 2)
                self.assertEqual(json.loads(r.stdout)["result"], "REFUSED")

    def test_provision_and_verify_dispatch_only_to_harmless_local_standin(self):
        # Even under root CI, never execute real provision/verify. Replace the
        # module, repin its bytes, and mock only this temporary wrapper's root
        # and ancestor checks. Production wrapper retains all checks unchanged.
        module = self.directory / "rhea_gen14_create_iam_credentials.py"
        original_sha = hashlib.sha256(module.read_bytes()).hexdigest()
        module.write_text('import json, os, sys\n'
                          'assert "AWS_ACCESS_KEY_ID" not in os.environ\n'
                          'print(json.dumps({"fixture": "NO_SDK_NO_CREDENTIALS", "mode": sys.argv[1]}))\n')
        wrapper = self.wrapper.read_text().replace(original_sha, hashlib.sha256(module.read_bytes()).hexdigest())
        wrapper = wrapper.replace('[[ "$OWNER" == 0 ]]', '[[ 1 == 1 ]]')
        wrapper = wrapper.replace('while [[ "$ancestor" != / ]]; do', 'while false; do')
        self.wrapper.write_text(wrapper)
        for mode in ("provision", "verify"):
            result = self.run_mode(mode, additional_env={"AWS_ACCESS_KEY_ID": "CANARY"})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout),
                             {"fixture": "NO_SDK_NO_CREDENTIALS", "mode": mode})

    def test_new_module_is_hash_pinned(self):
        with (self.directory / "rhea_gen14_create_iam_credentials.py").open("ab") as stream:
            stream.write(b"\n# modified\n")
        result = self.run_mode("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("source hash mismatch", result.stderr)

    def test_root_required_without_executing_real_provisioner(self):
        # Force the wrapper's id result to nonroot in a private test copy.
        self.wrapper.write_text(self.wrapper.read_text().replace(
            '[[ "$OWNER" == 0 ]]', '[[ 1000 == 0 ]]'))
        result = self.run_mode("provision")
        self.assertEqual(result.returncode, 2)
        self.assertIn("require root", result.stderr)

    def test_no_arbitrary_mode_or_extra_arguments(self):
        for args in ((), ("apply",), ("plan", "secret.json"), ("status", "--config", "/tmp/x")):
            with self.subTest(args=args):
                self.assertEqual(self.run_mode(*args).returncode, 64)

    def test_modified_source_is_refused(self):
        with (self.directory / FILES[1]).open("ab") as stream:
            stream.write(b"\n# changed\n")
        r = self.run_mode("status")
        self.assertEqual(r.returncode, 2)
        self.assertIn("source hash mismatch", r.stderr)

    def test_symlink_source_is_refused(self):
        target = self.directory / FILES[2]
        actual = self.directory / "marker-module-copy"
        target.rename(actual)
        target.symlink_to(actual.name)
        r = self.run_mode("plan")
        self.assertEqual(r.returncode, 2)
        self.assertIn("invalid source", r.stderr)

    def test_unsafe_source_directory_is_refused(self):
        os.chmod(self.directory, 0o777)
        r = self.run_mode("status")
        self.assertEqual(r.returncode, 2)
        self.assertIn("source directory mode", r.stderr)

    def test_unsafe_source_mode_is_refused(self):
        os.chmod(self.directory / FILES[1], 0o666)
        r = self.run_mode("status")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unsafe mode", r.stderr)

    def test_unsafe_wrapper_mode_is_refused(self):
        os.chmod(self.wrapper, 0o640)
        result = self.run_mode("status")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unsafe mode: run_rhea_gen14_iam.sh", result.stderr)

    def test_environment_values_are_not_exposed(self):
        env = dict(AWS_ACCESS_KEY_ID="CANARY_ACCESS_NEVER_PRINT",
                   AWS_SECRET_ACCESS_KEY="CANARY_SECRET_NEVER_PRINT",
                   PYTHONPATH="/definitely-untrusted",
                   HOME="/definitely-untrusted")
        r = self.run_mode("status", additional_env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("CANARY", r.stdout + r.stderr)
        self.assertEqual(json.loads(r.stdout)["credentials"], "NOT_ACCESSED")


if __name__ == "__main__":
    unittest.main()

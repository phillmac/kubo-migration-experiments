import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "verify_rhea_failed_step_close.py"
SPEC = importlib.util.spec_from_file_location("failed_step_close_tests", SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def varint(number):
    data = bytearray()
    while number >= 128:
        data.append((number & 127) | 128)
        number >>= 7
    data.append(number)
    return bytes(data)


def field(data):
    return varint(len(data)) + data


def manifest(tables, wal, sequence=m.EXPECTED_LAST_SEQUENCE):
    payload = varint(1) + field(b"leveldb.BytewiseComparator") + varint(2) + varint(wal)
    payload += varint(4) + varint(sequence)
    for number, (size, level, marked) in sorted(tables.items()):
        payload += varint(103) + varint(level) + varint(number) + varint(size)
        payload += field(b"a" * 8) + field(b"z" * 8) + varint(1) + varint(2)
        if marked:
            payload += varint(2) + field(b"\1")
        payload += varint(1)
    return struct.pack("<IHB", m.base.masked_crc(b"\1" + payload), len(payload), 1) + payload


class Missing(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class S3:
    """Read-only API surface; original SST bodies deliberately do not exist."""

    def __init__(self):
        self.latest = {}
        self.deleted = {}
        self.history = {}
        self.delete_history = []
        self.calls = []

    def add(self, key, data, version, *, size=None):
        row = {"Key": key, "VersionId": version, "Size": len(data) if data is not None else size,
               "ETag": '"' + (hashlib.md5(data).hexdigest() if data is not None else version) + '"'}
        self.latest[key] = row
        self.deleted.pop(key, None)
        self.history[key, version] = (row, data)
        pin = {"size": row["Size"], "version_id": version, "etag": row["ETag"]}
        if data is not None:
            pin["sha256"] = hashlib.sha256(data).hexdigest()
        return pin

    def delete(self, key):
        self.latest.pop(key, None)
        marker = {"Key": key, "VersionId": "delete-" + str(len(self.delete_history))}
        self.deleted[key] = marker
        self.delete_history.append(marker)

    def get_paginator(self, name):
        if name != "list_object_versions":
            raise AssertionError("unexpected API")
        return self

    def paginate(self, **kwargs):
        if kwargs != {"Bucket": m.BUCKET, "Prefix": "rhea/"}:
            raise AssertionError("listing escaped the fixed scope")
        self.calls.append(("list",))
        versions = [dict(row, IsLatest=self.latest.get(key, {}).get("VersionId") == version)
                    for (key, version), (row, _) in self.history.items()]
        deletes = [dict(row, IsLatest=self.deleted.get(row["Key"], {}).get("VersionId") == row["VersionId"])
                   for row in self.delete_history]
        yield {"Versions": versions, "DeleteMarkers": deletes}

    def head_object(self, Bucket, Key, VersionId=None):
        if Bucket != m.BUCKET:
            raise AssertionError("wrong bucket")
        self.calls.append(("head", Key, VersionId))
        if VersionId is None:
            if Key not in self.latest:
                raise Missing()
            row = self.latest[Key]
        else:
            if (Key, VersionId) not in self.history:
                raise Missing()
            row = self.history[Key, VersionId][0]
        return {"VersionId": row["VersionId"], "ETag": row["ETag"], "ContentLength": row["Size"]}

    def get_object(self, Bucket, Key, VersionId):
        if Bucket != m.BUCKET or Key.endswith(".sst"):
            raise AssertionError("unexpected scope or SST payload download")
        self.calls.append(("get", Key, VersionId))
        if (Key, VersionId) not in self.history:
            raise Missing()
        row, data = self.history[Key, VersionId]
        return {"VersionId": row["VersionId"], "ETag": row["ETag"], "ContentLength": row["Size"],
                "Body": io.BytesIO(data)}


class Fixture:
    def __init__(self, mode="final"):
        self.mode = mode
        self.tables = {46893047: (67057322, 6, True), 47475200: (123, 0, False)}
        self.inventory = {number: value[0] for number, value in self.tables.items()}
        self.digest = m.base.inventory_digest(self.inventory)
        self.s3 = S3()
        self.ledger = {}
        for number, (size, _, _) in self.tables.items():
            key = m.PREFIX + f"{number:06d}.sst"
            pin = self.s3.add(key, None, "baseline-" + str(number), size=size)
            self.ledger[key] = SimpleNamespace(size=size, version_id=pin["version_id"], etag=pin["etag"])
        for name, data in (("config", b"configuration"), ("version", b"16\n"), ("datastore_spec", b"spec")):
            key = "rhea/" + name
            pin = self.s3.add(key, data, "baseline-" + name)
            self.ledger[key] = SimpleNamespace(size=len(data), version_id=pin["version_id"], etag=pin["etag"])
        old = {"CURRENT": b"MANIFEST-000000\n", "LOCK": b"", "47475303.log": b"old-empty!!",
               "OPTIONS-47475305": b"unchanged options", "MANIFEST-47475302": manifest(self.tables, 47475301),
               m.OLD_MANIFEST: manifest(self.tables, 47475303),
               "marker.manifest.000006." + m.OLD_MANIFEST: b"", m.FORMAT_MARKER: b""}
        pins = {name: self.s3.add(m.PREFIX + name, data, "old-" + name) for name, data in old.items()}
        reopen = {"action": "inspect", "compactions": []}
        for side in ("before", "after"):
            reopen.update({side + "_format": "013", "sst_files_" + side: 2,
                           "sst_bytes_" + side: sum(self.inventory.values()),
                           "sst_inventory_sha256_" + side: self.digest, "marked_" + side: 1})
        self.previous = {"schema": 1, "scope": "fixed-disposable-full-clone-stage", "generation": 4,
                         "action": "ratchet13", "mode": "final", "bucket": m.BUCKET, "prefix": "rhea/",
                         "remote_generation_verified": True, "pebble_reopen_verified": True,
                         "after_format": "013", "marked_after": 1, "manifest": m.OLD_MANIFEST,
                         "manifest_marker": "marker.manifest.000006." + m.OLD_MANIFEST,
                         "format_marker": m.FORMAT_MARKER, "sst_count": 2,
                         "sst_bytes": sum(self.inventory.values()), "sst_inventory_sha256": self.digest,
                         "remote_metadata": pins, "reopen": reopen,
                         "sst_lineage": {"schema": 1, "baseline_ledger_sha256": m.generic.LEDGER_SHA256,
                                         "created": {}, "retired": {}, "rewrite_operations": 0}}
        self.parent_hash = m.canonical_sha256(self.previous)
        self.metadata = {"CURRENT": old["CURRENT"], "LOCK": b"", m.WAL: b"empty-wal!!",
                         m.OPTIONS: old["OPTIONS-47475305"], m.OLD_MANIFEST: old[m.OLD_MANIFEST],
                         m.MANIFEST: manifest(self.tables, int(m.WAL[:-4])),
                         m.MANIFEST_MARKER: b"", m.FORMAT_MARKER: b""}
        self.wal_hash = hashlib.sha256(self.metadata[m.WAL]).hexdigest()
        for name in set(old) - set(self.metadata):
            self.s3.delete(m.PREFIX + name)
        for name, data in self.metadata.items():
            if name not in old and not (mode == "before-markers" and name == m.MANIFEST_MARKER):
                self.s3.add(m.PREFIX + name, data, "closed-" + name)
        candidate = "pebble-lab-candidate-v1\ninput-level\t6\noutput-level\t6\n46893047\t67057322\n"
        candidate_hash = hashlib.sha256(candidate.encode()).hexdigest()
        plan_hash = hashlib.sha256((f"fullclone-plan-v1\nformat\t013\nmarked\t1\ninventory\t{self.digest}\n"
                                    f"candidate\t{candidate_hash}\n").encode()).hexdigest()
        self.report = {key: value for key, value in reopen.items() if key != "compactions"}
        self.report.update(action="step", error=m.FAILURE, seconds=16.148672929,
                           sst_diff={"created": [], "retired": [], "created_bytes": 0, "retired_bytes": 0,
                                     "created_count": 0, "retired_count": 0},
                           compactions=[{"type": "begin", "job": 2, "reason": "rewrite", "error": ""},
                                        {"type": "end", "job": 2, "reason": "rewrite", "input": [dict(m.FAILED_INPUT)],
                                         "error": m.FAILURE, "milliseconds": 136}],
                           picker_plan={"input_level": 6, "output_level": 6, "input_files": ["46893047.sst"],
                                        "input_bytes": 67057322, "candidate_sha256": candidate_hash, "plan_sha256": plan_hash},
                           expected_plan_sha256=plan_hash,
                           io={"sst_write_bytes": 0, "metadata_write_bytes": m.FAILED_METADATA_WRITE_BYTES,
                               "max_sst_write_bytes": m.generic.MAX_OUTPUT_BYTES,
                               "max_metadata_write_bytes": m.generic.MAX_METADATA_WRITE_BYTES})
        self.exit = {"returncode": 1, "monitor_failure": None, "budget_stop_present": False,
                     "process": {"pid": 2741005, "start_ticks": "6366522138",
                                 "boot_id": "727cc0aa-6827-403b-b97c-3f7ad839528e"}}

    def context(self):
        stack = ExitStack()
        for obj, name, value in ((m, "EXPECTED_PREVIOUS_SHA256", self.parent_hash), (m, "EXPECTED_MARKED", 1),
                                 (m, "WAL_SHA256", self.wal_hash), (m.base, "EXPECTED_SSTS", 2),
                                 (m.base, "EXPECTED_SST_BYTES", sum(self.inventory.values())),
                                 (m.base, "EXPECTED_INVENTORY", self.digest)):
            stack.enter_context(patch.object(obj, name, value))
        return stack

    def verify(self, **changes):
        args = {"s3": self.s3, "ledger": self.ledger, "previous_checkpoint": self.previous,
                "failed_report": self.report, "process_exit": self.exit, "metadata_bytes": self.metadata,
                "mode": self.mode, "previous_checkpoint_sha256": self.parent_hash}
        args.update(changes)
        with self.context():
            return m.verify_failed_close(**args)

    def recheck(self, before):
        with self.context():
            return m.recheck_failed_close_publication(self.s3, before)


class FailedCloseTests(unittest.TestCase):
    def test_final_bridge_retains_failure_and_unchanged_lineage_without_sst_get(self):
        f = Fixture()
        report_before = copy.deepcopy(f.report)
        result = f.verify()
        self.assertEqual(result["scope"], "fixed-disposable-full-clone-failed-step-close")
        self.assertEqual(result["action"], "reconcile-failed-step-close")
        self.assertTrue(result["remote_generation_verified"])
        self.assertFalse(result["pebble_reopen_verified"])
        self.assertTrue(result["failure_preserved"])
        self.assertEqual(result["failed_report_sha256"], m.canonical_sha256(f.report))
        self.assertEqual(result["process_exit_sha256"], m.canonical_sha256(f.exit))
        self.assertEqual(result["sst_lineage"], f.previous["sst_lineage"])
        self.assertEqual(result["sst_lineage"]["rewrite_operations"], 0)
        self.assertEqual(result["successful_rewrites"], 0)
        self.assertEqual(result["unchanged_sst_versions"], 2)
        self.assertEqual(result["new_sst_payload_bytes_downloaded"], 0)
        self.assertEqual(result["unchanged_sst_payload_bytes_downloaded"], 0)
        self.assertEqual(f.report, report_before)
        self.assertNotIn("generation", result)
        self.assertEqual(set(result["remote_metadata"]), set(f.metadata))
        self.assertTrue(all(call[0] in ("list", "get", "head") for call in f.s3.calls))

    def test_before_publication_only_new_manifest_marker_is_absent_then_recheck_and_final(self):
        f = Fixture("before-markers")
        before = f.verify()
        self.assertFalse(before["remote_generation_verified"])
        self.assertEqual(before["changed_markers"], [m.MANIFEST_MARKER])
        self.assertIn(m.FORMAT_MARKER, before["remote_metadata"])
        self.assertNotIn(m.MANIFEST_MARKER, before["remote_metadata"])
        self.assertEqual(f.recheck(before)["metadata_rechecked"], 7)
        f.s3.add(m.PREFIX + m.MANIFEST_MARKER, b"", "published-manifest")
        self.assertEqual(f.recheck(before)["new_ssts_rechecked"], 0)
        with self.assertRaises(m.VerificationError):
            f.verify()
        self.assertTrue(f.verify(mode="final")["remote_generation_verified"])

    def test_generic_previous_validator_accepts_completed_bridge_as_distinct_parent(self):
        f = Fixture()
        result = f.verify()
        result.update(generation=4, recovery_index=1, failed_attempts=1,
                      reopen=copy.deepcopy(f.previous["reopen"]), pebble_reopen_verified=True)
        markers, reopen = m.generic._validate_previous(result, m.canonical_sha256(result), m.generic._metadata_pins(result))
        self.assertEqual(markers["after_format"], "013")
        self.assertEqual(reopen["action"], "inspect")

    def test_success_or_different_failure_is_never_reclassified_as_bridge(self):
        for error in (None, "", "permission denied"):
            f = Fixture()
            f.report["error"] = error
            with self.subTest(error=error), self.assertRaises(m.VerificationError):
                f.verify()
        f = Fixture()
        f.report["action"] = "ratchet13"
        with self.assertRaises(m.VerificationError):
            f.verify()

    def test_exit_monitor_and_budget_evidence_are_strict(self):
        for key, value in (("returncode", 0), ("returncode", True), ("monitor_failure", "health failed"),
                           ("budget_stop_present", True)):
            f = Fixture()
            f.exit[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(m.VerificationError):
                f.verify()
        for key, value in (("sst_write_bytes", 1), ("sst_write_bytes", False),
                           ("metadata_write_bytes", m.generic.MAX_METADATA_WRITE_BYTES + 1),
                           ("blocked_budget_error", "stopped")):
            f = Fixture()
            f.report["io"][key] = value
            with self.subTest(io=key), self.assertRaises(m.VerificationError):
                f.verify()

    def test_any_sst_delta_or_compaction_output_is_refused(self):
        for field_name in ("created", "retired"):
            f = Fixture()
            f.report["sst_diff"][field_name] = [dict(m.FAILED_INPUT)]
            with self.subTest(delta=field_name), self.assertRaises(m.VerificationError):
                f.verify()
        f = Fixture()
        f.report["compactions"][1]["output"] = [dict(m.FAILED_INPUT)]
        with self.assertRaises(m.VerificationError):
            f.verify()
        f = Fixture()
        f.report["compactions"].append(copy.deepcopy(f.report["compactions"][1]))
        with self.assertRaises(m.VerificationError):
            f.verify()

    def test_failed_picker_state_or_event_binding_cannot_change(self):
        for change in ("plan", "input", "job", "end_error"):
            f = Fixture()
            if change == "plan":
                f.report["picker_plan"]["plan_sha256"] = "a" * 64
            elif change == "input":
                f.report["compactions"][1]["input"][0]["level"] = 5
            elif change == "job":
                f.report["compactions"][1]["job"] = 3
            else:
                f.report["compactions"][1]["error"] = ""
            with self.subTest(change=change), self.assertRaises(m.VerificationError):
                f.verify()

    def test_parent_checkpoint_hash_and_reopen_are_required(self):
        f = Fixture()
        with self.assertRaises(m.VerificationError):
            f.verify(previous_checkpoint_sha256="a" * 64)
        f.previous["reopen"]["error"] = "failed"
        with self.assertRaises(m.VerificationError):
            f.verify()

    def test_exact_file_marks_levels_and_sequence_are_preserved(self):
        for change in ("marks", "level", "sequence", "size"):
            f = Fixture()
            tables = copy.deepcopy(f.tables)
            sequence = m.EXPECTED_LAST_SEQUENCE
            if change == "marks":
                tables[46893047] = (67057322, 6, False)
                tables[47475200] = (123, 0, True)
            elif change == "level":
                tables[46893047] = (67057322, 5, True)
            elif change == "sequence":
                sequence += 1
            else:
                tables[46893047] = (67057321, 6, True)
                tables[47475200] = (124, 0, False)
            f.metadata[m.MANIFEST] = manifest(tables, int(m.WAL[:-4]), sequence)
            with self.subTest(change=change), self.assertRaises(m.VerificationError):
                f.verify()

    def test_crc_unknown_tag_and_closed_metadata_corruption_fail(self):
        f = Fixture()
        f.metadata[m.MANIFEST] = bytes([f.metadata[m.MANIFEST][0] ^ 1]) + f.metadata[m.MANIFEST][1:]
        with self.assertRaisesRegex(m.VerificationError, "CRC"):
            f.verify()
        f = Fixture()
        payload = varint(1234567)
        f.metadata[m.MANIFEST] = struct.pack("<IHB", m.base.masked_crc(b"\1" + payload), len(payload), 1) + payload
        with self.assertRaisesRegex(m.VerificationError, "unsupported"):
            f.verify()
        for name in (m.WAL, m.OPTIONS, "CURRENT", "LOCK", m.OLD_MANIFEST):
            f = Fixture()
            f.metadata[name] += b"x"
            with self.subTest(name=name), self.assertRaises(m.VerificationError):
                f.verify()

    def test_missing_or_extra_local_metadata_is_refused(self):
        for missing in ("LOCK", m.WAL, m.MANIFEST, m.FORMAT_MARKER):
            f = Fixture()
            del f.metadata[missing]
            with self.subTest(missing=missing), self.assertRaises(m.VerificationError):
                f.verify()
        f = Fixture()
        f.metadata["000123.log"] = b""
        with self.assertRaises(m.VerificationError):
            f.verify()

    def test_any_latest_sst_change_or_delete_or_extra_is_refused(self):
        for change in ("version", "delete", "extra"):
            f = Fixture()
            key = m.PREFIX + "46893047.sst"
            if change == "version":
                f.s3.add(key, None, "replacement-sst", size=67057322)
            elif change == "delete":
                f.s3.delete(key)
            else:
                f.s3.add(m.PREFIX + "000999.sst", None, "extra-sst", size=42)
            with self.subTest(change=change), self.assertRaises(m.VerificationError):
                f.verify()

    def test_failed_output_is_absent_even_from_nonlatest_history(self):
        for delete_marker in (False, True):
            f = Fixture()
            key = m.PREFIX + m.FAILED_OUTPUT
            if delete_marker:
                f.s3.delete_history.append({"Key": key, "VersionId": "old-deletion"})
            else:
                f.s3.add(key, None, "unexpected-output", size=0)
                f.s3.latest.pop(key)
            with self.subTest(delete_marker=delete_marker), self.assertRaisesRegex(m.VerificationError, "history"):
                f.verify()

    def test_preexisting_baseline_history_is_not_claimed_unique(self):
        f = Fixture()
        key = m.PREFIX + "46893047.sst"
        current = f.s3.latest[key]
        f.s3.add(key, None, "preexisting-older-version", size=67057322)
        f.s3.latest[key] = current
        result = f.verify()
        self.assertIn("latest versions for baseline SSTs", result["sst_history_scope"])

    def test_repository_and_remote_metadata_versions_and_bytes_are_checked(self):
        for change in ("repository", "retained_version", "metadata_bytes", "missing", "extra", "outside_delete"):
            f = Fixture()
            if change == "repository":
                f.s3.add("rhea/config", b"configuration", "replacement-config")
            elif change == "retained_version":
                f.s3.add(m.PREFIX + m.FORMAT_MARKER, b"", "replacement-format-marker")
            elif change == "metadata_bytes":
                f.s3.add(m.PREFIX + m.WAL, b"other-wal!!", "corrupted-wal")
            elif change == "missing":
                f.s3.delete(m.PREFIX + m.WAL)
            elif change == "extra":
                f.s3.add(m.PREFIX + "000888.log", b"", "extra-wal")
            else:
                f.s3.delete("rhea/unknown-repository-object")
            with self.subTest(change=change), self.assertRaises(m.VerificationError):
                f.verify()

    def test_publication_recheck_refuses_wrong_scope_and_changed_metadata_pin(self):
        f = Fixture("before-markers")
        before = f.verify()
        altered = copy.deepcopy(before)
        altered["scope"] = "fixed-disposable-full-clone-stage"
        with self.assertRaises(m.VerificationError):
            f.recheck(altered)
        f.s3.add(m.PREFIX + m.MANIFEST, f.metadata[m.MANIFEST], "new-version-after-proof")
        with self.assertRaisesRegex(m.VerificationError, "HEAD"):
            f.recheck(before)


if __name__ == "__main__":
    unittest.main()

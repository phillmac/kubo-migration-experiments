import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "verify_rhea_full_clone.py"
SPEC = importlib.util.spec_from_file_location("verify_full_clone_tests", SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(data):
    return varint(len(data)) + data


def manifest(tables, wal):
    payload = varint(1) + field(b"leveldb.BytewiseComparator") + varint(2) + varint(wal)
    for number, (size, level, marked) in tables.items():
        payload += varint(103) + varint(level) + varint(number) + varint(size)
        payload += field(b"a" * 8) + field(b"z" * 8) + varint(1) + varint(2)
        if marked:
            payload += varint(2) + field(b"\1")
        payload += varint(1)
    return struct.pack("<IHB", m.base.masked_crc(b"\1" + payload), len(payload), 1) + payload


def inventory(tables):
    return {number: row[0] for number, row in tables.items()}


def table_row(number, tables):
    size, level, _ = tables[number]
    return {"name": f"{number:06d}.sst", "number": number, "size": size, "level": level}


class Missing(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class S3:
    def __init__(self):
        self.latest = {}
        self.deleted = {}
        self.history = {}
        self.gets = []
        self.heads = []

    def add(self, key, data, version):
        row = {"Key": key, "Size": len(data), "ETag": '"' + hashlib.md5(data).hexdigest() + '"',
               "VersionId": version, "IsLatest": True}
        self.latest[key] = row
        self.deleted.pop(key, None)
        self.history[key, version] = (row, data)
        return {"size": len(data), "etag": row["ETag"], "version_id": version,
                "sha256": hashlib.sha256(data).hexdigest()}

    def delete(self, key):
        self.latest.pop(key, None)
        self.deleted[key] = {"Key": key, "VersionId": "delete-" + key, "IsLatest": True}

    def get_paginator(self, name):
        if name != "list_object_versions": raise AssertionError("unexpected API")
        return self

    def paginate(self, **kwargs):
        if kwargs != {"Bucket": m.BUCKET, "Prefix": "rhea/"}: raise AssertionError("wrong listing scope")
        yield {"Versions": list(self.latest.values()), "DeleteMarkers": list(self.deleted.values())}

    def head_object(self, Bucket, Key, VersionId=None):
        if Bucket != m.BUCKET: raise AssertionError("wrong bucket")
        self.heads.append((Key, VersionId))
        if VersionId is None:
            if Key not in self.latest: raise Missing()
            row = self.latest[Key]
        else:
            if (Key, VersionId) not in self.history: raise Missing()
            row = self.history[Key, VersionId][0]
        return {"VersionId": row["VersionId"], "ContentLength": row["Size"], "ETag": row["ETag"]}

    def get_object(self, Bucket, Key, VersionId):
        if Bucket != m.BUCKET: raise AssertionError("wrong bucket")
        if Key.endswith(("000001.sst", "000002.sst")):
            raise AssertionError("unchanged/retired original SST payload must never be downloaded")
        self.gets.append((Key, VersionId))
        if (Key, VersionId) not in self.history: raise Missing()
        row, data = self.history[Key, VersionId]
        return {"VersionId": row["VersionId"], "ContentLength": row["Size"], "ETag": row["ETag"], "Body": io.BytesIO(data)}


class StageFixture:
    def __init__(self, action="step", mode="final", retire_delete=True):
        self.action, self.mode = action, mode
        self.before_format, self.after_format = m.TRANSITIONS[action]
        marked = self.before_format in ("010", "013")
        self.before = {1: (100, 1, marked), 2: (200, 1, marked)}
        self.after = copy.deepcopy(self.before)
        if action == "step":
            del self.after[1]
            self.after[20] = (117, 1, False)
        elif action == "ratchet10":
            self.after = {number: (size, level, True) for number, (size, level, _) in self.before.items()}
        self.s3 = S3()
        self.ledger = {}
        for name, data in (("pebbleds/000001.sst", b"a" * 100), ("pebbleds/000002.sst", b"b" * 200),
                           ("config", b"configuration"), ("version", b"16\n"), ("datastore_spec", b"spec")):
            key = "rhea/" + name
            pin = self.s3.add(key, data, "base-" + name)
            self.ledger[key] = SimpleNamespace(size=pin["size"], version_id=pin["version_id"], etag=pin["etag"])
        self.old_manifest = "MANIFEST-000010"
        self.old_manifest_marker = "marker.manifest.000001." + self.old_manifest
        self.old_format_marker = "marker.format-version.000002." + self.before_format
        old = {
            "CURRENT": b"MANIFEST-000000\n", "LOCK": b"", "000009.log": b"empty-wal!!",
            "OPTIONS-000011": b"old options", self.old_manifest: manifest(self.before, 9),
            self.old_manifest_marker: b"", self.old_format_marker: b"",
        }
        old_pins = {name: self.s3.add(m.PREFIX + name, data, "old-" + name) for name, data in old.items()}
        self.previous = {
            "bucket": m.BUCKET, "prefix": "rhea/", "remote_generation_verified": True,
            "pebble_reopen_verified": True, "format_major_version": self.before_format,
            "marked_files": sum(row[2] for row in self.before.values()), "manifest": self.old_manifest,
            "manifest_marker": self.old_manifest_marker, "format_marker": self.old_format_marker,
            "sst_count": len(self.before), "sst_bytes": sum(row[0] for row in self.before.values()),
            "sst_inventory_sha256": m.base.inventory_digest(inventory(self.before)), "remote_metadata": old_pins,
            "reopen": {"action": "inspect", "after_format": self.before_format,
                       "sst_files_after": len(self.before), "sst_bytes_after": sum(row[0] for row in self.before.values()),
                       "sst_inventory_sha256_after": m.base.inventory_digest(inventory(self.before)),
                       "marked_after": sum(row[2] for row in self.before.values())},
        }
        self.new_manifest = "MANIFEST-000014"
        self.new_manifest_marker = "marker.manifest.000002." + self.new_manifest
        self.new_format_marker = ("marker.format-version.000005." + self.after_format
                                  if self.before_format != self.after_format else self.old_format_marker)
        self.metadata = {
            "CURRENT": b"MANIFEST-000000\n", "LOCK": b"", "000012.log": b"empty-wal!!",
            "OPTIONS-000015": b"new options", self.old_manifest: old[self.old_manifest],
            self.new_manifest: manifest(self.after, 12), self.new_manifest_marker: b"", self.new_format_marker: b"",
        }
        self.changed = [self.new_manifest_marker]
        if self.new_format_marker != self.old_format_marker: self.changed.append(self.new_format_marker)
        for name in set(old) - set(self.metadata): self.s3.delete(m.PREFIX + name)
        for name, data in self.metadata.items():
            if mode == "before-markers" and name in self.changed: continue
            if name in old and old[name] == data: continue
            self.s3.add(m.PREFIX + name, data, "new-" + name)
        self.hashes = {}
        if action == "step":
            if retire_delete: self.s3.delete(m.PREFIX + "000001.sst")
            data = b"c" * 117
            pin = self.s3.add(m.PREFIX + "000020.sst", data, "new-sst-20")
            self.hashes["000020.sst"] = {"size": 117, "sha256": pin["sha256"]}
        created = [table_row(number, self.after) for number in set(self.after) - set(self.before)]
        retired = [table_row(number, self.before) for number in set(self.before) - set(self.after)]
        self.report = {
            "action": action, "before_format": self.before_format, "after_format": self.after_format,
            "sst_diff": {"created": created, "retired": retired},
            "compactions": [], "io": {"sst_write_bytes": sum(row["size"] for row in created),
                "metadata_write_bytes": 500, "max_sst_write_bytes": m.MAX_OUTPUT_BYTES,
                "max_metadata_write_bytes": m.MAX_METADATA_WRITE_BYTES},
        }
        for suffix, tables in (("before", self.before), ("after", self.after)):
            self.report["sst_files_" + suffix] = len(tables)
            self.report["sst_bytes_" + suffix] = sum(row[0] for row in tables.values())
            self.report["sst_inventory_sha256_" + suffix] = m.base.inventory_digest(inventory(tables))
            self.report["marked_" + suffix] = sum(row[2] for row in tables.values())
        if action == "step":
            self.report["picker_plan"] = {"input_level": 1, "output_level": 1, "input_files": ["000001.sst"],
                                          "input_bytes": 100, "plan_sha256": "a" * 64}
            self.report["expected_plan_sha256"] = "a" * 64
            self.report["compactions"] = [
                {"type": "begin", "job": 1, "reason": "rewrite"},
                {"type": "end", "job": 1, "reason": "rewrite", "input": retired, "output": created, "error": "", "milliseconds": 10},
            ]

    def verify(self, **kwargs):
        params = dict(s3=self.s3, ledger=self.ledger, previous_checkpoint=self.previous, go_report=self.report,
                      metadata_bytes=self.metadata, created_sst_hashes=self.hashes, mode=self.mode,
                      previous_checkpoint_sha256=m.canonical_sha256(self.previous))
        params.update(kwargs)
        with patch.object(m.base, "EXPECTED_SSTS", 2), patch.object(m.base, "EXPECTED_SST_BYTES", 300), patch.object(
            m.base, "EXPECTED_INVENTORY", m.base.inventory_digest({1: 100, 2: 200})
        ):
            return m.verify_generation(**params)


class RepeatedStepFixture(StageFixture):
    """A second closed step retains the first output and retires another original."""

    def __init__(self):
        super().__init__()
        first = self.verify()
        first.update(generation=5, pebble_reopen_verified=True, reopen={
            "action": "inspect", "after_format": "013",
            "sst_files_after": self.report["sst_files_after"],
            "sst_bytes_after": self.report["sst_bytes_after"],
            "sst_inventory_sha256_after": self.report["sst_inventory_sha256_after"],
            "marked_after": self.report["marked_after"],
        })
        old_metadata = self.metadata
        self.previous = first
        self.before = copy.deepcopy(self.after)
        self.after = {20: self.before[20], 26: (131, 1, False)}
        self.old_manifest = first["manifest"]
        self.old_manifest_marker = first["manifest_marker"]
        self.old_format_marker = first["format_marker"]
        self.new_manifest = "MANIFEST-000024"
        self.new_manifest_marker = "marker.manifest.000003." + self.new_manifest
        self.new_format_marker = self.old_format_marker
        self.changed = [self.new_manifest_marker]
        self.metadata = {
            "CURRENT": b"MANIFEST-000000\n", "LOCK": b"", "000022.log": b"empty-wal!!",
            "OPTIONS-000025": b"second options", self.old_manifest: old_metadata[self.old_manifest],
            self.new_manifest: manifest(self.after, 22), self.new_manifest_marker: b"",
            self.new_format_marker: b"",
        }
        for name in set(old_metadata) - set(self.metadata):
            self.s3.delete(m.PREFIX + name)
        for name, data in self.metadata.items():
            if name in old_metadata and old_metadata[name] == data:
                continue
            self.s3.add(m.PREFIX + name, data, "second-" + name)
        self.s3.delete(m.PREFIX + "000002.sst")
        pin = self.s3.add(m.PREFIX + "000026.sst", b"d" * 131, "new-sst-26")
        self.hashes = {"000026.sst": {"size": 131, "sha256": pin["sha256"]}}
        created, retired = [table_row(26, self.after)], [table_row(2, self.before)]
        self.report["sst_diff"] = {"created": created, "retired": retired}
        self.report["io"]["sst_write_bytes"] = 131
        for suffix, tables in (("before", self.before), ("after", self.after)):
            self.report["sst_files_" + suffix] = len(tables)
            self.report["sst_bytes_" + suffix] = sum(row[0] for row in tables.values())
            self.report["sst_inventory_sha256_" + suffix] = m.base.inventory_digest(inventory(tables))
            self.report["marked_" + suffix] = sum(row[2] for row in tables.values())
        candidate = hashlib.sha256(
            b"pebble-lab-candidate-v1\ninput-level\t1\noutput-level\t1\n2\t200\n").hexdigest()
        plan = hashlib.sha256(("fullclone-plan-v1\nformat\t013\nmarked\t1\ninventory\t"
            + self.report["sst_inventory_sha256_before"] + "\ncandidate\t" + candidate + "\n").encode()).hexdigest()
        self.report["picker_plan"] = {"input_level": 1, "output_level": 1, "input_files": ["000002.sst"],
            "input_bytes": 200, "candidate_sha256": candidate, "plan_sha256": plan}
        self.report["expected_plan_sha256"] = plan
        self.report["compactions"] = [
            {"type": "begin", "job": 1, "reason": "rewrite"},
            {"type": "end", "job": 1, "reason": "rewrite", "input": retired,
             "output": created, "error": "", "milliseconds": 10},
        ]
        self.s3.gets.clear()
        self.s3.heads.clear()


class VerificationTests(unittest.TestCase):
    def test_all_preliminary_stages_preserve_exact_sst_versions(self):
        for action in ("ratchet6", "ratchet7", "ratchet10", "ratchet13"):
            with self.subTest(action=action):
                f = StageFixture(action)
                result = f.verify()
                self.assertTrue(result["remote_generation_verified"])
                self.assertEqual(result["unchanged_sst_versions"], 2)
                self.assertEqual(result["new_sst_payload_bytes_downloaded"], 0)
                self.assertEqual(result["sst_lineage"]["rewrite_operations"], 0)
                self.assertFalse(any(key.endswith(".sst") for key, _ in f.s3.gets))

    def test_rewrite_checks_only_new_sst_payload_and_preserves_lineage(self):
        f = StageFixture()
        result = f.verify()
        self.assertEqual(result["marked_after"], 1)
        self.assertEqual(result["unchanged_sst_versions"], 1)
        self.assertEqual(result["new_sst_payload_bytes_downloaded"], 117)
        self.assertEqual(result["unchanged_sst_payload_bytes_downloaded"], 0)
        self.assertEqual(result["sst_lineage"]["rewrite_operations"], 1)
        self.assertEqual(set(result["sst_lineage"]["retired"]), {"000001.sst"})
        self.assertEqual(set(result["sst_lineage"]["created"]), {"000020.sst"})
        self.assertEqual(result["retired_sst_states"]["000001.sst"]["state"], "latest-delete-marker")
        self.assertIn((m.PREFIX + "000001.sst", "base-pebbleds/000001.sst"), f.s3.heads)
        self.assertEqual([key for key, _ in f.s3.gets if key.endswith(".sst")], [m.PREFIX + "000020.sst"])

    def test_retired_unchanged_object_may_remain_unreferenced(self):
        f = StageFixture(retire_delete=False)
        self.assertEqual(f.verify()["retired_sst_states"]["000001.sst"]["state"], "unchanged-unreferenced-latest")

    def test_same_format_prepublication_holds_only_new_manifest_marker(self):
        f = StageFixture(mode="before-markers")
        result = f.verify()
        self.assertEqual(result["changed_markers"], [f.new_manifest_marker])
        self.assertIn(f.old_format_marker, result["remote_metadata"])
        self.assertFalse(result["remote_generation_verified"])

    def test_metadata_stage_holds_both_changed_markers(self):
        f = StageFixture("ratchet6", mode="before-markers")
        self.assertEqual(f.verify()["changed_markers"], [f.new_manifest_marker, f.new_format_marker])

    def test_partially_published_stage_uses_head_recheck_then_final_verifier(self):
        f = StageFixture("ratchet6", mode="before-markers")
        before = f.verify()
        f.s3.add(m.PREFIX + f.new_manifest_marker, b"", "published-manifest")
        m.recheck_publication_inputs(f.s3, before)
        with self.assertRaises(m.VerificationError): f.verify()
        f.s3.add(m.PREFIX + f.new_format_marker, b"", "published-format")
        m.recheck_publication_inputs(f.s3, before)
        result = f.verify(mode="final")
        self.assertTrue(result["remote_generation_verified"])

    def test_publication_recheck_detects_changed_data_version(self):
        f = StageFixture(mode="before-markers")
        before = f.verify()
        f.s3.add(m.PREFIX + "000020.sst", b"c" * 117, "substituted-version")
        with self.assertRaisesRegex(m.VerificationError, "HEAD"):
            m.recheck_publication_inputs(f.s3, before)

    def test_bad_predecessor_hash_state_or_reopen_refused(self):
        f = StageFixture()
        with self.assertRaisesRegex(m.VerificationError, "hash"):
            f.verify(previous_checkpoint_sha256="0" * 64)
        f.previous["remote_generation_verified"] = False
        with self.assertRaisesRegex(m.VerificationError, "not a final"):
            f.verify()
        f.previous["remote_generation_verified"] = True
        f.previous["pebble_reopen_verified"] = False
        del f.previous["reopen"]
        with self.assertRaises(m.VerificationError): f.verify()
        f.previous["reopen"] = {key: value for key, value in f.report.items() if key.endswith("_before")}
        f.previous["reopen"] = {key.replace("_before", "_after"): value for key, value in f.previous["reopen"].items()}
        f.previous["reopen"]["after_format"] = f.before_format
        with self.assertRaises(m.VerificationError): f.verify()
        f.previous["reopen"]["action"] = "inspect"
        self.assertTrue(f.verify()["remote_generation_verified"])
        f.previous["pebble_reopen_verified"] = True
        f.previous["reopen"]["action"] = "step"
        with self.assertRaises(m.VerificationError): f.verify()

    def test_certified_format3_seed_needs_no_raw_reopen_report(self):
        f = StageFixture("ratchet6")
        del f.previous["reopen"]
        del f.previous["remote_generation_verified"]
        f.previous["remote_format3_closure_verified"] = True
        self.assertTrue(f.verify()["remote_generation_verified"])

    def test_previous_manifest_is_fetched_by_exact_certified_version(self):
        f = StageFixture()
        # The latest object may no longer be the preceding generation.
        f.s3.add(m.PREFIX + f.old_manifest, b"other latest bytes", "overwritten-old-manifest")
        with self.assertRaises(m.VerificationError):
            f.verify()  # Its retained local metadata copy still must match latest.
        self.assertIn((m.PREFIX + f.old_manifest, "old-" + f.old_manifest), f.s3.gets)

    def test_previous_manifest_hash_and_inventory_are_required(self):
        for change in ("hash", "inventory", "marked", "count-type", "size-type"):
            f = StageFixture()
            if change == "hash": f.previous["remote_metadata"][f.old_manifest]["sha256"] = "0" * 64
            if change == "inventory": f.previous["sst_inventory_sha256"] = "0" * 64
            if change == "marked": f.previous["marked_files"] = 99
            if change == "count-type": f.previous["sst_count"] = float(f.previous["sst_count"])
            if change == "size-type": f.previous["sst_bytes"] = float(f.previous["sst_bytes"])
            with self.subTest(change=change), self.assertRaises(m.VerificationError): f.verify()

    def test_unknown_or_changed_sst_objects_refused(self):
        for change in ("untouched", "retired", "unknown", "unknown-delete", "outside-delete", "missing", "lost-history"):
            f = StageFixture()
            if change == "untouched": f.s3.add(m.PREFIX + "000002.sst", b"b" * 200, "changed")
            if change == "retired": f.s3.add(m.PREFIX + "000001.sst", b"a" * 100, "changed")
            if change == "unknown": f.s3.add(m.PREFIX + "000099.sst", b"unknown", "new")
            if change == "unknown-delete": f.s3.delete(m.PREFIX + "000099.sst")
            if change == "outside-delete": f.s3.delete("rhea/000099.sst")
            if change == "missing": f.s3.delete(m.PREFIX + "000002.sst")
            if change == "lost-history": del f.s3.history[m.PREFIX + "000001.sst", "base-pebbleds/000001.sst"]
            with self.subTest(change=change), self.assertRaises((m.VerificationError, Missing)): f.verify()

    def test_created_sst_hash_size_and_complete_hash_set_required(self):
        for change in ("hash", "size", "missing", "extra"):
            f = StageFixture()
            if change == "hash": f.hashes["000020.sst"]["sha256"] = "0" * 64
            if change == "size": f.hashes["000020.sst"]["size"] += 1
            if change == "missing": f.hashes.clear()
            if change == "extra": f.hashes["000099.sst"] = dict(f.hashes["000020.sst"])
            with self.subTest(change=change), self.assertRaises(m.VerificationError): f.verify()

    def test_metadata_only_stage_cannot_rewrite_or_run_compaction(self):
        for change in ("bytes", "event", "created"):
            f = StageFixture("ratchet10")
            if change == "bytes": f.report["io"]["sst_write_bytes"] = 1
            if change == "event": f.report["compactions"] = [{"type": "begin", "job": 1}]
            if change == "created": f.report["sst_diff"]["created"] = [table_row(1, f.after)]
            with self.subTest(change=change), self.assertRaises(m.VerificationError): f.verify()

    def test_preliminary_mark_boundaries_are_independent_of_report(self):
        for action, marked_before, marked_after in (("ratchet6", 1, 1), ("ratchet7", 0, 1),
                                                    ("ratchet10", 1, 1), ("ratchet13", 2, 1)):
            f = StageFixture(action)
            before = {f"{n:06d}.sst": {"number": n, "size": row[0], "level": row[1], "marked": n <= marked_before}
                      for n, row in f.before.items()}
            after = {name: dict(row, marked=row["number"] <= marked_after) for name, row in before.items()}
            f.report.update(marked_before=marked_before, marked_after=marked_after)
            with self.subTest(action=action), self.assertRaises(m.VerificationError):
                m._validate_stage(f.report, before, after, {"marked_files": marked_before}, {"marked_files": marked_after},
                                  f.before_format, f.after_format, {})

    def test_exact_picker_event_and_marked_delta_required(self):
        for change in ("plan", "input", "input-bytes", "job", "reason", "error", "two-jobs", "output", "marked", "level", "level-type"):
            f = StageFixture()
            if change == "plan": f.report["expected_plan_sha256"] = "b" * 64
            if change == "input": f.report["picker_plan"]["input_files"] = ["000002.sst"]
            if change == "input-bytes": f.report["picker_plan"]["input_bytes"] += 1
            if change == "job": f.report["compactions"][1]["job"] = 2
            if change == "reason": f.report["compactions"][1]["reason"] = "default"
            if change == "error": f.report["compactions"][1]["error"] = "failed"
            if change == "two-jobs": f.report["compactions"] *= 2
            if change == "output": f.report["compactions"][1]["output"] = []
            if change == "marked": f.report["marked_after"] = 0
            if change == "level": f.report["picker_plan"]["output_level"] = 2
            if change == "level-type": f.report["picker_plan"]["output_level"] = True
            with self.subTest(change=change), self.assertRaises(m.VerificationError): f.verify()

    def test_write_caps_and_output_budget_fail_closed(self):
        for label in ("sst", "metadata"):
            f = StageFixture()
            f.report["io"][label + "_write_bytes"] = f.report["io"]["max_" + label + "_write_bytes"] + 1
            with self.subTest(label=label), self.assertRaises(m.VerificationError): f.verify()
        f = StageFixture()
        with patch.object(m, "MAX_OUTPUT_BYTES", 116), self.assertRaises(m.VerificationError): f.verify()
        f = StageFixture()
        f.report["io"]["blocked_budget_error"] = "disk full"
        with self.assertRaises(m.VerificationError): f.verify()

    def test_metadata_corruption_missing_wal_and_wrong_format_refused(self):
        for change in ("crc", "wal", "format", "unknown", "same-marker"):
            f = StageFixture()
            if change == "crc": f.metadata[f.new_manifest] = f.metadata[f.new_manifest][:-1] + b"x"
            if change == "wal": del f.metadata["000012.log"]
            if change == "format":
                f.metadata["marker.format-version.000005.014"] = f.metadata.pop(f.new_format_marker)
            if change == "unknown": f.metadata["extra"] = b""
            if change == "same-marker":
                f.metadata[f.old_manifest_marker] = f.metadata.pop(f.new_manifest_marker)
            with self.subTest(change=change), self.assertRaises(m.VerificationError): f.verify()

    def test_unchanged_format_marker_keeps_its_version(self):
        f = StageFixture()
        f.s3.add(m.PREFIX + f.old_format_marker, b"", "changed-format-marker")
        with self.assertRaisesRegex(m.VerificationError, "unchanged marker"):
            f.verify()

    def test_compact_lineage_reconstructs_current_reference_set(self):
        f = StageFixture()
        certificate = f.verify()
        baseline = {name[len(m.PREFIX):]: {"size": row.size, "version_id": row.version_id, "etag": row.etag}
                    for name, row in f.ledger.items() if name.endswith(".sst")}
        current, lineage = m._lineage(certificate, baseline)
        self.assertEqual(set(current), {"000002.sst", "000020.sst"})
        self.assertEqual(lineage, certificate["sst_lineage"])
        broken = copy.deepcopy(certificate)
        broken["sst_lineage"]["retired"]["000001.sst"]["size"] = 99
        with self.assertRaises(m.VerificationError): m._lineage(broken, baseline)

    def test_second_step_preserves_prior_output_and_cumulative_lineage(self):
        f = RepeatedStepFixture()
        previous = copy.deepcopy(f.previous)
        result = f.verify()
        self.assertEqual(f.previous, previous)
        self.assertEqual(result["previous_checkpoint_sha256"], m.canonical_sha256(previous))
        self.assertEqual(result["sst_lineage"]["rewrite_operations"], 2)
        self.assertEqual(set(result["sst_lineage"]["created"]), {"000020.sst", "000026.sst"})
        self.assertEqual(set(result["sst_lineage"]["retired"]), {"000001.sst", "000002.sst"})
        self.assertEqual(result["sst_lineage"]["created"]["000020.sst"], previous["sst_lineage"]["created"]["000020.sst"])
        self.assertEqual(set(result["created_sst_versions"]), {"000026.sst"})
        # The one untouched current SST is prior-created, not an original SST.
        self.assertEqual(result["unchanged_sst_versions"], 1)
        self.assertEqual(result["unchanged_sst_payload_bytes_downloaded"], 0)
        self.assertEqual(result["new_sst_payload_bytes_downloaded"], 131)
        self.assertEqual(result["marked_after"], 0)
        self.assertEqual([key for key, _ in f.s3.gets if key.endswith(".sst")], [m.PREFIX + "000026.sst"])
        for number in (1, 2):
            self.assertIn((m.PREFIX + f"{number:06d}.sst", f"base-pebbleds/{number:06d}.sst"), f.s3.heads)

    def test_second_step_refuses_changed_prior_created_output(self):
        for field, value in (("VersionId", "changed-version"), ("ETag", '"changed-etag"'), ("Size", 118)):
            with self.subTest(field=field):
                f = RepeatedStepFixture()
                key = m.PREFIX + "000020.sst"
                f.s3.latest[key] = dict(f.s3.latest[key], **{field: value})
                with self.assertRaisesRegex(m.VerificationError, "untouched SST version changed"):
                    f.verify()

    def test_before_marker_report_cannot_become_a_predecessor(self):
        f = StageFixture(mode="before-markers")
        before = f.verify()
        with self.assertRaises(m.VerificationError):
            m._validate_previous(before, m.canonical_sha256(before), m._metadata_pins(before))

    def test_all_network_methods_are_read_only(self):
        f = StageFixture()
        result = f.verify()
        self.assertEqual(result["created_sst_versions"]["000020.sst"]["sha256"], f.hashes["000020.sst"]["sha256"])
        self.assertFalse(result["pebble_reopen_verified"])


if __name__ == "__main__":
    unittest.main()

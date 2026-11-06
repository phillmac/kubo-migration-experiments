import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import struct
import sys
import unittest
from types import SimpleNamespace


SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "verify_rhea_lab_format3.py"
SPEC = importlib.util.spec_from_file_location("verify_format3", SOURCE)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
GUARD_SPEC = importlib.util.spec_from_file_location("guard_for_verifier_tests", SOURCE.with_name("rhea_wasabi_lab_mount.py"))
guard = importlib.util.module_from_spec(GUARD_SPEC)
sys.modules[GUARD_SPEC.name] = guard
GUARD_SPEC.loader.exec_module(guard)


def uvar(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(value):
    return uvar(len(value)) + value


def fragment(payload, kind=1):
    return struct.pack("<IHB", m.masked_crc(bytes([kind]) + payload), len(payload), kind) + payload


def table(number, size, level=0, tag=100, custom=b""):
    payload = uvar(tag) + uvar(level) + uvar(number)
    if tag == 102:
        payload += uvar(0)
    payload += uvar(size)
    if tag == 104:
        payload += b"\0"  # range-only table: two range bounds follow
    payload += field(b"a" * 8) + field(b"z" * 8)
    if tag != 7:
        payload += uvar(1) + uvar(2)
    if tag in (103, 104):
        payload += custom + uvar(1)
    return payload


def manifest(inventory=None):
    inventory = {1: 100, 2: 200} if inventory is None else inventory
    payload = uvar(1) + field(b"leveldb.BytewiseComparator") + uvar(2) + uvar(10)
    payload += uvar(3) + uvar(20) + uvar(4) + uvar(2)
    payload += b"".join(table(number, size) for number, size in inventory.items())
    return fragment(payload)


def snapshot(inventory=None):
    return {
        "CURRENT": b"MANIFEST-000000\n", "LOCK": b"",
        "MANIFEST-000012": manifest(inventory), "OPTIONS-000011": b"[Version]\n",
        "000010.log": b"closed-wal!",
        "marker.manifest.000001.MANIFEST-000012": b"",
        "marker.format-version.000002.003": b"",
    }


class MissingObject(Exception):
    response = {"Error": {"Code": "NoSuchKey"}}


class FakeS3:
    def __init__(self, local, markers=True):
        self.ledger = {}
        self.latest = {}
        self.data = {}
        self.deleted = []
        self.gets = []
        self.head_changed = False
        for key, size in ((m.PREFIX + "000001.sst", 100), (m.PREFIX + "000002.sst", 200),
                          ("rhea/config", 17), ("rhea/version", 3), ("rhea/datastore_spec", 37)):
            row = dict(Key=key, Size=size, VersionId="baseline-" + key, ETag='"base"', IsLatest=True)
            self.latest[key] = row
            self.ledger[key] = SimpleNamespace(size=size, version_id=row["VersionId"], etag=row["ETag"])
        for name, value in local.items():
            if not markers and name.startswith("marker."):
                continue
            self.add_metadata(name, value)

    def add_metadata(self, name, value):
        key = m.PREFIX + name
        self.data[key] = value
        self.latest[key] = dict(Key=key, Size=len(value), VersionId="new-" + name,
                                ETag='"' + hashlib.md5(value).hexdigest() + '"', IsLatest=True)

    def get_paginator(self, method):
        if method != "list_object_versions":
            raise AssertionError("Unexpected S3 API")
        return self

    def paginate(self, **kwargs):
        if kwargs != {"Bucket": m.BUCKET, "Prefix": "rhea/"}:
            raise AssertionError("Unexpected S3 scope")
        yield {"Versions": list(self.latest.values()), "DeleteMarkers": self.deleted}

    def get_object(self, **kwargs):
        key = kwargs["Key"]
        if key.endswith(".sst"):
            raise AssertionError("SST payload must never be downloaded")
        self.gets.append(key)
        row = self.latest[key]
        if kwargs != {"Bucket": m.BUCKET, "Key": key, "VersionId": row["VersionId"]}:
            raise AssertionError("Metadata GET must pin the listed version")
        return dict(VersionId=row["VersionId"], ContentLength=row["Size"], ETag=row["ETag"], Body=io.BytesIO(self.data[key]))

    def head_object(self, **kwargs):
        key = kwargs["Key"]
        if key not in self.latest:
            raise MissingObject()
        row = self.latest[key]
        return dict(VersionId="changed" if self.head_changed else row["VersionId"],
                    ContentLength=row["Size"], ETag=row["ETag"])


class ManifestTests(unittest.TestCase):
    def test_crc32c_known_vector(self):
        self.assertEqual(m.crc32c(b"123456789"), 0xE3069283)

    def test_exact_inventory_and_log_state(self):
        inventory, stats = m.decode_manifest(manifest())
        self.assertEqual(inventory, {1: 100, 2: 200})
        self.assertEqual(stats["min_unflushed_log"], 10)
        self.assertEqual(stats["marked_files"], 0)
        self.assertEqual(m.inventory_digest(inventory), hashlib.sha256(b"1\t100\n2\t200\n").hexdigest())

    def test_fragmented_record_crc_and_ordering(self):
        payload = b"a" * (m.BLOCK + 500)
        split = m.BLOCK - 7
        encoded = fragment(payload[:split], 2) + fragment(payload[split:], 4)
        self.assertEqual(list(m.manifest_records(encoded)), [payload])
        for value in (fragment(b"x", 3), fragment(b"x", 2), fragment(b"x", 4), encoded[:-1], b"bad"):
            with self.subTest(value=value[:10]), self.assertRaises(m.VerificationError):
                list(m.manifest_records(value))

    def test_crc_corruption_and_varint_overflow_refused(self):
        data = bytearray(manifest())
        data[-1] ^= 1
        with self.assertRaisesRegex(m.VerificationError, "CRC32C"):
            m.decode_manifest(bytes(data))
        for data in (b"\x80", b"\xff" * 10):
            with self.assertRaises(m.VerificationError):
                m.parse_uvar(data, 0)

    def test_known_new_file_tags(self):
        for tag in (7, 100, 102, 103, 104):
            with self.subTest(tag=tag):
                self.assertEqual(m.decode_manifest(fragment(table(1, 100, tag=tag)))[0], {1: 100})

    def test_unknown_top_and_custom_tags_refused(self):
        for payload in (uvar(105), uvar(106), uvar(200), uvar(999),
                        table(1, 100, tag=103, custom=uvar(66) + uvar(1)),
                        table(1, 100, tag=103, custom=uvar(33) + field(b"ignored"))):
            with self.assertRaises(m.VerificationError):
                m.decode_manifest(fragment(payload))

    def test_table_move_and_absent_deletion(self):
        data = fragment(table(1, 100)) + fragment(uvar(6) + uvar(0) + uvar(1) + table(1, 100, level=1))
        self.assertEqual(m.decode_manifest(data)[0], {1: 100})
        with self.assertRaisesRegex(m.VerificationError, "absent"):
            m.decode_manifest(fragment(uvar(6) + uvar(0) + uvar(99)))

    def test_duplicate_table_levels_and_marked_snapshot_refused(self):
        with self.assertRaisesRegex(m.VerificationError, "multiple"):
            m.decode_manifest(fragment(table(1, 100) + table(1, 100, level=1)))
        local = snapshot({1: 100})
        local["MANIFEST-000012"] = fragment(uvar(2) + uvar(10) + table(1, 100, tag=103, custom=uvar(2) + field(b"\1")))
        with self.assertRaisesRegex(m.VerificationError, "marked"):
            m.local_closure(local, {1: 100})

    def test_equal_count_and_bytes_do_not_hide_substitution(self):
        with self.assertRaisesRegex(m.VerificationError, "exact SST"):
            m.local_closure(snapshot({1: 100, 3: 200}), {1: 100, 2: 200})

    def test_missing_wal_target_and_wrong_markers_refused(self):
        for change in ("wal", "target", "format", "current", "extra_marker"):
            local = snapshot()
            if change == "wal": del local["000010.log"]
            if change == "target": del local["MANIFEST-000012"]
            if change == "format": local["marker.format-version.000002.014"] = local.pop("marker.format-version.000002.003")
            if change == "current": local["CURRENT"] = b"MANIFEST-000012\n"
            if change == "extra_marker": local["marker.format-version.000001.002"] = b""
            with self.subTest(change=change), self.assertRaises(m.VerificationError):
                m.local_closure(local, {1: 100, 2: 200})


class RemoteTests(unittest.TestCase):
    def test_pre_marker_queue_is_exact_closed_tuple(self):
        profile = guard.PROFILES["full-clone"]
        row = dict(id=7, name="pebbleds/marker.format-version.000002.003", size=0, uploading=False)
        observation = {"pid": 999, "stats": {"fs": profile.remote, "diskCache": {
            "uploadsInProgress": 0, "uploadsQueued": 1, "erroredFiles": 0, "outOfSpace": False}},
            "queue": {"queue": [row]}}
        m.validate_pending_markers(guard, profile, observation, snapshot(), "before-markers")
        for name in ("pebbleds/MANIFEST-000012", "pebbleds/marker.format-version.000001.002"):
            changed = copy.deepcopy(observation)
            changed["queue"]["queue"][0]["name"] = name
            with self.assertRaises(m.VerificationError):
                m.validate_pending_markers(guard, profile, changed, snapshot(), "before-markers")
        observation["queue"]["queue"] = []
        with self.assertRaisesRegex(m.VerificationError, "no longer pending"):
            m.validate_pending_markers(guard, profile, observation, snapshot(), "before-markers")

    def test_final_queue_must_still_be_clean(self):
        profile = guard.PROFILES["full-clone"]
        observation = {"pid": 999, "stats": {"fs": profile.remote, "diskCache": {
            "uploadsInProgress": 0, "uploadsQueued": 0, "erroredFiles": 0, "outOfSpace": False}},
            "queue": {"queue": []}}
        m.validate_pending_markers(guard, profile, observation, snapshot(), "final")
        observation["stats"]["diskCache"]["uploadsQueued"] = 1
        with self.assertRaises(guard.Refusal):
            m.validate_pending_markers(guard, profile, observation, snapshot(), "final")

    def test_final_independent_metadata_and_versions_without_sst_download(self):
        local = snapshot()
        s3 = FakeS3(local)
        result = m.verify_remote(s3, s3.ledger, local, "final")
        self.assertTrue(result["remote_format3_closure_verified"])
        self.assertFalse(result["pebble_reopen_verified"])
        self.assertEqual(result["sst_payload_bytes_downloaded"], 0)
        self.assertEqual(len(s3.gets), len(local))

    def test_before_markers_and_intermediate_manifest_marker(self):
        local = snapshot()
        s3 = FakeS3(local, markers=False)
        result = m.verify_remote(s3, s3.ledger, local, "before-markers")
        self.assertFalse(result["remote_format3_closure_verified"])
        s3.add_metadata("marker.manifest.000001.MANIFEST-000012", b"")
        m.verify_remote(s3, s3.ledger, local, "before-markers")

    def test_pre_marker_refuses_already_published_final_marker(self):
        local = snapshot()
        s3 = FakeS3(local)
        with self.assertRaisesRegex(m.VerificationError, "already published"):
            m.verify_remote(s3, s3.ledger, local, "before-markers")

    def test_changed_new_or_deleted_ssts_refused(self):
        local = snapshot()
        for change in ("version", "size", "etag", "new", "deleted", "new_deleted"):
            s3 = FakeS3(local)
            key = m.PREFIX + "000001.sst"
            if change == "version": s3.latest[key]["VersionId"] = "changed"
            if change == "size": s3.latest[key]["Size"] += 1
            if change == "etag": s3.latest[key]["ETag"] = "changed"
            if change == "new": s3.latest[m.PREFIX + "000003.sst"] = dict(s3.latest[key], Key=m.PREFIX + "000003.sst")
            if change in ("deleted", "new_deleted"):
                if change == "deleted": del s3.latest[key]
                else: key = m.PREFIX + "000999.sst"
                s3.deleted = [dict(Key=key, VersionId="deleted", IsLatest=True)]
            with self.subTest(change=change), self.assertRaises(m.VerificationError):
                m.verify_remote(s3, s3.ledger, local, "final")

    def test_repo_objects_are_also_immutable(self):
        local = snapshot()
        s3 = FakeS3(local)
        s3.latest["rhea/config"]["VersionId"] = "changed"
        with self.assertRaisesRegex(m.VerificationError, "version changed"):
            m.verify_remote(s3, s3.ledger, local, "final")

    def test_metadata_bytes_missing_objects_and_latest_race_refused(self):
        local = snapshot()
        for change in ("bytes", "missing", "head", "unknown"):
            s3 = FakeS3(local)
            if change == "bytes": s3.data[m.PREFIX + "CURRENT"] = b"x" * len(local["CURRENT"])
            if change == "missing": del s3.latest[m.PREFIX + "000010.log"]
            if change == "head": s3.head_changed = True
            if change == "unknown": s3.add_metadata("unrecognized-file", b"")
            with self.subTest(change=change), self.assertRaises(m.VerificationError):
                m.verify_remote(s3, s3.ledger, local, "final")

    def test_expected_obsolete_metadata_deletes_are_allowed(self):
        local = snapshot()
        s3 = FakeS3(local)
        s3.deleted = [dict(Key=m.PREFIX + "000009.log", VersionId="deleted", IsLatest=True)]
        self.assertEqual(m.verify_remote(s3, s3.ledger, local, "final")["latest_delete_markers"], 1)

    def test_duplicate_latest_entries_refused(self):
        local = snapshot()
        s3 = FakeS3(local)
        s3.deleted = [dict(Key=m.PREFIX + "CURRENT", VersionId="deleted", IsLatest=True)]
        with self.assertRaisesRegex(m.VerificationError, "duplicate"):
            m.verify_remote(s3, s3.ledger, local, "final")


if __name__ == "__main__":
    unittest.main()

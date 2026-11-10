"""Entirely offline: genuine version-cursor model and synthetic MANIFESTs."""
import copy
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


m = load("multi_sst_candidate_tests", ROOT / "scripts/verify_rhea_multi_sst_candidate.py")
bounded = load("multi_sst_history_fixtures", ROOT / "tests/test_verify_rhea_full_clone_bounded.py")
f = bounded.fixtures


def table(number, size, marked=True):
    return {"name": f"{number:06d}.sst", "number": number, "size": size, "level": 1, "marked": marked}


def rows(tables):
    return [{key: row[key] for key in ("name", "number", "size", "level")}
            for row in sorted(tables.values(), key=lambda row: row["number"])]


def delta(created, retired):
    result = {"created": rows(created), "retired": rows(retired)}
    for label, tables in (("created", created), ("retired", retired)):
        result[label + "_count"] = len(tables)
        result[label + "_bytes"] = sum(row["size"] for row in tables.values())
    return result


def state_fields(before, after):
    out = {"before_format": "013", "after_format": "013"}
    for side, value in (("before", before), ("after", after)):
        state = m._state(value)
        for prefix, key in (("sst_files_", "files"), ("sst_bytes_", "bytes"),
                            ("sst_inventory_sha256_", "inventory_sha256"), ("marked_", "marked")):
            out[prefix + side] = state[key]
    return out


def picker(before, name):
    row = before[name]
    text = f"pebble-lab-candidate-v1\ninput-level\t1\noutput-level\t1\n{row['number']}\t{row['size']}\n"
    candidate = hashlib.sha256(text.encode()).hexdigest()
    state = m._state(before)
    text = (f"fullclone-plan-v1\nformat\t013\nmarked\t{state['marked']}\ninventory\t"
            f"{state['inventory_sha256']}\ncandidate\t{candidate}\n")
    return {"input_level": 1, "output_level": 1, "input_files": [name], "input_bytes": row["size"],
            "candidate_sha256": candidate, "plan_sha256": hashlib.sha256(text.encode()).hexdigest()}


def make_report(before, replacements=((1, 40, 117), (2, 41, 231)), maximum=2):
    current, units, created, retired, events = copy.deepcopy(before), [], {}, {}, []
    written, total_input = 0, 0
    for index, (old, new, size) in enumerate(replacements):
        old_name, new_name = f"{old:06d}.sst", f"{new:06d}.sst"
        gone, fresh = {old_name: current[old_name]}, {new_name: table(new, size, False)}
        plan = picker(current, old_name)
        after = {name: row for name, row in current.items() if name != old_name}
        after.update(fresh)
        changes = delta(fresh, gone)
        pair = [{"type": "begin", "job": 31 + index, "reason": "rewrite", "error": ""},
                {"type": "end", "job": 31 + index, "reason": "rewrite", "input": changes["retired"],
                 "output": changes["created"], "error": ""}]
        written += size
        io = {"sst_write_bytes": written, "metadata_write_bytes": (index + 1) * 500,
              "max_sst_write_bytes": m.MAX_OUTPUT, "max_metadata_write_bytes": m.MAX_METADATA}
        unit = dict(state_fields(current, after), action="step", picker_plan=plan,
                    expected_plan_sha256=plan["plan_sha256"], compactions=pair, sst_diff=changes, io=io)
        units.append(unit)
        events.extend(pair)
        created.update(fresh)
        retired.update(gone)
        total_input += plan["input_bytes"]
        current = after
    report = {"schema": m.WRITER_SCHEMA, "action": "multi-step", "closed": True, "units": units,
              "before": m._state(before), "after": m._state(current),
              "request": {"maximum_units": maximum, "before": m._state(before),
                          "initial_plan_sha256": units[0]["picker_plan"]["plan_sha256"]},
              "physical_compactions": len(units), "compactions": events, "input_bytes": total_input,
              "sst_diff": delta(created, retired), "io": dict(units[-1]["io"], metadata_write_bytes=1400),
              "stop_reason": "unit-limit"}
    hashes = {name: {"size": row["size"], "sha256": hashlib.sha256(bytes([row["number"]]) * row["size"]).hexdigest()}
              for name, row in created.items()}
    return report, current, hashes


def manifest(tables, wal):
    return f.manifest({row["number"]: (row["size"], row["level"], row["marked"]) for row in tables.values()}, wal)


class BatchFixture:
    def __init__(self, mode="final"):
        self.mode = mode
        self.s3 = bounded.CompleteHistoryS3()
        self.baseline = {number: number * 100 for number in range(1, 13)}
        self.ledger, origin = {}, {}
        for number, size in self.baseline.items():
            name = f"{number:06d}.sst"
            pin = self.s3.add(m.PREFIX + name, bytes([number]) * size, "base-" + name)
            origin[name] = {key: pin[key] for key in ("size", "etag", "version_id")}
            self.ledger[m.PREFIX + name] = SimpleNamespace(**origin[name])
        for name in ("config", "version", "datastore_spec"):
            pin = self.s3.add("rhea/" + name, name.encode(), "repo-" + name)
            self.ledger["rhea/" + name] = SimpleNamespace(**{key: pin[key] for key in ("size", "etag", "version_id")})
        self.before = {f"{number:06d}.sst": table(number, self.baseline[number]) for number in (1, 2, 3)}
        lineage = {"schema": 1, "baseline_ledger_sha256": m.proof.LEDGER_SHA256,
                   "created": {}, "retired": {}, "rewrite_operations": 9}
        for old, number in zip(range(4, 13), range(20, 29)):
            name = f"{number:06d}.sst"
            size = self.baseline[old] + 7
            lineage["created"][name] = self.s3.add(m.PREFIX + name, bytes([number]) * size, "prior-" + name)
            lineage["retired"][f"{old:06d}.sst"] = origin[f"{old:06d}.sst"]
            self.s3.delete(m.PREFIX + f"{old:06d}.sst")
            self.before[name] = table(number, size, False)
        self.old_manifest, self.new_manifest = "MANIFEST-000030", "MANIFEST-000050"
        self.old_marker = "marker.manifest.000016." + self.old_manifest
        self.new_marker = "marker.manifest.000017." + self.new_manifest
        self.format_marker = "marker.format-version.000012.013"
        old_metadata = {"CURRENT": b"MANIFEST-000000\n", "LOCK": b"", "000029.log": b"empty-wal!!",
                        "OPTIONS-000031": b"old options", self.old_manifest: manifest(self.before, 29),
                        self.old_marker: b"", self.format_marker: b""}
        old_pins = {name: self.s3.add(m.PREFIX + name, data, "old-" + name) for name, data in old_metadata.items()}
        reopen = dict(state_fields(self.before, self.before), action="inspect", compactions=[],
                      sst_diff=delta({}, {}), io={"sst_write_bytes": 0, "metadata_write_bytes": 0,
                      "max_sst_write_bytes": m.MAX_OUTPUT, "max_metadata_write_bytes": m.MAX_METADATA})
        self.previous = {"schema": 1, "scope": "fixed-disposable-full-clone-stage", "generation": 13,
                         "bucket": m.BUCKET, "prefix": "rhea/", "remote_generation_verified": True,
                         "pebble_reopen_verified": True, "after_format": "013", "manifest": self.old_manifest,
                         "manifest_marker": self.old_marker, "format_marker": self.format_marker,
                         "sst_count": len(self.before), "sst_bytes": sum(row["size"] for row in self.before.values()),
                         "sst_inventory_sha256": m._state(self.before)["inventory_sha256"],
                         "marked_after": 3, "sst_lineage": lineage, "remote_metadata": old_pins, "reopen": reopen}
        self.report, self.after, self.hashes = make_report(self.before)
        self.metadata = {"CURRENT": b"MANIFEST-000000\n", "LOCK": b"", "000049.log": b"empty-wal!!",
                         "OPTIONS-000051": b"new options", self.old_manifest: old_metadata[self.old_manifest],
                         self.new_manifest: manifest(self.after, 49), self.new_marker: b"", self.format_marker: b""}
        for name in set(old_metadata) - set(self.metadata):
            self.s3.delete(m.PREFIX + name)
        for name, data in self.metadata.items():
            if mode == "before-markers" and name == self.new_marker:
                continue
            if old_metadata.get(name) == data:
                continue
            self.s3.add(m.PREFIX + name, data, "new-" + name)
        for old, number, size in ((1, 40, 117), (2, 41, 231)):
            self.s3.delete(m.PREFIX + f"{old:06d}.sst")
            self.s3.add(m.PREFIX + f"{number:06d}.sst", bytes([number]) * size, "new-sst-" + str(number))

    def verify(self, **kwargs):
        params = dict(s3=self.s3, ledger=self.ledger, previous_checkpoint=self.previous, go_report=self.report,
                      metadata_bytes=self.metadata, created_sst_hashes=self.hashes, mode=self.mode,
                      previous_checkpoint_sha256=m.canonical_sha256(self.previous))
        params.update(kwargs)
        with patch.object(m, "GENERATION13_SHA256", m.canonical_sha256(self.previous)), patch.object(
            m.proof.base, "EXPECTED_SSTS", len(self.baseline)
        ), patch.object(m.proof.base, "EXPECTED_SST_BYTES", sum(self.baseline.values())), patch.object(
            m.proof.base, "EXPECTED_INVENTORY", m.proof.base.inventory_digest(self.baseline)
        ):
            return m.verify_generation(**params)

    def validate(self):
        return m.validate_batch(self.report, self.before, self.after, m._stats(self.before), m._stats(self.after),
                                "013", "013", self.hashes)


class PureValidationTests(unittest.TestCase):
    def test_two_units_and_one_unit_both_validate(self):
        fixture = BatchFixture()
        self.assertEqual(tuple(map(len, fixture.validate())), (2, 2))
        fixture.report, fixture.after, fixture.hashes = make_report(fixture.before, ((1, 40, 117),), maximum=1)
        self.assertEqual(tuple(map(len, fixture.validate())), (1, 1))

    def test_fail_closed_evidence_mutations(self):
        mutations = [
            lambda r: r.update(schema=1), lambda r: r.update(closed=False), lambda r: r.update(error="second failed"),
            lambda r: r.update(attempted_unit={"action": "step"}), lambda r: r.update(physical_compactions=True),
            lambda r: r.update(physical_compactions=1), lambda r: r["units"].pop(),
            lambda r: r["request"].update(maximum_units=3), lambda r: r["request"]["before"].update(marked=True),
            lambda r: r["request"].update(initial_plan_sha256="0" * 64),
            lambda r: r["units"][1]["picker_plan"].update(candidate_sha256="0" * 64),
            lambda r: r["units"][1]["picker_plan"].update(plan_sha256=r["units"][0]["picker_plan"]["plan_sha256"]),
            lambda r: r["compactions"].pop(), lambda r: r["compactions"].append(copy.deepcopy(r["compactions"][0])),
            lambda r: r["units"][1]["compactions"][0].update(job=31),
            lambda r: r["units"][1]["compactions"][1].update(job=31),
            lambda r: r["units"][1]["sst_diff"]["created"].append(copy.deepcopy(r["units"][1]["sst_diff"]["created"][0])),
            lambda r: r["units"][1]["sst_diff"].update(retired=r["units"][0]["sst_diff"]["retired"]),
            lambda r: r["units"][1]["sst_diff"].update(retired=r["units"][0]["sst_diff"]["created"]),
            lambda r: r["units"][1]["sst_diff"].update(created=r["units"][0]["sst_diff"]["created"]),
            lambda r: r["units"][0]["compactions"][1]["input"][0].update(level=2),
            lambda r: r["units"][0].update(sst_inventory_sha256_after="f" * 64),
            lambda r: r["units"][0]["io"].update(sst_write_bytes=1),
            lambda r: r["units"][1]["io"].update(metadata_write_bytes=1),
            lambda r: r["io"].update(metadata_write_bytes=m.MAX_METADATA + 1),
            lambda r: r["io"].update(sst_write_bytes=m.MAX_OUTPUT + 1),
            lambda r: r["io"].update(blocked_budget_error="blocked"), lambda r: r.update(input_bytes=m.MAX_INPUT + 1),
            lambda r: r["sst_diff"].update(created_bytes=1), lambda r: r["after"].update(files=99),
            lambda r: r.update(stop_reason="no-marked-files"), lambda r: r.update(stop_reason="recovery-required"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                fixture = BatchFixture()
                mutate(fixture.report)
                with self.assertRaises(m.VerificationError):
                    fixture.validate()

    def test_over_aggregate_input_and_valid_bounded_stop(self):
        fixture = BatchFixture()
        for name in ("000001.sst", "000002.sst"):
            fixture.before[name]["size"] = 150 * 1024**2
        fixture.report, fixture.after, fixture.hashes = make_report(fixture.before)
        with self.assertRaisesRegex(m.VerificationError, "aggregate input"):
            fixture.validate()
        fixture.report, fixture.after, fixture.hashes = make_report(fixture.before, ((1, 40, 117),))
        fixture.report.update(stop_reason="next-unit-budget", stopped_plan=picker(fixture.after, "000002.sst"))
        fixture.validate()
        fixture.report["stop_reason"] = "unit-limit"
        with self.assertRaisesRegex(m.VerificationError, "premature"):
            fixture.validate()

    def test_closed_hash_sets_and_sizes_are_exact(self):
        for mutate in (lambda h: h.pop("000041.sst"), lambda h: h.update({"000099.sst": h["000040.sst"]}),
                       lambda h: h["000040.sst"].update(size=1), lambda h: h["000040.sst"].update(sha256="bad")):
            fixture = BatchFixture()
            mutate(fixture.hashes)
            with self.assertRaises(m.VerificationError):
                fixture.validate()


class CloudProofTests(unittest.TestCase):
    def proof_pair(self):
        fixture = BatchFixture("before-markers")
        pre = fixture.verify()
        fixture.s3.add(m.PREFIX + fixture.new_marker, b"", "published-marker")
        fixture.mode = "final"
        final = fixture.verify()
        reopen = dict(state_fields(fixture.after, fixture.after), action="inspect", compactions=[],
                      sst_diff=delta({}, {}), io={"sst_write_bytes": 0, "metadata_write_bytes": 0,
                      "max_sst_write_bytes": m.MAX_OUTPUT, "max_metadata_write_bytes": m.MAX_METADATA})
        return fixture, pre, final, reopen

    def test_publication_recheck_is_hash_bound_and_checks_both_new_versions(self):
        fixture = BatchFixture("before-markers")
        pre = fixture.verify()
        result = m.recheck_publication_inputs(fixture.s3, pre, m.canonical_sha256(pre))
        self.assertEqual(result["new_ssts_rechecked"], 2)
        with self.assertRaises(m.VerificationError):
            m.recheck_publication_inputs(fixture.s3, pre, "f" * 64)
        fixture.s3.add(m.PREFIX + "000041.sst", bytes([41]) * 231, "same-content-new-version")
        with self.assertRaises(m.VerificationError):
            m.recheck_publication_inputs(fixture.s3, pre, m.canonical_sha256(pre))

    def test_proof_pair_and_reopen_fail_closed(self):
        fixture, pre, final, reopen = self.proof_pair()
        mutations = [
            lambda a, b, c, d: a.update(proof_pass_id=b["proof_pass_id"]),
            lambda a, b, c, d: a.update(mode="final"),
            lambda a, b, c, d: b.update(go_report_sha256="0" * 64),
            lambda a, b, c, d: b.update(physical_rewrite_total=10),
            lambda a, b, c, d: b["created_sst_versions"]["000041.sst"].update(version_id="changed"),
            lambda a, b, c, d: b["remote_metadata"]["OPTIONS-000051"].update(version_id="changed"),
            lambda a, b, c, d: c.update(marked_after=2),
            lambda a, b, c, d: c.update(compactions=[{"type": "begin"}]),
            lambda a, b, c, d: c["io"].update(metadata_write_bytes=1),
            lambda a, b, c, d: d.update({"OPTIONS-000051": b"wrong"}),
            lambda a, b, c, d: d.pop(fixture.new_marker),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                a, b, c, d = copy.deepcopy((pre, final, reopen, fixture.metadata))
                mutate(a, b, c, d)
                with patch.object(m, "GENERATION13_SHA256", m.canonical_sha256(fixture.previous)):
                    with self.assertRaises(m.VerificationError):
                        m.finalize_checkpoint(a, b, c, d)

    def test_prepublication_proof_refuses_early_marker_and_cannot_be_predecessor(self):
        fixture = BatchFixture("before-markers")
        pre = fixture.verify()
        with self.assertRaises(m.VerificationError):
            m._predecessor(pre, m.canonical_sha256(pre))
        fixture.s3.add(m.PREFIX + fixture.new_marker, b"", "too-early")
        with self.assertRaisesRegex(m.VerificationError, "publication barrier"):
            fixture.verify()

    def test_both_full_passes_download_both_new_ssts_preserve_lineage_and_reopen(self):
        fixture = BatchFixture("before-markers")
        baseline_previous = copy.deepcopy(fixture.previous)
        original_stage = m.proof._validate_stage
        pre = fixture.verify()
        calls = len(fixture.s3.list_calls)
        self.assertGreater(calls, 1)
        self.assertFalse(pre["remote_generation_verified"])
        fixture.s3.add(m.PREFIX + fixture.new_marker, b"", "published-marker")
        fixture.mode = "final"
        final = fixture.verify()
        self.assertGreater(len(fixture.s3.list_calls), calls)
        self.assertNotEqual(pre["proof_pass_id"], final["proof_pass_id"])
        for number in (40, 41):
            self.assertEqual(sum(key == m.PREFIX + f"{number:06d}.sst" for key, _ in fixture.s3.gets), 2)
        self.assertFalse(any(key.endswith(".sst") and not key.endswith(("000040.sst", "000041.sst"))
                             for key, _ in fixture.s3.gets))
        self.assertEqual((final["generation"], final["batch_checkpoint_count"], final["physical_compactions"],
                          final["physical_rewrite_total"]), (14, 1, 2, 11))
        self.assertEqual(len(final["sst_lineage"]["created"]), 11)
        self.assertEqual(len(final["sst_lineage"]["retired"]), 11)
        self.assertEqual(len(final["retired_sst_states"]), 11)
        for name, pin in fixture.previous["sst_lineage"]["created"].items():
            self.assertEqual(final["sst_lineage"]["created"][name], pin)
        self.assertEqual(final["unit_evidence"], fixture.report["units"])
        self.assertEqual(final["new_sst_payload_bytes_downloaded"], 348)
        self.assertEqual(final["unchanged_sst_versions"], 10)
        self.assertEqual(fixture.previous, baseline_previous)
        self.assertIs(m.proof._validate_stage, original_stage)
        reopen = dict(state_fields(fixture.after, fixture.after), action="inspect", compactions=[],
                      sst_diff=delta({}, {}), io={"sst_write_bytes": 0, "metadata_write_bytes": 0,
                      "max_sst_write_bytes": m.MAX_OUTPUT, "max_metadata_write_bytes": m.MAX_METADATA})
        with patch.object(m, "GENERATION13_SHA256", m.canonical_sha256(fixture.previous)):
            certificate = m.finalize_checkpoint(pre, final, reopen, fixture.metadata)
        self.assertTrue(certificate["pebble_reopen_verified"])
        self.assertEqual(certificate["previous_checkpoint_sha256"], m.canonical_sha256(fixture.previous))
        self.assertEqual(certificate["before_markers_proof_sha256"], m.canonical_sha256(pre))
        self.assertFalse(final["pebble_reopen_verified"])
        with patch.object(m, "GENERATION13_SHA256", m.canonical_sha256(fixture.previous)):
            self.assertEqual(m._predecessor(certificate, m.canonical_sha256(certificate)), 2)

    def test_all_cloud_identity_and_payload_invariants_fail_closed(self):
        mutations = [
            lambda x: x.s3.add(m.PREFIX + "000003.sst", b"x" * 300, "overwritten-unchanged"),
            lambda x: x.s3.delete(m.PREFIX + "000003.sst"),
            lambda x: x.s3.add(m.PREFIX + "000099.sst", b"unrelated", "unknown"),
            lambda x: x.s3.add(m.PREFIX + "000040.sst", b"x" * 117, "corrupt-new"),
            lambda x: x.s3.delete(m.PREFIX + "000041.sst"),
            lambda x: x.s3.add(m.PREFIX + x.format_marker, b"", "overwritten-old-marker"),
            lambda x: x.s3.delete(m.PREFIX + x.new_marker),
            lambda x: x.s3.add(m.PREFIX + "OPTIONS-000051", b"bad", "changed-metadata"),
            lambda x: x.s3.add("rhea/config", b"bad", "changed-repo"),
            lambda x: x.s3.add(m.PREFIX + "mystery", b"bad", "unknown-metadata"),
            lambda x: x.s3.history.pop((m.PREFIX + "000001.sst", "base-000001.sst")),
            lambda x: x.previous["sst_lineage"]["retired"]["000004.sst"].update(version_id="wrong"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                fixture = BatchFixture()
                mutate(fixture)
                with self.assertRaises((m.VerificationError, f.Missing)):
                    fixture.verify()

    def test_final_scan_observes_changes_after_first_pass(self):
        fixture = BatchFixture("before-markers")
        fixture.verify()
        calls = len(fixture.s3.list_calls)
        fixture.s3.add(m.PREFIX + fixture.new_marker, b"", "published-marker")
        fixture.s3.add(m.PREFIX + "000003.sst", b"x" * 300, "late-change")
        fixture.mode = "final"
        with self.assertRaisesRegex(m.VerificationError, "untouched SST version changed"):
            fixture.verify()
        self.assertGreater(len(fixture.s3.list_calls), calls)

    def test_old_interfaces_and_unknown_schemas_refuse_candidate(self):
        fixture = BatchFixture()
        with self.assertRaisesRegex(m.VerificationError, "unsupported stage transition"):
            m.proof._validate_stage(fixture.report, fixture.before, fixture.after, m._stats(fixture.before),
                                   m._stats(fixture.after), "013", "013", fixture.hashes)
        with self.assertRaisesRegex(m.VerificationError, "exact protected generation-13"):
            m._predecessor(fixture.previous, m.canonical_sha256(fixture.previous))
        with self.assertRaises(m.VerificationError):
            fixture.verify(enumeration_workers=1)
        for schema in (True, 0, 3, "2"):
            bad = copy.deepcopy(fixture.previous)
            bad["schema"] = schema
            with self.assertRaises(m.VerificationError):
                m._predecessor(bad, m.canonical_sha256(bad))

    def test_historical_certificate_pin_is_preserved(self):
        raw = (ROOT / "docs/evidence/rhea-batch2-000013-certificate-20261107.json").read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), m.GENERATION13_SHA256)
        import json
        previous = json.loads(raw)
        self.assertEqual(m._predecessor(previous, m.canonical_sha256(previous)), 1)


if __name__ == "__main__":
    unittest.main()

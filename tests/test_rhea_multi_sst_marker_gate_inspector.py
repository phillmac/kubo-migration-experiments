"""Separate adversarial read-only inspector and pure stage-chain suite."""
import copy
import time
import unittest
from unittest.mock import patch

import test_rhea_multi_sst_marker_gate as fixture

g, inspector = fixture.g, fixture.inspector


class InspectorTests(unittest.TestCase):
    setUp = fixture.GateTests.setUp
    new_guard = fixture.GateTests.new_guard
    inspect = fixture.GateTests.inspect

    def alter(self, name, change):
        # Simulate offline evidence corruption; the application never replaces
        # immutable receipts or exposes this test helper.
        value = g.c.parse(self.store.read(name))
        change(value)
        (self.store.path / name).write_bytes(g.c.canonical(value))

    def test_stage_skip_refused(self):
        state = g.GateState(self.batch.sha256)
        with self.assertRaisesRegex(Exception, 'illegal'):
            state.advance(self.batch, 'published', {})

    def test_preserve_terminal_and_no_replay_edge(self):
        state = g.GateState(self.batch.sha256).advance(self.batch, 'preserve', {})
        with self.assertRaisesRegex(Exception, 'terminal'):
            state.advance(self.batch, 'data-drained', ())

    def test_state_bound_to_one_generation(self):
        state = g.GateState('0' * 64)
        with self.assertRaisesRegex(Exception, 'generation/batch'):
            state.advance(self.batch, 'preserve', {})

    def test_data_drain_requires_marker_queue_and_no_data(self):
        state = g.GateState(self.batch.sha256)
        with self.assertRaisesRegex(Exception, 'exact withheld'):
            state.advance(self.batch, 'data-drained', ())
        with self.assertRaises(Exception):
            state.advance(self.batch, 'data-drained', g.classify_queue(self.batch, self.host.observe()['rc']))

    def test_two_full_proofs_must_agree_beyond_pass_ids(self):
        original = g.v.verify_generation
        def verify(*args, **kwargs):
            proof = original(*args, **kwargs)
            if proof['mode'] == 'final':
                proof['sst_inventory_sha256'] = 'f' * 64
            return proof
        with patch.object(g.v, 'verify_generation', side_effect=verify), self.assertRaisesRegex(Exception, 'passes disagree'):
            self.pilot.run()
        self.assertEqual(self.pilot.state.phase, 'preserve/manual-inspection')

    def test_selected_intent_tamper_preserve(self):
        self.pilot.run()
        self.alter('gate-mutation-0001-intent.json', lambda val: val.update(batch_sha256='0' * 64))
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_missing_mutation_receipt_preserve(self):
        self.pilot.run()
        (self.store.path / 'gate-mutation-0001-receipt.json').unlink()
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_torn_intent_preserve(self):
        self.pilot.run()
        (self.store.path / 'gate-mutation-0001-intent.json').write_bytes(b'{')
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_before_snapshot_tamper_preserve(self):
        self.pilot.run()
        self.alter('gate-prepublication.json', lambda val: val['history'].clear())
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_reused_final_pass_id_preserve(self):
        self.pilot.run()
        before = g.c.parse(self.store.read('gate-before-proof.json'))
        self.alter('gate-final-proof.json', lambda val: val.update(proof_pass_id=before['proof_pass_id']))
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_retained_final_proof_mismatch_preserve(self):
        self.pilot.run()
        self.alter('gate-final-proof.json', lambda val: val.update(physical_rewrite_total=100))
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_restored_boot_mismatch_preserve(self):
        self.pilot.run()
        self.restored['reader_identity']['boot_id'] = '00000000-0000-0000-0000-000000000000'
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_reader_stop_sentinel_preserve(self):
        self.pilot.run()
        self.restored['stop'] = True
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_reopen_metadata_mismatch_preserve(self):
        self.pilot.run()
        metadata = dict(self.batch.metadata, CURRENT=b'corrupt')
        self.assertEqual(self.inspect(reopened_metadata=metadata)['decision'], 'preserve/manual-inspection')

    def test_final_proof_remote_manifest_replaced_preserve(self):
        self.pilot.run()
        name = self.fx.new_manifest
        self.fx.s3.add(g.v.PREFIX + name, self.batch.metadata[name], 'same-bytes-new-version')
        self.assertEqual(self.inspect()['decision'], 'preserve/manual-inspection')

    def test_new_dirty_row_after_first_closed_observation_refused(self):
        first = self.host.rows.pop(1)
        e = self.host.observe()
        self.guard.sample(e, time.monotonic())
        self.host.rows[1] = first
        with self.assertRaisesRegex(Exception, 'new dirty queue row'):
            self.guard.sample(self.host.observe(), time.monotonic())

    def test_slow_durable_intent_prevents_rc_action(self):
        original = self.store.put
        self.guard.policy = g.TimingPolicy(.005, .2, .15, .01, 10, 60)
        def put(name, value):
            result = original(name, value)
            if name.endswith('0001-intent.json'):
                time.sleep(.4)
            return result
        with patch.object(self.store, 'put', side_effect=put), self.assertRaisesRegex(Exception, 'observer stalled'):
            self.pilot.run()
        self.assertEqual(self.host.calls, [])

    def test_uncertain_long_rc_prevents_receipt_or_second_mutation(self):
        original = self.host.rc
        self.guard.policy = g.TimingPolicy(.005, .2, .15, .01, 10, 60)
        def rc(*args, **kwargs):
            result = original(*args, **kwargs)
            time.sleep(.4)
            return result
        with patch.object(self.host, 'rc', side_effect=rc), self.assertRaises(Exception):
            self.pilot.run()
        self.assertEqual(len(self.host.calls), 1)
        self.assertFalse(list(self.store.path.glob('*-receipt.json')))

    def test_monitor_remains_independent_during_marker_recheck(self):
        original = g.exact_latest
        counts = []
        def exact(*args, **kwargs):
            count = self.host.observation_calls
            time.sleep(.025)
            counts.append(self.host.observation_calls - count)
            return original(*args, **kwargs)
        with patch.object(g, 'exact_latest', side_effect=exact):
            self.pilot.run()
        self.assertTrue(all(count >= 1 for count in counts))

    def test_monitor_failure_stays_latched_even_if_stop_removed(self):
        self.host.stop = True
        with self.assertRaises(Exception):
            self.guard.sample(self.host.observe(), time.monotonic())
        self.host.stop = False
        with self.assertRaisesRegex(Exception, 'guard failed'):
            self.guard.sample(self.host.observe(), time.monotonic())


if __name__ == '__main__':
    unittest.main()

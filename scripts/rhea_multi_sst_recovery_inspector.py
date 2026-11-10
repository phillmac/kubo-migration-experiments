#!/usr/bin/env python3
"""Read-only recovery decisions; NEVER writer replay, publication or journal repair.

CLI has no live adapter: local inspection alone always requires manual review.
Independent cloud/host observations can only be injected by offline tests or a
future separately reviewed installed inspector. A certificate candidate is a
finding for an operator, never permission to execute a mutation.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
from pathlib import Path
from typing import ContextManager, Protocol

import rhea_multi_sst_checkpoint_controller as c

MANUAL = 'preserve/manual-inspection'
RESTORE = 'restore-only'
CERTIFIABLE = 'certifiable-without-writer'


class RecoveryObserver(Protocol):
    """Separate read-only capability, deliberately no writer/publisher API.

    exclusive_read_lock must exclude both controllers and writers, authenticate
    the lock holder and inspect /proc boot/PID/start/executable/mount/RC identity.
    observe must independently read every retained protected guard and verify
    admission signature, consumed nonce, deployment pins and process stop state.
    source_process/writer_identity are compared with the exact retained tuples;
    PID absence alone is insufficient. Report unknown if identity is unavailable.
    cloud_read must expose only GET/HEAD/LIST; independent_snapshot must compare
    actual stopped closed files/output hashes/Go sink files with retained files,
    without opening Pebble writable. partial_state_proven is only true after
    independent reconciliation of actual MANIFEST/SST state, never inferred from
    a failed report alone. No recovery mutation is provided.
    """
    def exclusive_read_lock(self) -> ContextManager: ...
    def observe(self, intent: dict) -> dict: ...
    def independent_snapshot(self) -> dict: ...
    def cloud_read(self): ...
    def baseline_ledger(self) -> dict: ...
    def reopen_observation(self) -> dict: ...


def result(category, reason, state=None, **extra):
    return dict(decision=category, reason=reason, phase=state.get('phase') if state else None,
                writer_replay_allowed=False, mutations_performed=False, **extra)


def inspect(directory, observer: RecoveryObserver | None = None):
    """Safe repeated read-only inspection. No automatic certificate installation.

    Missing evidence is manual. A confirmed invalid/partial batch with all guards
    independently available needs lab restore; no partial compaction is finished
    here. Publication uncertainty stays manual even for a locally closed batch.
    """
    state = None
    try:
        store = c.Store(directory)
        with store.lock(existing=True), observer.exclusive_read_lock() if observer else nullcontext():
            intent, state = store.audit()
            c.validate_intent(intent)
            receipts = {phase: store.receipt(phase) for phase in state['receipts']}
            if observer is None:
                return result(MANUAL, 'independent locked host identities, guards and cloud proof unavailable', state)
            observations = observer.observe(intent)
            c.guards(observations.get('guards'), intent['guards'])
            c.require(observations.get('locked') is True and observations.get('writer_stopped') is True
                      and observations.get('admission_verified') is True
                      and observations.get('source_pins_sha256') == intent['source_pins_sha256'],
                      'missing independent lock/stop/admission/source verification')
            writer = receipts.get('writer_closed')
            if writer is None:
                return result(MANUAL, 'no exact closed Go receipt; possible unreceipted commit; no writer replay', state)
            c.require(observations.get('source_process') == writer['source_process']
                      and observations.get('writer_identity') == receipts['writer_ready']['writer_identity'],
                      'independent stopped process identity mismatch')
            # Cross-check actual retained files BEFORE classifying partial state.
            actual = observer.independent_snapshot()
            c.require(actual.get('writer') == writer, 'independently observed Go files/report differ')
            report = writer['report']
            if report.get('closed') is not True or report.get('error') or report.get('attempted_unit'):
                if actual.get('partial_state_proven') is True:
                    return result(RESTORE, 'independently reconciled partial Go state; no completion proof; lab restore required', state)
                return result(MANUAL, 'partial/unclosed report without independent MANIFEST/SST reconciliation; lab restore required if proof unavailable', state)
            c.validate_closed(writer, intent)
            c.require(writer['binary_sha256'] == receipts['writer_ready']['binary_sha256'],
                      'retained writer executable differs from handoff')
            snapshot = receipts.get('snapshot')
            c.require(snapshot is not None and actual.get('snapshot') == snapshot,
                      'closed metadata/output hashes unavailable or differ from actual retained files')
            metadata = c.validate_snapshot(snapshot, writer, intent)
            if 'marker_intent' not in receipts:
                # A fresh prepublication proof can establish current absence. It
                # cannot provide a missing historical proof or publish a marker.
                c.verifier.verify_generation(observer.cloud_read(), observer.baseline_ledger(),
                    intent['previous_checkpoint'], writer['report'], metadata, snapshot['hashes'],
                    'before-markers', intent['previous_checkpoint_sha256'], enumeration_workers=4)
                return result(MANUAL, 'closed pre-marker candidate verified; publication not authorized by recovery', state,
                              marker_boundary='before')
            # Once marker intent exists, absence/error/timeout is NOT rollback.
            c.require(all(x in receipts for x in ('data_drained', 'before_proved', 'markers_published',
                                                  'final_proved', 'reopened')),
                      'post-marker uncertainty or missing full two-pass/reopen evidence; preserve for independent inspection')
            drained = receipts['data_drained']
            c.health(drained['health'], drained=True)
            c.require(drained.get('writer_stopped') is True
                      and drained.get('writer_identity') == observations['writer_identity'], 'drain/stop identity mismatch')
            before, final = receipts['before_proved'], receipts['final_proved']
            published = receipts['markers_published']
            c.require(published.get('before_sha256') == c.digest(before)
                      and published.get('published') == before['changed_markers']
                      and receipts['marker_intent'] == {'before_sha256': c.digest(before),
                                                        'changed_markers': before['changed_markers']},
                      'publication intent/receipt binding mismatch')
            for item in (before, final):
                c.require(item.get('go_report_sha256') == c.digest(writer['report'])
                          and item.get('closed_output_hashes_sha256') == c.digest(snapshot['hashes'])
                          and item.get('previous_checkpoint_sha256') == intent['previous_checkpoint_sha256'],
                          'proof/report/output/predecessor binding mismatch')
            reopened = receipts['reopened']
            c.process_tuple(reopened['reader_identity'])
            c.require(reopened['reader_identity']['boot_id'] == intent['reader_identity']['boot_id']
                      and reopened['reader_identity']['exe_sha256'] == intent['reader_identity']['exe_sha256'],
                      'reopened reader boot/executable differs')
            c.require(observer.reopen_observation() == reopened, 'independent reader/reopen state differs')
            candidate = c.verifier.finalize_checkpoint(before, final, reopened['report'],
                                                       c.decode_metadata(reopened['metadata']))
            # New complete GET/LIST/HEAD proof with its own ID, same predecessor;
            # recheck all currently visible marker versions, not just local claims.
            fresh = c.verifier.verify_generation(observer.cloud_read(), observer.baseline_ledger(),
                intent['previous_checkpoint'], writer['report'], metadata, snapshot['hashes'],
                'final', intent['previous_checkpoint_sha256'], enumeration_workers=4)
            c.require(fresh['proof_pass_id'] not in (before['proof_pass_id'], final['proof_pass_id']),
                      'independent cloud proof reused')
            for key in set(final) - {'proof_pass_id', 'verified_unix'}:
                c.require(c.digest({'v': fresh.get(key)}) == c.digest({'v': final[key]}),
                          'fresh cloud/marker proof differs: ' + key)
            c.require(candidate['generation'] == 14 and candidate['batch_checkpoint_count'] == 1
                      and candidate['physical_rewrite_total'] == 9 + writer['report']['physical_compactions'],
                      'candidate generation/physical lineage mismatch')
            if 'certified' in receipts:
                c.require(receipts['certified'] == candidate, 'stored certificate differs from independent gate')
            return result(CERTIFIABLE, 'two retained fresh passes, exact closed batch and reopen independently confirmed; operator action only',
                          state, certificate_sha256=c.digest(candidate), marker_boundary='after')
    except Exception as exc:
        # SDK failures, malformed/torn evidence, unknown identities, unavailable
        # observers all fail closed. Signals still interrupt normally.
        return result(MANUAL, str(exc), state)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    args = parser.parse_args(argv)
    finding = inspect(args.evidence)
    print(json.dumps(finding, sort_keys=True))
    return 0 if finding['decision'] == CERTIFIABLE else 2


if __name__ == '__main__':
    raise SystemExit(main())

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import rhea_gen14_writer_supervisor as writer


class PlannerBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        evidence = ROOT / 'docs/evidence/rhea-gen14-supervised-writer-20261127.json'
        cls.proposal = json.loads(evidence.read_bytes())['prepared']['proposal']
        cls.cert = (ROOT / 'docs/evidence/rhea-batch2-000013-certificate-20261107.json').read_bytes()

    def test_picker_and_inventory_match_checkpoint(self):
        self.assertEqual(writer.verified_request(self.proposal, self.cert), self.proposal['request'])

    def test_reject_other_checkpoint_size_candidate_and_request(self):
        changes = [
            (('request','maximum_units'), 1), (('request','before','bytes'), 1),
            (('first_inputs',0,'number'), 2), (('first_inputs',0,'size'), 1),
            (('first_picker_plan','output_level'), 5),
            (('first_picker_plan','candidate_sha256'), '0' * 64),
            (('request','initial_plan_sha256'), '0' * 64),
        ]
        for keys, value in changes:
            with self.subTest(keys=keys):
                proposal = copy.deepcopy(self.proposal)
                node = proposal
                for key in keys[:-1]:
                    node = node[key]
                node[keys[-1]] = value
                with self.assertRaises(writer.c.Refusal):
                    writer.verified_request(proposal, self.cert)
        with self.assertRaises(writer.c.Refusal):
            writer.verified_request(self.proposal, self.cert + b' ')

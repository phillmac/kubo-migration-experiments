import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from failure_lab import Refusal, missing_sst_error
from pin_stream_lab import verified_ok


class EvidenceTests(unittest.TestCase):
    def test_missing_sst_exact_number_without_extension(self):
        text = 'Error: failed to open pebble database: L6: 000167: file 000167 (type 2) unknown to the objstorage provider: file does not exist'
        self.assertTrue(missing_sst_error(text, 'pebbleds/000167.sst'))
        self.assertFalse(missing_sst_error(text, 'pebbleds/000168.sst'))
    def test_unrelated_failure_not_missing_sst(self):
        self.assertFalse(missing_sst_error('permission denied 000167', '000167.sst'))
    def test_flattened_good_pin(self):
        self.assertTrue(verified_ok({'Cid': 'synthetic', 'Ok': True}))
    def test_flattened_bad_pin_false_omitted(self):
        self.assertFalse(verified_ok({'Cid': 'synthetic', 'BadNodes': [{'Cid': 'child', 'Err': 'not found'}]}))
    def test_pin_index_error_not_a_broken_dag_result(self):
        with self.assertRaises(Refusal): verified_ok({'Err': 'pin enumeration failed'})
    def test_incomplete_per_pin_result_refused(self):
        with self.assertRaises(Refusal): verified_ok({'Cid': 'synthetic'})


if __name__ == '__main__': unittest.main()

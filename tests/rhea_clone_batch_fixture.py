"""Feed real, independently decoded MANIFESTs from the Go bulk fixture into the cloud verifier."""
import base64
import copy
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import rhea_clone_batch_proof as bulk

fixture=json.loads(Path(sys.argv[1]).read_bytes())
before,bs=bulk.p._decode_tables(base64.b64decode(fixture['before'],validate=True))
after,ats=bulk.p._decode_tables(base64.b64decode(fixture['after'],validate=True))
report,hashes=fixture['report'],fixture['hashes']
new,gone=bulk.validate_batch(report,before,after,bs,ats,hashes)
assert len(new)==len(gone)==report['physical_compactions']>2
for field,value in [('input_bytes',report['input_bytes']-1),('units',report['units'][:-1]),('stop_reason','next-unit-budget')]:
    modified=copy.deepcopy(report)
    modified[field]=value
    try:
        bulk.validate_batch(modified,before,after,bs,ats,hashes)
    except (RuntimeError,ValueError,KeyError):
        continue
    raise AssertionError('accepted altered '+field)
print('Verified the larger native batch against both decoded MANIFESTs and rejected altered receipts')

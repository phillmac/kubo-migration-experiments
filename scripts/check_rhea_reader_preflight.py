#!/usr/bin/env python3
"""Offline AST boundary, source pins and disabled-gate checks. No host access."""
import ast
import hashlib
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def check():
    path = ROOT / 'scripts/rhea_multi_sst_reader_preflight.py'
    tree = ast.parse(path.read_bytes(), filename=str(path))
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    allowed_imports = {'__future__', 'argparse', 'json', 'math', 'os', 'pathlib', 'socket',
                       'stat', 'subprocess', 'time', 'rhea_multi_sst_signed_admission'}
    forbidden = {'exec', 'eval', 'compile', '__import__', 'system', 'popen', 'Popen',
                 'check_call', 'check_output', 'flock', 'chmod', 'chown', 'unlink', 'rename',
                 'replace', 'write_text', 'write_bytes', 'mkdir', 'rmdir', 'remove', 'kill', 'killpg'}
    child_calls = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [alias.name for alias in node.names] if isinstance(node, ast.Import) else [node.module]
            assert set(names) <= allowed_imports, ('unexpected import', names)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == 'os':
            assert not node.attr.startswith(('O_WR', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND')), node.attr
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr if isinstance(node.func, ast.Attribute) else ''
        assert name not in forbidden, ('forbidden call', name, node.lineno)
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
            assert name in {'run', 'TimeoutExpired'}, ('unexpected subprocess API', name)
            if name != 'run':
                continue
            owner = parents[node]
            while owner is not tree and not isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                owner = parents[owner]
            assert isinstance(owner, ast.FunctionDef) and owner.name == 'probe_reader_restored', 'child outside root probe'
            child_calls.append(node)
    assert len(child_calls) == 1, 'exactly one historical child call required'
    call = child_calls[0]
    assert ast.unparse(call.args[0]) == "['/usr/bin/python3', '-I', '-B', str(HEALTH), '--phase', 'reader-restored', '--reader-sha256', RESTORED_SHA256]"
    options = {kw.arg: kw.value for kw in call.keywords}
    assert set(options) == {'stdin', 'stdout', 'stderr', 'cwd', 'env', 'timeout', 'check'}
    assert set(ast.literal_eval(options['env'])) == {'PATH', 'HOME', 'LANG', 'LC_ALL'}
    assert ast.literal_eval(options['cwd']) == '/' and ast.unparse(options['timeout']) == 'MAX_AGE'
    for filename in ('scripts/rhea_multi_sst_reader_preflight.py',
                     'scripts/rhea_multi_sst_root_host_adapter.py',
                     'scripts/check_rhea_reader_preflight.py',
                     'tests/test_rhea_multi_sst_reader_preflight.py'):
        compile((ROOT / filename).read_bytes(), filename, 'exec')
    sys.path.insert(0, str(ROOT / 'scripts'))
    import rhea_multi_sst_checkpoint_controller as controller
    import rhea_multi_sst_root_host_adapter as host
    import rhea_multi_sst_signed_admission as admission
    import rhea_multi_sst_reader_preflight as reader
    controller.source_pins(ROOT)
    pins = {'scripts/rhea_batch2_health.py': reader.HEALTH_SHA256,
            'scripts/rhea_wasabi_lab_mount.py': host.WRAPPER_SHA256}
    pins.update({'scripts/' + host.ARTIFACTS[role][0]: pin for role, pin in host.HISTORICAL_ARTIFACTS.items()})
    pins.update({'docs/evidence/' + name: pin for name, _, pin in reader.CERTIFICATES})
    pins['docs/evidence/rhea-full-clone-failed-close-certified-20261103.json'] = reader.CLOSE_SHA256
    pins['docs/evidence/rhea-batch2-reader-finalization-20261107.json'] = reader.FINALIZATION_SHA256
    for filename, pin in pins.items():
        assert hashlib.sha256((ROOT / filename).read_bytes()).hexdigest() == pin, filename
    assert reader.MAX_AGE == 120 and reader.IMMUTABLE_REPORT['maximum_rewrites'] == 9
    assert controller.INSTALLED_ADAPTER_SHA256 is None and controller.ADMISSION_PUBLIC_KEY_SHA256 is None
    assert admission.PUBLIC_KEY_SHA256 is None and admission.KEY_NOT_BEFORE is None and admission.KEY_NOT_AFTER is None
    assert host.PROVISION_PUBLIC_KEY_SHA256 is None and host.PROVISION_KEY_NOT_BEFORE is None and host.PROVISION_KEY_NOT_AFTER is None
    print('AST read-only boundary, historical source/certificate pins and disabled gates: OK')


if __name__ == '__main__':
    check()

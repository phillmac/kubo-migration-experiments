"""Build the controller's planner and monitored child against the writer's pinned Pebble tree."""
import argparse
from pathlib import Path
import shutil
import subprocess
import tempfile

import build_rhea_pilot_offline as pilot


def assemble(inputs, work, pebble):
    command, _ = pilot.assemble(inputs, work, pebble)
    package = command / 'gen14'
    package.mkdir()
    for name in ('budget.go', 'state.go', 'unit.go', 'journal.go', 'batch.go'):
        (package / name).write_bytes(inputs['cmd/pebble-format-v1/multistep/' + name])
    for directory, name in [('inspect', 'readonly_linux.go'), ('gen14', 'main.go'), ('gen14', 'prepare.go'), ('gen14', 'worker_linux.go')]:
        (package / name).write_bytes(pilot.read_regular(pilot.ROOT / 'cmd/pebble-format-v1' / directory / name))
    return command


def build(go, cache, output):
    inputs, _ = pilot.verify_sources()
    sums = pilot.module_sums(inputs[str(pilot.PILOT / 'deps/go.sum')])
    with tempfile.TemporaryDirectory(prefix='rhea-gen14-plan-') as temp:
        work = Path(temp)
        (work / 'tmp').mkdir()
        modules, sources, _ = pilot.materialize_modules(cache, work, sums)
        pebble = work / 'pebble-v1.1.3'
        shutil.copytree(sources[pilot.PEBBLE, pilot.VERSION], pebble)
        command = assemble(inputs, work, pebble)
        env = pilot.environment(work, modules)
        env['CGO_ENABLED'] = '0'
        env['RHEA_GEN14_DRIVER'] = str(pilot.ROOT / 'tests/rhea_gen14_socket_fixture.py')
        # Test the same transport and picker against the pilot's real on-disk
        # fixture. Test-only DB selectors never enter the release executable.
        for name in ('worker_linux.go', 'prepare.go', 'supervisor_test.go', 'marker_transition_test.go'):
            shutil.copyfile(pilot.ROOT / 'cmd/pebble-format-v1/gen14' / name, command / 'multistep' / name)
        subprocess.run([go, 'test', '-v', '-mod=readonly', '-p=2', '-count=1', '-timeout=240s',
                        '-run=^TestGeneration14', './multistep'], cwd=command, env=env, check=True)
        subprocess.run([go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-buildid=',
                        '-p=2', '-o', work / 'rhea-gen14', './gen14'], cwd=command, env=env, check=True)
        with (work / 'rhea-gen14').open('rb') as src, output.open('xb') as dst:
            shutil.copyfileobj(src, dst)
        output.chmod(0o555)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('go', 'module-cache', 'output'):
        parser.add_argument('--' + flag, required=True, type=Path)
    args = parser.parse_args()
    build(args.go.resolve(strict=True), args.module_cache.resolve(strict=True), args.output)

"""Explicit, Linux-only AnyTLS integration entrypoint (never an offline fixture).

Dependencies: Python >= 3.11, Git, Go >= 1.24, a built cnode executable, loopback
TCP/TLS access. `prepare --download` explicitly permits GitHub/module downloads;
without it, a clean pinned checkout and a populated Go module cache are required.
No source patches or generated files are placed in the reference checkout.

Example (from the repository root):
  python3 tests/anytls_reference_integration.py prepare --workspace build/anytls-reference --download
  python3 tests/anytls_reference_integration.py run --workspace build/anytls-reference --binary build/cnode --output build/anytls-integration

`run` verifies embedded Go VCS revision/cleanliness and executable hashes, runs
all 15 scripts (both pool and relay suites), and retains logs and JSON results.
The wire/FIN comparisons use actual unmodified reference client AND server;
the other scripts deliberately exercise malformed frames and controlled peers.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from anytls_fin_integration import REFERENCE_COMMIT

REFERENCE_URL = 'https://github.com/anytls/anytls-go.git'
SCRIPTS = (
    'anytls_auth_padding_integration',
    'anytls_backpressure_integration',
    'anytls_client_padding_integration',
    'anytls_early_fin_integration',
    'anytls_fin_integration',
    'anytls_frame_padding_integration',
    'anytls_handshake_budget_integration',
    'anytls_identity_integration',
    'anytls_interop_integration',
    'anytls_negotiation_integration',
    'anytls_open_order_integration',
    'anytls_padding_bounds_integration',
    'anytls_padding_integration',
    'anytls_pool_integration',
    'anytls_stream_parsing_integration',
)


def executable(value):
    result = shutil.which(str(value))
    if result is None:
        raise RuntimeError(f'executable not found: {value}')
    return str(Path(result).resolve())


def command(argv, **kwargs):
    return subprocess.run([str(value) for value in argv], check=True, text=True,
                          capture_output=True, **kwargs).stdout


def reference_binaries(workspace):
    return {kind: workspace / 'bin' / f'anytls-{kind}' for kind in ('client', 'server')}


def verify_reference(go, workspace):
    report = {}
    for kind, binary in reference_binaries(workspace).items():
        metadata = command([go, 'version', '-m', binary])
        if (f'vcs.revision={REFERENCE_COMMIT}' not in metadata or
                'vcs.modified=false' not in metadata or f'path\tanytls/cmd/{kind}' not in metadata):
            raise RuntimeError(f'not an unmodified pinned reference {kind}: {binary}\n{metadata}')
        report[kind] = {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                        'build_metadata': metadata}
    return report


def prepare(args):
    workspace = args.workspace
    workspace.mkdir(parents=True, exist_ok=True)
    source = args.reference_source or workspace / 'source'
    if not source.exists():
        if not args.download:
            raise RuntimeError('reference checkout missing; supply --reference-source or explicitly use --download')
        source.parent.mkdir(parents=True, exist_ok=True)
        command(['git', 'clone', '--no-checkout', REFERENCE_URL, source])
        command(['git', '-C', source, 'checkout', '--detach', REFERENCE_COMMIT])
    if command(['git', '-C', source, 'rev-parse', 'HEAD']).strip() != REFERENCE_COMMIT:
        raise RuntimeError(f'reference checkout must already be at {REFERENCE_COMMIT}: {source}')
    if command(['git', '-C', source, 'status', '--porcelain']).strip():
        raise RuntimeError(f'reference checkout must be clean, including untracked files: {source}')
    binaries = reference_binaries(workspace)
    for binary in binaries.values():
        if binary.is_relative_to(source):
            raise RuntimeError('reference binary output must be outside its source checkout')
        binary.parent.mkdir(parents=True, exist_ok=True)
    go = executable(args.go)
    environment = dict(os.environ, CGO_ENABLED='0')
    if not args.download:
        environment.update(GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local',
                           GOPRIVATE='', GONOPROXY='none', GOVCS='*:off')
    build_logs = {}
    for kind, binary in binaries.items():
        result = subprocess.run([go, 'build', '-buildvcs=true', '-trimpath', '-o', str(binary), f'./cmd/{kind}'],
                                cwd=source, env=environment, text=True, capture_output=True)
        build_logs[kind] = result.stdout + result.stderr
        (workspace / f'build-{kind}.log').write_text(build_logs[kind], encoding='utf-8')
        result.check_returncode()
    report = {'reference_commit': REFERENCE_COMMIT, 'source': str(source),
              'network_downloads_authorized': args.download, 'binaries': verify_reference(go, workspace)}
    (workspace / 'reference.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))
    return 0


def run(args):
    go = executable(args.go)
    binary = Path(executable(args.binary))
    references = verify_reference(go, args.workspace)
    original_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    args.output.mkdir(parents=True, exist_ok=True)
    selected = args.suite or SCRIPTS
    results = []
    for script in selected:
        variants = ('pool', 'relay') if script == 'anytls_pool_integration' else (None,)
        for variant in variants:
            name = script if variant is None else f'{script}-{variant}'
            output = args.output / name
            output.mkdir(parents=True, exist_ok=True)
            argv = [sys.executable, str(Path(__file__).with_name(f'{script}.py')),
                    '--binary', str(binary), '--output', str(output)]
            if variant is not None:
                argv += ['--suite', variant]
            if script in ('anytls_fin_integration', 'anytls_interop_integration'):
                argv += ['--reference-client', references['client']['path'],
                         '--reference-server', references['server']['path'], '--go', go]
            elif script == 'anytls_frame_padding_integration':
                argv += ['--reference-client', references['client']['path'], '--go', go]
            started = time.monotonic()
            with (output / 'runner.log').open('w', encoding='utf-8') as log:
                # Scripts own and join their service children. A generous outer
                # deadline is a last-resort guard, not a change to test deadlines.
                child = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    status = child.wait(timeout=args.timeout)
                    error = None
                except BaseException as failure:
                    import signal
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    if not isinstance(failure, subprocess.TimeoutExpired):
                        raise
                    status, error = child.returncode, 'integration runner deadline exceeded'
            value = {'name': name, 'command': argv, 'returncode': status, 'error': error,
                     'passed': status == 0 and error is None, 'seconds': round(time.monotonic() - started, 3)}
            results.append(value)
            print(json.dumps(value), flush=True)
    unchanged = verify_reference(go, args.workspace) == references and hashlib.sha256(binary.read_bytes()).hexdigest() == original_hash
    report = {'reference_commit': REFERENCE_COMMIT, 'reference': references,
              'binary': {'path': str(binary), 'sha256': original_hash}, 'binaries_unchanged': unchanged,
              'scripts': results}
    (args.output / 'integration-results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return 0 if unchanged and all(value['passed'] for value in results) else 1


def main():
    if sys.platform != 'linux':
        raise RuntimeError('AnyTLS integration fixtures require Linux')
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('prepare', 'run'):
        sub = commands.add_parser(name)
        sub.add_argument('--workspace', required=True, type=lambda value: Path(value).resolve())
        sub.add_argument('--go', default='go')
        if name == 'prepare':
            sub.add_argument('--download', action='store_true', help='explicitly allow reference/toolchain/module downloads')
            sub.add_argument('--reference-source', type=lambda value: Path(value).resolve())
        else:
            sub.add_argument('--binary', required=True)
            sub.add_argument('--output', required=True, type=lambda value: Path(value).resolve())
            sub.add_argument('--suite', action='append', choices=SCRIPTS)
            sub.add_argument('--timeout', type=float, default=600)
    args = parser.parse_args()
    return prepare(args) if args.command == 'prepare' else run(args)


if __name__ == '__main__':
    raise SystemExit(main())

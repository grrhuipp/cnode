"""Real Xray 1-RTT/0-RTT/replay test against a multi-Worker cnode inbound.

The bridge captures actual client traffic, not a synthesized implementation.
Repeated connections exercise SO_REUSEPORT admission; first-response byte counts
prove resumed flights were used. Captured resumed traffic is then replayed intact
and must never reach the target. All listeners/credentials are loopback fixtures.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import re
import subprocess

from anytls_fin_integration import Resources, USER, available_port, configure, target
from vless_xray_interop import REFERENCE_COMMIT, RELEASE_SHA256


async def run_case(args, mode, output):
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    flights = []
    target_requests = []
    boundary_peers = {}
    request = b'vless-0rtt-real-xray'
    response = b'accepted-once-per-nfs-key'
    result = {'mode': mode, 'passed': False}
    try:
        keys = subprocess.run([str(args.xray), 'vlessenc'], check=True,
                              capture_output=True, text=True).stdout
        # The generator emits X25519 first, then ML-KEM-768. Use one matched pair.
        decryption = re.findall(r'"decryption": "([^"]+)"', keys)[0]
        encryption = re.findall(r'"encryption": "([^"]+)"', keys)[0]
        decryption = decryption.replace('.native.', f'.{mode}.')
        encryption = encryption.replace('.native.', f'.{mode}.')

        async def backend(reader, writer):
            data = await reader.readexactly(len(request))
            assert data == request
            target_requests.append(data.hex())
            writer.write(response)
            await writer.drain()

        backend_port = await resources.listen(backend)
        server_port, front_port = available_port(), available_port()

        async def bridge(reader, writer):
            upstream_reader, upstream_writer = await resources.connect(server_port)
            flight = {'sent': bytearray(), 'before_first_response': None}
            flights.append(flight)

            async def upload():
                while data := await reader.read(65536):
                    flight['sent'].extend(data)
                    upstream_writer.write(data)
                    await upstream_writer.drain()
                upstream_writer.write_eof()

            async def download():
                while data := await upstream_reader.read(65536):
                    if flight['before_first_response'] is None:
                        flight['before_first_response'] = len(flight['sent'])
                    writer.write(data)
                    await writer.drain()
                writer.write_eof()

            try:
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(upload())
                    tasks.create_task(download())
            except* ConnectionError:
                pass

        bridge_port = await resources.listen(bridge)
        configure(output,
            {'protocol': 'vless', 'listen': '127.0.0.1', 'port': server_port, 'proxyProtocol': 'off',
             'settings': {'decryption': decryption, 'clients': [{'id': str(USER)}]}},
            {'protocol': 'freedom', 'settings': {}})
        config_path = output / 'config.json'
        config = json.loads(config_path.read_text())
        config['workers'] = 4
        config['timeouts']['handshake'] = 2
        config['log'].update(enable=True, loglevel='debug')
        config_path.write_text(json.dumps(config))
        reference = {'log': {'loglevel': 'debug'},
            'inbounds': [{'listen': '127.0.0.1', 'port': front_port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': False}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                'address': '127.0.0.1', 'port': bridge_port,
                'users': [{'id': str(USER), 'encryption': encryption}]}]}}]}
        reference_path = output / 'xray.json'
        reference_path.write_text(json.dumps(reference))
        resources.spawn([args.binary, '--config-dir', output], output / 'cnode.log')
        resources.spawn([args.xray, 'run', '-config', reference_path], output / 'xray.log')
        for number in range(17):
            reader, writer = await resources.connect(front_port)
            writer.write(b'\5\1\0')
            await writer.drain()
            assert await reader.readexactly(2) == b'\5\0'
            writer.write(b'\5\1\0' + target(backend_port))
            await writer.drain()
            header = await reader.readexactly(4)
            assert header[:2] == b'\5\0'
            await reader.readexactly(6 if header[3] == 1 else 18)
            writer.write(request)
            await writer.drain()
            assert await reader.readexactly(len(response)) == response
            writer.close()
            await writer.wait_closed()
            assert len(target_requests) == number + 1
        assert len(flights) == 17, 'unexpected reconnect fallback or missing connection'
        assert flights[0]['before_first_response'] >= 1298, 'initial PFS flight not observed'
        assert all(98 <= item['before_first_response'] < 1000 for item in flights[1:]), \
            'resumption silently fell back to a fresh PFS handshake'

        # Bypass PROXY autodetection: these connections must reach the encryption
        # runtime itself, including a truly empty FIN and a nonempty short flight.
        for kind, payload in (
                ('empty', b''), ('truncated', b'\0'),
                ('rejected', b'\0' * len(flights[0]['sent'])), ('timeout', None)):
            reader, writer = await resources.connect(server_port)
            boundary_peers[kind] = writer.get_extra_info('sockname')[1]
            if payload is not None:
                writer.write(payload)
                await writer.drain()
                writer.write_eof()
            try:
                await asyncio.wait_for(reader.read(), 4)
            except ConnectionError:
                pass
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
        assert len(target_requests) == 17, 'invalid handshake reached target'
        replay = bytes(flights[1]['sent'])
        (output / 'captured-zero-rtt.bin').write_bytes(replay)
        for _ in range(64):
            reader, writer = await resources.connect(server_port)
            writer.write(replay)
            await writer.drain()
            try:
                await asyncio.wait_for(reader.read(), 3)
            except ConnectionError:
                pass
            writer.close()
        assert len(target_requests) == 17, 'replayed early data reached target'
        result.update(passed=True, authenticated_requests=len(target_requests),
            first_response_client_bytes=[item['before_first_response'] for item in flights],
            replay_sha256=hashlib.sha256(replay).hexdigest())
    except Exception as error:
        result['error'] = repr(error)
    finally:
        result['children_alive'] = all(child.poll() is None for child in resources.children)
        await resources.close()
    result['peer_errors'] = resources.errors
    result['passed'] &= not resources.errors and result['children_alive']
    logs = '\n'.join(path.read_text(errors='replace') for path in output.rglob('*.log'))
    for kind, port in boundary_peers.items():
        peer_logs = '\n'.join(line for line in logs.splitlines() if f'127.0.0.1:{port}' in line)
        expected = {'truncated': 'encryption handshake truncated',
                    'rejected': 'encryption handshake rejected', 'timeout': 'timeout'}
        valid = ('encryption handshake' not in peer_logs and 'authentication failed' not in peer_logs
                 if kind == 'empty' else
                 (expected[kind] in peer_logs or
                  (kind == 'timeout' and 'encryption handshake timed out' in peer_logs)))
        if not valid:
            result['passed'] = False
            result.setdefault('error', f'{kind} encryption boundary misclassified: {peer_logs}')
    lookups = [(int(owner), int(receiver), accepted == 'true')
               for owner, receiver, accepted in re.findall(
                   r'ticket lookup owner=(\d+) receiver=(\d+) accepted=(true|false)', logs)]
    accepted = [item for item in lookups if item[2]]
    rejected = [item for item in lookups if not item[2]]
    evidence = {
        'resumed_receiver_workers': sorted({receiver for _, receiver, _ in accepted}),
        'cross_worker_accepts': sum(owner != receiver for owner, receiver, _ in accepted),
        'same_worker_replay_rejects': sum(owner == receiver for owner, receiver, _ in rejected),
        'cross_worker_replay_rejects': sum(owner != receiver for owner, receiver, _ in rejected),
    }
    result['worker_evidence'] = evidence
    if not (len(accepted) == 16 and len(evidence['resumed_receiver_workers']) >= 2
            and evidence['cross_worker_accepts'] > 0
            and evidence['same_worker_replay_rejects'] > 0
            and evidence['cross_worker_replay_rejects'] > 0 and len(rejected) == 64):
        result['passed'] = False
        result.setdefault('error', 'missing proof of cross-Worker resumption and both replay admission paths')
    (output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    digest = hashlib.sha256(args.xray.read_bytes()).hexdigest()
    metadata = subprocess.run([args.go, 'version', '-m', str(args.xray)], check=True,
                              capture_output=True, text=True).stdout
    assert digest == RELEASE_SHA256 or (f'vcs.revision={REFERENCE_COMMIT}' in metadata
                                        and 'vcs.modified=false' in metadata)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'xray-build.txt').write_text(metadata)
    results = []
    for mode in ('native', 'xorpub', 'random'):
        results.append(await asyncio.wait_for(run_case(args, mode, args.output / mode), 120))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2))
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('binary', 'xray', 'output'):
        parser.add_argument('--' + name, required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--go', default='go')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

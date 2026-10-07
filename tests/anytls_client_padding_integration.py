"""A peer's padding policy survives physical sessions and stays within its outbound client."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct
import traceback

from anytls_fin_integration import (
    Resources, USER, REQUEST, BANNER, available_port, frame, target,
    tls_settings, open_application, observe_eof, until,
)
from anytls_padding_integration import DEFAULT


async def scenario(args, name, output, result, resources):
    shared_endpoint = name == 'shared-endpoint'
    auth_a = 65535 if name == 'maximum-auth' else 45
    policies = {
        'a': f'stop=8\n0={auth_a}-{auth_a}\n1=256-256\n2=64-64\n'.encode(),
        'b': b'stop=8\n0=91-91\n1=320-320\n2=80-80\n',
    }
    sessions = {'a': [], 'b': []}
    hashes = {hashlib.sha256(f'secret-{key}'.encode()).digest(): key for key in sessions}

    async def server(reader, writer):
        auth = await reader.readexactly(34)
        key = hashes[auth[:32]]
        padding_length = int.from_bytes(auth[32:], 'big')
        assert await reader.readexactly(padding_length) == bytes(padding_length)
        state = {'writer': writer, 'auth_padding': padding_length, 'settings': b'', 'padding': [],
                 'requests': {}, 'barriers': 0, 'closed': False, 'sids': []}
        sessions[key].append(state)
        try:
            while True:
                command, sid, length = struct.unpack('!BIH', await reader.readexactly(7))
                payload = await reader.readexactly(length)
                if command == 4:
                    state['settings'] = payload
                    writer.write(frame(10, payload=b'v=2'))
                elif command == 1:
                    state['sids'].append(sid)
                    state['requests'][sid] = bytearray()
                    writer.write(frame(7, sid))
                elif command == 2:
                    state['requests'][sid].extend(payload)
                    if state['requests'][sid] == target(443) + REQUEST:
                        if len(sessions[key]) == 1:
                            writer.write(frame(6, payload=policies[key]) + frame(6, payload=b'stop=0\n1=bad'))
                        writer.write(frame(2, sid, BANNER) + frame(3, sid) + frame(8))
                elif command == 0:
                    assert payload == bytes(length)
                    state['padding'].append(length)
                elif command == 9:
                    state['barriers'] += 1
                await writer.drain()
        finally:
            state['closed'] = True

    peer_a = await resources.listen(server, tls=True)
    peer_b = peer_a if shared_endpoint else await resources.listen(server, tls=True)
    ports = {'a': available_port(), 'b': available_port()}
    config = {'workers': 1, 'timeouts': {'handshake': 5, 'connIdle': 15, 'write': 5,
              'uplinkOnly': 10, 'downlinkOnly': 10},
              'log': {'enable': False, 'logDir': (output / 'logs').as_posix()}}
    inbounds = [{'tag': f'client-{key}', 'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                 'settings': {'clients': [{'id': str(USER)}]}} for key, port in ports.items()]
    outbounds = [{'tag': f'peer-{key}', 'protocol': 'anytls', 'settings': {
        'server': '127.0.0.1', 'server_port': peer_port, 'password': f'secret-{key}', 'minIdleSession': 1},
        'streamSettings': tls_settings()} for key, peer_port in [('a', peer_a), ('b', peer_b)]]
    routing = {'rules': [{'type': 'field', 'inboundTag': [f'client-{key}'], 'outboundTag': f'peer-{key}'}
                         for key in ports]}
    for file, value in [('config.json', config), ('inbounds.json', inbounds), ('outbounds.json', outbounds), ('routing.json', routing)]:
        (output / file).write_text(json.dumps(value))
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    observations = []
    for key in ['a', 'b', 'a', 'b', 'a']:
        reader, _ = await open_application(resources, ports[key], False)
        payload, eof, _ = await observe_eof(reader)
        assert payload == BANNER and eof, 'application roundtrip failed'
        state = sessions[key][-1]
        await until(lambda: state['barriers'] == 1)
        first = len(sessions[key]) == 1
        raw = DEFAULT if first else policies[key]
        digest = hashlib.md5(raw).hexdigest()
        settings = b'v=2\nclient=cnode\npadding-md5=' + digest.encode()
        auth_expected = 30 if first else (auth_a if key == 'a' else 91)
        padding_expected = None if first else [
            (256 if key == 'a' else 320) - (7 + len(settings) + 7 + 7 + len(target(443))) - 7,
            (64 if key == 'a' else 80) - (7 + len(REQUEST)) - 7,
        ]
        passed = state['auth_padding'] == auth_expected and state['settings'] == settings and state['sids'] == [1]
        if not first: passed &= state['padding'] == padding_expected
        observations.append({'peer': key, 'connection': len(sessions[key]), 'auth_padding': state['auth_padding'],
            'expected_auth_padding': auth_expected, 'settings': state['settings'].decode(), 'expected_md5': digest,
            'padding_lengths': state['padding'], 'expected_padding_lengths': padding_expected, 'passed': passed})
        # Wait for the peer to observe cnode closing after Alert. The following
        # application request must create a physical session instead of racing
        # an idle checkout whose background reader has not processed EOF yet.
        state['writer'].write(frame(5, payload=b'fixture requires a fresh physical session'))
        await state['writer'].drain()
        await until(lambda: state['closed'])
    result.update(passed=all(value['passed'] for value in observations), shared_endpoint=shared_endpoint,
                  physical_connections={key: len(values) for key, values in sessions.items()}, observations=observations)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for name in ('distinct-endpoints', 'shared-endpoint', 'maximum-auth'):
        output = args.output / name
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': name, 'passed': False}
        try:
            await asyncio.wait_for(scenario(args, name, output, result, resources), 20)
        except Exception as error:
            result.update(passed=False, error=repr(error), traceback=traceback.format_exc())
        finally:
            result['children_alive_before_cleanup'] = bool(resources.children) and all(c.poll() is None for c in resources.children)
            await resources.close()
        result['peer_errors'] = resources.errors
        result['passed'] &= result['children_alive_before_cleanup'] and not resources.errors
        results.append(result)
        print(json.dumps(result), flush=True)
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps({'binary_sha256': digest, 'cases': results}, indent=2))
    return 0 if all(value['passed'] for value in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

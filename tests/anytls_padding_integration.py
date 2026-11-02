"""Prepared padding policies over real inbound and outbound AnyTLS/TLS sessions."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct

from anytls_fin_integration import (
    Resources, Frames, USER, REQUEST, BANNER, available_port, configure, frame,
    target, tls_settings, open_application, observe_eof, until,
)

DEFAULT = (b'stop=8\n0=30-30\n1=100-400\n'
           b'2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n'
           b'3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000')
SPARSE = b'stop=4294967295\n4294967294=64-65\n0=45-45\n7=96-96\n'


async def inbound(args, name, output, result, resources):
    requests = []

    async def destination(reader, writer):
        requests.append(await reader.readexactly(len(REQUEST)))
        writer.write(BANNER)
        await writer.drain()

    destination_port = await resources.listen(destination)
    port = available_port()
    as_array = 'array' in name
    matched = name.endswith('matched')
    raw = SPARSE.rstrip(b'\n') if as_array else SPARSE
    setting = raw.decode().split('\n') if as_array else raw.decode()
    configure(output, {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': port,
                       'settings': {'clients': [{'password': 'secret'}], 'paddingScheme': setting},
                       'streamSettings': tls_settings(True)}, {'protocol': 'freedom', 'settings': {}})
    # Separate worker handlers must consume the same immutable prepared policy.
    config = json.loads((output / 'config.json').read_text())
    config['workers'] = 2
    (output / 'config.json').write_text(json.dumps(config))
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    updates = []
    for connection in range(4):
        reader, writer = await resources.connect(port, tls=True)
        received = Frames(resources, reader)
        digest = hashlib.md5(raw).hexdigest().encode() if matched else b'outdated'
        writer.write(hashlib.sha256(b'secret').digest() + b'\0\0'
                     + frame(4, payload=b'v=2\npadding-md5=' + digest))
        for sid in (1, 2):
            writer.write(frame(1, sid) + frame(2, sid, target(destination_port) + REQUEST))
            await writer.drain()
            await until(lambda: received.payload(sid) == BANNER and received.count(3, sid) == 1)
        await received.barrier(writer)
        values = [payload for command, _, payload in received.values if command == 6]
        assert values == ([] if matched else [raw]), 'raw scheme distribution or digest matching failed'
        updates.append(len(values))
    result.update(passed=requests == [REQUEST] * 8, connections=4, logical_streams=len(requests),
                  updates_per_connection=updates, scheme_md5=hashlib.md5(raw).hexdigest())


async def outbound(args, name, output, result, resources):
    if name == 'outbound-stop':
        scheme = b'stop=4\n0=128-128\n3=96-96\n'
        expected = {'2': [68], '3': []}
    else:
        high = b'2147483647' if name == 'outbound-sparse-int32' else b'4294967294'
        scheme = b'stop=4294967295\n' + high + b'=64-65\n3=96-96\n4=128-128\n'
        expected = {'2': [68, 106], '3': []}
    sessions = []
    barriers = 0

    async def server(reader, writer):
        nonlocal barriers
        state = {'targets': [], 'padding': {}, 'requests': {}}
        sessions.append(state)
        auth = await reader.readexactly(34)
        assert auth[:32] == hashlib.sha256(b'secret').digest()
        assert int.from_bytes(auth[32:], 'big') == 30
        await reader.readexactly(30)
        active = 0
        while True:
            command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
            payload = await reader.readexactly(size)
            if command == 4:
                assert b'padding-md5=' + hashlib.md5(DEFAULT).hexdigest().encode() in payload
                writer.write(frame(10, payload=b'v=2'))
            elif command == 1:
                active = sid
                state['targets'].append(sid)
                state['padding'][str(sid)] = []
                state['requests'][sid] = bytearray()
                writer.write(frame(7, sid))
            elif command == 2:
                state['requests'][sid].extend(payload)
                if state['requests'][sid] == target(443) + REQUEST:
                    if sid == 1:
                        # The invalid update following a valid one must leave it usable.
                        writer.write(frame(6, payload=scheme) + frame(6, payload=b'stop=0\n1=bad'))
                    writer.write(frame(2, sid, BANNER) + frame(3, sid) + frame(8))
            elif command == 0:
                assert payload == bytes(size)
                state['padding'][str(active)].append(size)
            elif command == 9:
                barriers += 1
            await writer.drain()

    peer_port = await resources.listen(server, tls=True)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                       'settings': {'clients': [{'id': str(USER)}]}},
              {'protocol': 'anytls', 'settings': {'server': '127.0.0.1', 'server_port': peer_port,
               'password': 'secret', 'minIdleSession': 1}, 'streamSettings': tls_settings()})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    for sid in (1, 2, 3):
        reader, _ = await open_application(resources, port, False)
        data, eof, _ = await observe_eof(reader)
        assert data == BANNER and eof, 'application roundtrip failed'
        await until(lambda: barriers == sid)
    actual = {sid: sessions[0]['padding'].get(sid) for sid in expected}
    result.update(passed=len(sessions) == 1 and sessions[0]['targets'] == [1, 2, 3] and actual == expected,
                  physical_connections=len(sessions), stream_ids=sessions[0]['targets'],
                  padding_lengths=actual, expected_padding_lengths=expected, scheme_bytes=len(scheme),
                  barriers=barriers)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    cases = [args.case] if args.case else [
        'inbound-text-update', 'inbound-text-matched', 'inbound-array-update', 'inbound-array-matched',
        'outbound-sparse-int32', 'outbound-sparse-uint32', 'outbound-stop']
    results = []
    for name in cases:
        output = args.output / name
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': name, 'passed': False}
        try:
            scenario = inbound if name.startswith('inbound') else outbound
            await asyncio.wait_for(scenario(args, name, output, result, resources), 16)
        except Exception as error:
            result.update(passed=False, error=repr(error))
        finally:
            result['children_alive_before_cleanup'] = bool(resources.children) and all(c.poll() is None for c in resources.children)
            await resources.close()
        result['peer_errors'] = resources.errors
        result['passed'] &= result['children_alive_before_cleanup'] and not resources.errors
        results.append(result)
        print(json.dumps(result), flush=True)
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps({'binary_sha256': digest, 'cases': results}, indent=2))
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--case')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

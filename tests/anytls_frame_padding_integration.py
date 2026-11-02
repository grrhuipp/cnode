"""Frame padding obeys wire capacity independently of internal buffer sizes."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import traceback

from anytls_fin_integration import (
    Resources, USER, REQUEST, BANNER, available_port, frame, target,
    configure, tls_settings, open_application, observe_eof, until, REFERENCE_COMMIT,
)
from anytls_padding_integration import DEFAULT
from anytls_auth_padding_integration import LEARNED


# The opening packet is 89 bytes: Settings + SYN + PSH(target). A mixed
# Waste adds a seven-byte header; a subsequent pure Waste carries its own size.
CASES = [
    ('one-byte', '1-1', [], True),
    ('seven-bytes', '7-7', [], True),
    ('eight-bytes', '8-8', [], True),
    ('buffer-minus-one', '8191-8191', [8095], True),
    ('buffer-size', '8192-8192', [8096], True),
    ('buffer-plus-one', '8193-8193', [8097], True),
    ('tls-size', '16384-16384', [16288], True),
    ('maximum', '65535-65535', [65439], True),
    ('upper-range', '65535-65536', [65439], True),
    ('reversed-range', '65536-65535', [65439], True),
    ('split-then-pad', '1-1,7-7,8-8,8192-8192,c,65535-65535', [8112], True),
    ('pure-maximum', '256-256,65535-65535', [160, 65535], True),
    ('pure-buffer-size', '256-256,8192-8192', [160, 8192], True),
    ('check-before-maximum', '256-256,c,65535-65535', [160], True),
    ('constant-overflow', '65536-65536', [160], False),
    ('range-overflow', '65534-65537', [160], False),
    ('overflow-after-check', '256-256,c,65536-65536', [160], False),
    ('invalid-last-duplicate', '256-256\n1=65536-65536', [160], False),
    ('invalid-first-duplicate', '65536-65536\n1=256-256', [160], False),
]


async def scenario(args, record, padding_expected, valid, output, result, resources):
    candidate = f'stop=3\n0=45-45\n1={record}\n2=64-64\n'.encode()
    sessions = []

    async def server(reader, writer):
        auth = await reader.readexactly(34)
        assert auth[:32] == hashlib.sha256(b'frame-padding-fixture').digest()
        padding_length = int.from_bytes(auth[32:], 'big')
        assert await reader.readexactly(padding_length) == bytes(padding_length)
        state = {'writer': writer, 'auth_padding': padding_length, 'settings': b'',
                 'request': bytearray(), 'padding': [], 'barriers': 0, 'closed': False, 'sids': []}
        sessions.append(state)
        connection = len(sessions)
        try:
            while True:
                command, sid, length = struct.unpack('!BIH', await reader.readexactly(7))
                payload = await reader.readexactly(length)
                if command == 4:
                    state['settings'] = payload
                    writer.write(frame(10, payload=b'v=2'))
                elif command == 1:
                    state['sids'].append(sid)
                    writer.write(frame(7, sid))
                elif command == 2:
                    state['request'].extend(payload)
                    if state['request'] == target(443) + REQUEST:
                        if connection <= 2:
                            writer.write(frame(6, payload=LEARNED if connection == 1 else candidate))
                        writer.write(frame(2, sid, BANNER) + frame(3, sid) + frame(8))
                elif command == 0:
                    assert payload == bytes(length)
                    state['padding'].append(length)
                elif command == 9:
                    state['barriers'] += 1
                await writer.drain()
        finally:
            state['closed'] = True

    peer_port = await resources.listen(server, tls=True)
    front_port = available_port()
    configure(output,
        {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
         'settings': {'clients': [{'id': str(USER)}]}},
        {'protocol': 'anytls', 'settings': {'server': '127.0.0.1', 'server_port': peer_port,
         'password': 'frame-padding-fixture', 'minIdleSession': 1}, 'streamSettings': tls_settings()})
    if args.reference_client:
        resources.spawn([args.reference_client, '-l', f'127.0.0.1:{front_port}', '-s',
                         f'127.0.0.1:{peer_port}', '-p', 'frame-padding-fixture', '-m', '1'], output / 'child.log')
    else:
        resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    observations = []
    for index in range(4):
        payload, eof, error = b'', False, None
        try:
            reader, _ = await open_application(resources, front_port, bool(args.reference_client))
            payload, eof, _ = await observe_eof(reader)
        except (asyncio.IncompleteReadError, ConnectionError) as exception:
            error = repr(exception)
        await until(lambda: len(sessions) > index)
        state = sessions[index]
        complete = payload == BANNER and eof
        if complete:
            await until(lambda: state['barriers'] == 1)
        raw = DEFAULT if index == 0 else LEARNED if index == 1 or not valid else candidate
        client = b'anytls/0.0.13' if args.reference_client else b'cnode'
        settings = b'v=2\nclient=' + client + b'\npadding-md5=' + hashlib.md5(raw).hexdigest().encode()
        delta = len(client) - len(b'cnode')
        assert 7 + len(settings) + 7 + 7 + len(target(443)) == 89 + delta
        opening_padding = [160] if index == 1 or not valid else list(padding_expected)
        if opening_padding:
            opening_padding[0] -= delta
        expected = None if index == 0 else opening_padding + [42]
        settings_match = state['settings'] == settings
        if args.reference_client:
            # The reference serializes a Go map in arbitrary field order.
            settings_match = dict(line.split(b'=', 1) for line in state['settings'].splitlines()) == dict(
                line.split(b'=', 1) for line in settings.splitlines())
        passed = complete and settings_match and state['sids'] == [1]
        passed &= state['auth_padding'] == (30 if index == 0 else 45)
        if expected is not None:
            passed &= state['padding'] == expected
        observations.append({'connection': index + 1, 'auth_padding': state['auth_padding'],
            'settings': state['settings'].decode(), 'expected_settings': settings.decode(),
            'padding_lengths': state['padding'], 'expected_padding_lengths': expected,
            'target_bytes': bytes(state['request']).hex(), 'application_complete': complete,
            'application_error': error, 'passed': passed})
        if complete:
            state['writer'].write(frame(5, payload=b'fixture requires a fresh physical session'))
            await state['writer'].drain()
        await until(lambda: state['closed'])
    result.update(passed=all(value['passed'] for value in observations), candidate=candidate.decode(),
                  candidate_valid=valid, physical_connections=len(sessions), observations=observations)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    reference_hash = None
    if args.reference_client:
        reference_hash = hashlib.sha256(args.reference_client.read_bytes()).hexdigest()
        metadata = subprocess.run([str(args.go), 'version', '-m', str(args.reference_client)],
                                  check=True, capture_output=True, text=True).stdout
        assert f'vcs.revision={REFERENCE_COMMIT}' in metadata and 'vcs.modified=false' in metadata
        assert 'path\tanytls/cmd/client' in metadata
    results = []
    for name, record, expected, valid in CASES:
        if args.reference_client and not valid:
            continue  # Never feed unencodable rules to the unmodified reference.
        output = args.output / name
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': name, 'passed': False}
        try:
            await asyncio.wait_for(scenario(args, record, expected, valid, output, result, resources), 20)
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
    if args.reference_client:
        assert hashlib.sha256(args.reference_client.read_bytes()).hexdigest() == reference_hash
    (args.output / 'results.json').write_text(json.dumps({'binary_sha256': digest,
        'reference_sha256': reference_hash, 'cases': results}, indent=2))
    return 0 if all(value['passed'] for value in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--reference-client', type=lambda x: Path(x).resolve())
    parser.add_argument('--go', type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

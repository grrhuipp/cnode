"""Observe authentication bytes after peer policy updates and physical reconnects."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct
import traceback

from anytls_fin_integration import (
    Resources, USER, REQUEST, BANNER, available_port, frame, target,
    configure, tls_settings, open_application, observe_eof, until,
)
from anytls_padding_integration import DEFAULT


LEARNED = b'stop=8\n0=45-45\n1=256-256\n2=64-64\n'
CASES = [
    ('missing-zero', b'stop=3\n1=160-160\n2=80-80\n', (0, 0)),
    ('stop-only', b'stop=1\n', (0, 0)),
    ('explicit-zero', b'stop=2\n0=0-0\n1=160-160\n', (0, 0)),
    ('auth-only', b'stop=1\n0=45-45\n', (45, 45)),
    ('range', b'stop=2\n0=45-77\n1=160-160\n', (45, 77)),
    ('reversed-range', b'stop=2\n0=77-45\n1=160-160\n', (45, 77)),
    ('upper-bound', b'stop=2\n0=65535-65536\n1=160-160\n', (65535, 65536)),
    ('valid-duplicate', b'stop=2\n0=45-45\n0=91-91\n1=160-160\n', (91, 91)),
    ('constant-overflow', b'stop=2\n0=65536-65536\n1=160-160\n', None),
    ('range-overflow', b'stop=2\n0=65534-65537\n1=160-160\n', None),
    ('copy-marker', b'stop=2\n0=c,55-55\n1=160-160\n', None),
    ('multiple-ranges', b'stop=2\n0=45-45,50-50\n1=160-160\n', None),
    ('negative', b'stop=2\n0=-1-10\n1=160-160\n', None),
    ('malformed', b'stop=2\n0=garbage\n1=160-160\n', None),
    ('zero-nonzero', b'stop=2\n0=0-10\n1=160-160\n', None),
    ('empty-auth', b'stop=2\n0=\n1=160-160\n', None),
    ('trailing-comma', b'stop=2\n0=45-45,\n1=160-160\n', None),
    ('invalid-last-duplicate', b'stop=2\n0=45-45\n0=bad\n1=160-160\n', None),
    ('invalid-first-duplicate', b'stop=2\n0=bad\n0=45-45\n1=160-160\n', None),
]


async def scenario(args, candidate, expected_range, output, result, resources):
    sessions = []

    async def server(reader, writer):
        auth = await reader.readexactly(34)
        assert auth[:32] == hashlib.sha256(b'auth-policy-fixture').digest()
        padding_length = int.from_bytes(auth[32:], 'big')
        assert await reader.readexactly(padding_length) == bytes(padding_length)
        state = {'writer': writer, 'auth_padding': padding_length, 'settings': b'',
                 'request': bytearray(), 'barriers': 0, 'closed': False, 'sids': []}
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
         'password': 'auth-policy-fixture', 'minIdleSession': 1}, 'streamSettings': tls_settings()})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    samples = 32 if expected_range == (45, 77) else 2
    observations = []
    for index in range(2 + samples):
        reader, _ = await open_application(resources, front_port, False)
        payload, eof, _ = await observe_eof(reader)
        assert payload == BANNER and eof, 'application roundtrip failed'
        state = sessions[-1]
        await until(lambda: state['barriers'] == 1)
        raw = DEFAULT if index == 0 else LEARNED if index == 1 or expected_range is None else candidate
        lo, hi = (30, 30) if index == 0 else (45, 45) if index == 1 or expected_range is None else expected_range
        digest = hashlib.md5(raw).hexdigest()
        settings = b'v=2\nclient=cnode\npadding-md5=' + digest.encode()
        auth_matches = state['auth_padding'] == lo if lo == hi else lo <= state['auth_padding'] < hi
        passed = auth_matches and state['settings'] == settings and state['sids'] == [1]
        observations.append({'connection': index + 1, 'auth_padding': state['auth_padding'],
            'expected_range': [lo, hi], 'settings': state['settings'].decode(),
            'expected_md5': digest, 'passed': passed})
        # An acknowledged update plus observed peer closure makes the next auth
        # unambiguously belong to a fresh physical session with the learned policy.
        state['writer'].write(frame(5, payload=b'fixture requires a fresh physical session'))
        await state['writer'].drain()
        await until(lambda: state['closed'])
    distinct = sorted({value['auth_padding'] for value in observations[2:]})
    varied = samples != 32 or len(distinct) >= 2
    result.update(passed=all(value['passed'] for value in observations) and varied,
                  candidate=candidate.decode(), candidate_valid=expected_range is not None,
                  physical_connections=len(sessions), samples=samples, distinct_sizes=distinct,
                  range_varied=varied, observations=observations)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for name, candidate, expected in CASES:
        output = args.output / name
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': name, 'passed': False}
        try:
            await asyncio.wait_for(scenario(args, candidate, expected, output, result, resources), 30)
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

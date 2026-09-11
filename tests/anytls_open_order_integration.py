"""Real TLS opening writes under backpressure while the peer closes the logical stream."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct
import time

from anytls_fin_integration import (
    Resources, USER, REQUEST, BANNER, available_port, configure, frame,
    target, tls_settings, open_application, observe_eof,
)

PADDING_RECORDS = 4096
PADDING_SCHEME = b'stop=4\n3=' + b','.join([b'8000-8001'] * PADDING_RECORDS) + b'\n'


async def scenario(args, with_payload, output, result, resources):
    sessions = []
    expected = bytes(range(251)) * 32 if with_payload else b''
    drained = asyncio.Event()

    async def server(reader, writer):
        session = {'targets': [], 'requests': {}, 'padding_bytes': 0, 'fin_replies': 0,
                   'payload_after_fin': 0, 'fin_at': None, 'barrier_at': None}
        sessions.append(session)
        auth = await reader.readexactly(34)
        assert auth[:32] == hashlib.sha256(b'secret').digest()
        await reader.readexactly(int.from_bytes(auth[32:], 'big'))
        while True:
            command, sid, length = struct.unpack('!BIH', await reader.readexactly(7))
            payload = await reader.readexactly(length)
            if command == 4:
                writer.write(frame(10, payload=b'v=2'))
            elif command == 1:
                session['targets'].append(sid)
                session['requests'][sid] = bytearray()
                if sid != 2:
                    writer.write(frame(7, sid))
            elif command == 2:
                session['requests'][sid].extend(payload)
                if sid == 2:
                    if session['fin_at'] is None:
                        assert session['requests'][sid] == target(443), 'opening write must contain only the target'
                        session['fin_at'] = time.monotonic()
                        writer.write((frame(2, sid, expected) if expected else b'') + frame(3, sid) + frame(8))
                        await writer.drain()
                        # The 32 MiB padding train cannot drain through the
                        # paused TLS reader. FIN travels in the other direction.
                        await asyncio.sleep(0.4)
                    else:
                        session['payload_after_fin'] += len(payload)
                elif session['requests'][sid] == target(443) + REQUEST:
                    if sid == 1:
                        writer.write(frame(6, payload=PADDING_SCHEME))
                    writer.write(frame(2, sid, BANNER) + frame(3, sid))
            elif command == 0 and session['fin_at'] is not None:
                session['padding_bytes'] += length
            elif command == 3 and sid == 2:
                session['fin_replies'] += 1
            elif command == 9:
                session['barrier_at'] = time.monotonic()
                drained.set()
            await writer.drain()

    server_port = await resources.listen(server, tls=True)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                       'settings': {'clients': [{'id': str(USER)}]}},
              {'protocol': 'anytls', 'settings': {'server': '127.0.0.1', 'server_port': server_port,
               'password': 'secret', 'minIdleSession': 1}, 'streamSettings': tls_settings()})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    reader, _ = await open_application(resources, port, False)
    data, eof, _ = await observe_eof(reader)
    assert eof and data == BANNER and len(sessions) == 1, 'warmup failed'
    reader, writer = await resources.connect(port)
    writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', 443) + b'\1\x7f\0\0\1' + REQUEST)
    await writer.drain()
    response, eof, _ = await observe_eof(reader, 6)
    header_valid = response[:2] == b'\0\0'
    data = response[2:] if header_valid else response
    closed_at = time.monotonic()
    await asyncio.wait_for(drained.wait(), 2)
    first = sessions[0]
    result.update(eof=eof, header_valid=header_valid, received_bytes=len(data), expected_bytes=len(expected),
                  close_after_fin_seconds=round(closed_at - first['fin_at'], 3),
                  barrier_after_fin_seconds=round(first['barrier_at'] - first['fin_at'], 3),
                  padding_bytes=first['padding_bytes'], payload_after_fin=first['payload_after_fin'],
                  fin_replies=first['fin_replies'])
    reader, _ = await open_application(resources, port, False)
    recovered, recovery_eof, _ = await observe_eof(reader)
    result.update(physical_connections=len(sessions), stream_ids=first['targets'],
                  recovered=recovery_eof and recovered == BANNER)
    result['passed'] = eof and header_valid and data == expected and result['close_after_fin_seconds'] < 2 and \
        first['padding_bytes'] >= 30 * 1024 * 1024 and not first['payload_after_fin'] and \
        not first['fin_replies'] and result['recovered'] and len(sessions) == 1 and first['targets'] == [1, 2, 3]


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for with_payload in (False, True):
        output = args.output / ('payload-fin' if with_payload else 'empty-fin')
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': output.name, 'passed': False}
        try:
            await asyncio.wait_for(scenario(args, with_payload, output, result, resources), 16)
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
    (args.output / 'results.json').write_text(json.dumps({'binary_sha256': digest, 'cases': results}, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

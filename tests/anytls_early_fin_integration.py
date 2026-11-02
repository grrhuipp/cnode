"""Close logical streams during header preparation and before SYNACK."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct

from anytls_fin_integration import (
    Resources, Frames, USER, REQUEST, BANNER, available_port, configure, frame,
    target, tls_settings, until, open_application, observe_eof,
)


async def inbound_case(args, prefix, output, result, resources):
    requests = []

    async def backend(reader, writer):
        requests.append(await reader.readexactly(len(REQUEST)))
        writer.write(BANNER)
        await writer.drain()

    backend_port = await resources.listen(backend)
    port = available_port()
    configure(output,
              {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': port,
               'settings': {'clients': [{'password': 'secret'}]}, 'streamSettings': tls_settings(True)},
              {'protocol': 'freedom', 'settings': {}})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    reader, writer = await resources.connect(port, tls=True)
    received = Frames(resources, reader)
    writer.write(hashlib.sha256(b'secret').digest() + b'\0\0' + frame(4, payload=b'v=2'))
    for sid in range(1, 129):
        writer.write(frame(1, sid) + (frame(2, sid, prefix) if prefix else b'') + frame(3, sid))
    await received.barrier(writer)
    await asyncio.sleep(0.1)
    assert not requests and not received.closed
    assert not any(c == 3 and s <= 128 for c, s, _ in received.values), 'FIN reply to closed preparation'
    writer.write(frame(1, 129) + frame(2, 129, target(backend_port) + REQUEST))
    await writer.drain()
    await until(lambda: received.payload(129) == BANNER and received.count(3, 129) == 1)
    await received.barrier(writer)
    result.update(passed=requests == [REQUEST] and not received.closed,
                  retired_streams=128, recovery_connections=len(requests), session_alive=not received.closed)


async def outbound_case(args, payload_before_fin, output, result, resources):
    sessions = []
    expected = bytes(range(251)) * 32 if payload_before_fin else b''

    async def server(reader, writer):
        session = {'frames': [], 'requests': {}, 'closed': False}
        sessions.append(session)
        auth = await reader.readexactly(34)
        assert auth[:32] == hashlib.sha256(b'secret').digest()
        await reader.readexactly(int.from_bytes(auth[32:], 'big'))
        while True:
            command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
            payload = await reader.readexactly(size)
            session['frames'].append((command, sid, payload))
            if command == 4:
                writer.write(frame(10, payload=b'v=2'))
            elif command == 1:
                session['requests'][sid] = bytearray()
                if sid != 2:
                    writer.write(frame(7, sid))
            elif command == 2:
                session['requests'][sid].extend(payload)
                if sid == 2 and not session['closed']:
                    session['closed'] = True
                    writer.write((frame(2, sid, expected) if expected else b'') + frame(3, sid))
                elif sid != 2 and session['requests'][sid] == target(443) + REQUEST:
                    writer.write(frame(2, sid, BANNER) + frame(3, sid))
            elif command == 8:
                writer.write(frame(9))
            await writer.drain()

    peer_port = await resources.listen(server, tls=True)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                       'settings': {'clients': [{'id': str(USER)}]}},
              {'protocol': 'anytls', 'settings': {'server': '127.0.0.1', 'server_port': peer_port,
               'password': 'secret', 'minIdleSession': 1}, 'streamSettings': tls_settings()})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    for number in range(3):
        reader, writer = await open_application(resources, port, False)
        data, eof, seconds = await observe_eof(reader)
        assert eof and data == (expected if number == 1 else BANNER)
        if number == 1:
            result['close_seconds'] = seconds
        await asyncio.sleep(0.1)
    assert len(sessions) == 1
    assert not any(c == 3 and s == 2 for c, s, _ in sessions[0]['frames']), 'FIN replied before SYNACK'
    result.update(passed=True, drained_bytes=len(expected), physical_connections=len(sessions),
                  stream_ids=list(sessions[0]['requests']))


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    magic = lambda name: b'\3' + bytes([len(name)]) + name + b'\0\0'
    cases = [('syn-only', b''), ('partial-address', b'\1\x7f'),
             ('uot1', magic(b'sp.udp-over-tcp.arpa')),
             ('uot2', magic(b'sp.v2.udp-over-tcp.arpa') + b'\1')]
    results = []
    for name, prefix in cases + [('before-synack', False), ('payload-before-synack', True)]:
        output = args.output / name
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'name': name, 'passed': False}
        try:
            probe = outbound_case if isinstance(prefix, bool) else inbound_case
            await asyncio.wait_for(probe(args, prefix, output, result, resources), 12)
        except Exception as error:
            result.update(passed=False, error=repr(error))
        finally:
            result['children_alive_before_cleanup'] = all(c.poll() is None for c in resources.children)
            await resources.close()
        result['peer_errors'] = resources.errors
        result['passed'] &= not resources.errors and result['children_alive_before_cleanup']
        results.append(result)
        (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
        print(json.dumps(result), flush=True)
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

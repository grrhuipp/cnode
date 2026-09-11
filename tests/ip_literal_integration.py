"""Verify complete literal consumption through the real VLESS -> Freedom chain."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct

from anytls_fin_integration import Resources, USER, REQUEST, BANNER, available_port, configure

CASES = [
    ('ipv4', b'127.0.0.1', True),
    ('mapped-v6', b'::ffff:127.0.0.1', True),
    ('mapped-v6-hex', b'0:0:0:0:0:ffff:7f00:1', True),
    ('embedded-port', b'127.0.0.1:9', False),
    ('embedded-nul', b'127.0.0.1\0ignored', False),
    ('mapped-nul', b'::ffff:127.0.0.1\0ignored', False),
    ('bracketed-v4', b'[127.0.0.1]', False),
    ('bracketed-mapped-v6', b'[::ffff:127.0.0.1]', False),
    ('trailing-space', b'127.0.0.1 ', False),
    ('invalid-scope', b'::ffff:127.0.0.1%invalid', False),
]


async def run(args, name, host, accepted):
    output = args.output / name
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    reached = []
    received = bytearray()
    closed = False
    error = None

    async def backend(reader, writer):
        reached.append(await reader.readexactly(len(REQUEST)))
        writer.write(BANNER)
        await writer.drain()

    try:
        target_port = await resources.listen(backend)
        port = available_port()
        configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                           'settings': {'clients': [{'id': str(USER)}]}},
                  {'protocol': 'freedom', 'settings': {}})
        resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
        reader, writer = await resources.connect(port)
        writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', target_port)
                     + b'\2' + bytes([len(host)]) + host + REQUEST)
        await writer.drain()
        async with asyncio.timeout(2):
            while chunk := await reader.read(65536):
                received.extend(chunk)
                if len(received) >= 2 + len(BANNER):
                    break
            else:
                closed = True
    except ConnectionError:
        closed = True
    except Exception as failure:
        error = repr(failure)
    finally:
        children_alive = bool(resources.children) and all(child.poll() is None for child in resources.children)
        await resources.close()
    passed = not error and not resources.errors and children_alive and (
        reached == [REQUEST] and received == b'\0\0' + BANNER if accepted
        else not reached and not received and closed)
    return {'case': name, 'host_hex': host.hex(), 'expected_accepted': accepted,
            'target_reached': len(reached), 'response_hex': received.hex(),
            'closed': closed, 'error': error, 'children_alive_before_cleanup': children_alive,
            'peer_errors': resources.errors, 'passed': passed}


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    args.output = args.output.resolve()
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for case in CASES:
        result = await run(args, *case)
        results.append(result)
        print(json.dumps(result), flush=True)
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps(
        {'binary_sha256': digest, 'cases': results}, indent=2), encoding='utf-8')
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))

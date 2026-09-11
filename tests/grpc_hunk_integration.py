"""Raw HTTP/2 peers exercise both production Hunk decoders over TCP and TLS."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import traceback

from anytls_fin_integration import Resources, REQUEST, available_port, configure, until
from grpc_substream_integration import Peer, READY, h2frame, headers, grpc, vless, varint
from grpc_eof_integration import grpc_transport, protocol_settings


LIMIT = 4 * 1024 * 1024
VALID = ('fragmented', 'unknown-fields', 'duplicate-last', 'unknown-group', 'maximum')
MALFORMED = ('trailing-key-zero', 'trailing-truncated-field', 'overflow-key', 'overflow-varint',
             'duplicate-empty', 'truncated-body', 'compressed')


async def receive_to_close(reader):
    data = bytearray()
    deadline = asyncio.get_running_loop().time() + 5
    while True:
        try:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return bytes(data), False, False
            chunk = await asyncio.wait_for(reader.read(65536), remaining)
        except TimeoutError:
            return bytes(data), False, False
        except ConnectionError:
            return bytes(data), True, True
        if not chunk:
            return bytes(data), True, False
        data.extend(chunk)


def encode(mode, payload):
    field = lambda data: b'\x0a' + varint(len(data)) + data
    if mode == 'unknown-fields':
        message = b'\x10\x96\x01\x19' + b'\0' * 8 + field(payload) + b'\x25' + b'\0' * 4
    elif mode == 'duplicate-last':
        message = field(b'wrong') + field(payload)
    elif mode == 'unknown-group':
        message = b'\x13\x1b\x20\x01\x1c\x14' + field(payload)
    elif mode == 'trailing-key-zero':
        message = field(payload) + b'\0'
    elif mode == 'trailing-truncated-field':
        message = field(payload) + b'\x1a\x04\0'
    elif mode == 'overflow-key':
        message = varint(((1 << 32) + 1) << 3 | 2) + varint(len(payload)) + payload
    elif mode == 'overflow-varint':
        message = b'\x10' + b'\xff' * 9 + b'\x02' + field(payload)
    elif mode == 'duplicate-empty':
        message = field(payload) + field(b'')
    elif mode in ('oversize-prefix', 'uint32-prefix'):
        size = LIMIT + 1 if mode == 'oversize-prefix' else 0xffffffff
        return b'\0' + size.to_bytes(4, 'big')
    else:
        message = field(payload)
    wire = bytes([int(mode == 'compressed')]) + len(message).to_bytes(4, 'big') + message
    return wire[:-1] if mode == 'truncated-body' else wire


async def send_data(writer, wire, fragmented=False, end=False):
    offset = 0
    for size in ([1, 1, 1, 1, 1, 1, 1, 2] if fragmented else []):
        if offset >= len(wire):
            break
        part = wire[offset:offset + size]
        offset += len(part)
        writer.write(h2frame(0, int(end and offset == len(wire)), 1, part))
        await writer.drain()
        await asyncio.sleep(0.01)
    while offset < len(wire):
        part = wire[offset:offset + 16384]
        offset += len(part)
        writer.write(h2frame(0, int(end and offset == len(wire)), 1, part))
        await writer.drain()


async def inbound(args, mode, tls, output, result, resources):
    requests = []
    body = REQUEST if mode != 'maximum' else b'z' * (LIMIT - 5 - len(vless(443, b'')))

    async def destination(reader, writer):
        data = await reader.readexactly(len(body) if not requests else len(REQUEST))
        requests.append(data)
        writer.write(READY)
        await writer.drain()

    target = await resources.listen(destination)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
        'settings': protocol_settings('vless'), 'streamSettings': grpc_transport(tls, True)},
        {'protocol': 'freedom', 'settings': {}})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    reader, writer = await resources.connect(port, tls=tls)
    writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4) + h2frame(1, 4, 1, headers(tls)))
    await writer.drain()
    peer = Peer(resources, reader, writer)
    wire = encode(mode, vless(target, body))
    result['wire_bytes'] = len(wire)
    await send_data(writer, wire, fragmented=mode == 'fragmented', end=True)
    await until(lambda: peer.closed or any(sid == 1 and (
                (mode in VALID and kind == 1 and flags & 1) or
                (mode not in VALID and kind == 3 and payload == b'\0\0\0\x08'))
                for kind, flags, sid, payload in peer.frames), 5)
    assert not peer.closed and not peer.error, f'physical connection lost: {peer.error}'
    result['first_target_requests'] = len(requests)
    result['first_response_hex'] = bytes(peer.messages.get(1, b'')).hex()
    if mode in VALID:
        assert requests == [body] and bytes(peer.messages.get(1, b'')) == b'\0\0' + READY
    else:
        assert not requests and not peer.messages.get(1), 'rejected message reached proxy protocol/target'
        resets = [payload.hex() for kind, _, sid, payload in peer.frames if kind == 3 and sid == 1]
        assert resets == ['00000008'], 'rejected application stream must end with exactly one CANCEL'
        result['first_stream_resets'] = resets
    await peer.open(3, target, REQUEST, tls, end=True)
    await peer.wait_message(3, b'\0\0' + READY)
    await peer.ping(b'hunk-ok!')
    assert requests[-1] == REQUEST
    result.update(passed=True, recovery=True, target_body_bytes=len(body) if mode in VALID else 0)


async def outbound(args, mode, tls, output, result, resources):
    responses = []
    body = READY if mode != 'maximum' else b'z' * (LIMIT - 5 - 2)

    async def server(reader, writer):
        index = len(responses)
        responses.append(index)
        assert await reader.readexactly(24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        peer = Peer(resources, reader, writer)
        writer.write(h2frame(4) + h2frame(1, 4, 1, b'\x88\0\x0ccontent-type\x10application/grpc'))
        await writer.drain()
        await peer.wait_message(1, vless(443, REQUEST))
        wire = encode(mode, b'\0\0' + body) if index == 0 else grpc(b'\0\0' + READY)
        if index == 0:
            result['wire_bytes'] = len(wire)
        await send_data(writer, wire, fragmented=index == 0 and mode == 'fragmented')
        writer.write(h2frame(1, 5, 1, b'\0\x0bgrpc-status\x010'))
        await writer.drain()
        await until(lambda: peer.closed, 5)
        result.setdefault('server_connections', []).append({'index': index, 'peer_error': peer.error})
        expected_reset = index == 0 and mode not in VALID and peer.error and peer.error.startswith('ConnectionResetError(')
        assert not peer.error or expected_reset, f'HTTP/2 observation: {peer.error}'

    target = await resources.listen(server, tls=tls)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
        'settings': protocol_settings('vless')},
        {'protocol': 'vless', 'settings': protocol_settings('vless', target),
         'streamSettings': grpc_transport(tls, False)})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    for index in (0, 1):
        reader, writer = await resources.connect(port)
        writer.write(vless(443, REQUEST))
        await writer.drain()
        data, eof, reset = await receive_to_close(reader)
        expected = b'\0\0' + (body if index == 0 else READY) if index or mode in VALID else b''
        if index == 0:
            result.update(first_response_bytes=len(data), first_response_sha256=hashlib.sha256(data).hexdigest(), eof=eof, reset=reset)
        assert eof and data == expected, f'response mismatch: got {len(data)} expected {len(expected)} eof={eof}'
        writer.close()
    result.update(passed=True, recovery=True, application_body_bytes=len(body) if mode in VALID else 0)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    modes = list(VALID + MALFORMED)
    if args.prefix_limits:
        modes += ['oversize-prefix', 'uint32-prefix']
    results = []
    for role, scenario in [('inbound', inbound), ('outbound', outbound)]:
        for tls in (False, True):
            for mode in modes:
                name = f'{role}-{"tls" if tls else "tcp"}-{mode}'
                if args.case and name != args.case:
                    continue
                output = args.output / name
                output.mkdir(parents=True, exist_ok=True)
                resources = Resources()
                result = {'case': name, 'passed': False}
                try:
                    await asyncio.wait_for(scenario(args, mode, tls, output, result, resources), 15)
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
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--output', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--case')
    parser.add_argument('--prefix-limits', action='store_true', help='Exercise huge declared lengths only against a binary with verified prefix bounds.')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

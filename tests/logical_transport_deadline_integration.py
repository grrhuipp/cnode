"""Consumer-visible split-transport deadline handoff and child cancellation tests."""
import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import socket
import time
import traceback

from anytls_fin_integration import Resources, USER, available_port, configure, until
from grpc_substream_integration import Peer, READY, ECHO, FLOOD, h2frame, vless, wait_for_backpressure
from http2_server_errors_integration import request_headers


def timeouts(output, handshake, limits=None):
    path = output / 'config.json'
    config = json.loads(path.read_text())
    config['timeouts'].update(handshake=handshake, write=30, connIdle=30)
    config['log']['loglevel'] = 'debug'
    if limits:
        config['limits'] = limits
    path.write_text(json.dumps(config), encoding='utf-8')


async def response(reader):
    header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 3)
    assert header.startswith(b'HTTP/1.1 200 '), header
    return header


async def packet(resources, port, session, sequence, payload):
    reader, writer = await resources.connect(port)
    writer.write((f'POST /fixture/{session}/{sequence} HTTP/1.1\r\nHost: localhost\r\n'
                  f'Content-Length: {len(payload)}\r\n\r\n').encode() + payload)
    await writer.drain()
    await response(reader)
    writer.close()
    await writer.wait_closed()


class Chunked:
    def __init__(self, reader):
        self.reader = reader
        self.pending = bytearray()

    async def exact(self, count):
        while len(self.pending) < count:
            line = await self.reader.readuntil(b'\r\n')
            size = int(line.strip(), 16)
            assert size, 'downlink terminated before expected proxy bytes'
            self.pending.extend(await self.reader.readexactly(size))
            assert await self.reader.readexactly(2) == b'\r\n'
        result = bytes(self.pending[:count])
        del self.pending[:count]
        return result


async def h1_case(args, mode, output, result, resources):
    result['destination_bytes'] = 0
    async def destination(reader, writer):
        while data := await reader.read(8192):
            result['destination_bytes'] += len(data)
            writer.write(data)
            await writer.drain()

    target = await resources.listen(destination)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
              'settings': {'clients': [{'id': str(USER)}]},
              'streamSettings': {'network': 'xhttp', 'security': 'none',
                                 'xhttpSettings': {'path': '/fixture', 'mode': mode}}},
              {'protocol': 'freedom', 'settings': {}})
    timeouts(output, 1)
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')

    async def down(session):
        reader, writer = await resources.connect(port)
        writer.write(f'GET /fixture/{session} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        await writer.drain()
        assert b'Transfer-Encoding: chunked'.lower() in (await response(reader)).lower()
        return reader, writer

    # An accepted transport with no complete proxy request must still expire.
    slow, _ = await down('slow')
    started = time.monotonic()
    assert await asyncio.wait_for(slow.read(), 3) in (b'', b'0\r\n\r\n')
    result['incomplete_proxy_timeout_seconds'] = time.monotonic() - started
    assert result['incomplete_proxy_timeout_seconds'] >= 0.5

    reader, _ = await down('active')
    body = Chunked(reader)
    started = time.monotonic()
    upload_writer = None
    prefixed_header = b''
    if mode == 'stream-up':
        upload_reader, upload_writer = await resources.connect(port)
        upload_writer.write(b'POST /fixture/active HTTP/1.1\r\nHost: localhost\r\n'
                            b'Transfer-Encoding: chunked\r\n\r\n')
        await upload_writer.drain()
        await response(upload_reader)

    async def upload(sequence, payload):
        if upload_writer is None:
            await packet(resources, port, 'active', sequence, payload)
        else:
            header = f'{len(payload):x}\r\n'.encode()
            if sequence == 1:
                header = header[len(prefixed_header):]
            upload_writer.write(header + payload + b'\r\n')
            await upload_writer.drain()

    await upload(0, vless(target, READY))
    if upload_writer is not None:
        # The first sniff read consumes this incomplete size line, then expires.
        # The next relay read must resume the same decoder rather than see EOF.
        prefixed_header = f'{len(ECHO):x}'.encode()[:1]
        upload_writer.write(prefixed_header)
        await upload_writer.drain()
    assert await asyncio.wait_for(body.exact(2 + len(READY)), 3) == b'\0\0' + READY
    result['echoed_packets'] = 0
    sequence = 1
    while time.monotonic() - started < 2.2:
        await asyncio.sleep(0.1)
        await upload(sequence, ECHO)
        assert await asyncio.wait_for(body.exact(len(ECHO)), 3) == ECHO
        result['echoed_packets'] += 1
        sequence += 1
    result.update(passed=True, active_seconds=time.monotonic() - started,
                  echoed_packets=sequence, incomplete_proxy_timed_out=True)


async def h2_case(args, output, result, resources):
    # RFC 7748 section 6.1 public test vector; these are not deployment keys.
    private = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
    public = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
    encode = lambda key: base64.urlsafe_b64encode(key).decode().rstrip('=')
    states = {}
    # Keep enough ciphertext to prove sustained physical-write backpressure,
    # without making the subsequent full-byte drain a throughput benchmark.
    flood_count = 256

    async def destination(reader, writer):
        tag = await reader.readexactly(1)
        state = {'go': asyncio.Event(), 'drained': False, 'closed': False, 'sent': 0, 'writer': writer}
        states[tag] = state
        writer.write(READY)
        await writer.drain()
        try:
            if tag == b'A':
                await state['go'].wait()
                writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
                for _ in range(flood_count):
                    writer.write(FLOOD)
                    await writer.drain()
                    state['sent'] += len(FLOOD)
                state['drained'] = True
            while data := await reader.read(8192):
                writer.write(data)
                await writer.drain()
        finally:
            state['closed'] = True
            writer.close()
            await writer.wait_closed()

    target = await resources.listen(destination)
    front, probe_port = available_port(), available_port()
    server_dir = output / 'server'
    server_dir.mkdir(exist_ok=True)
    configure(server_dir, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front,
              'settings': {'clients': [{'id': str(USER)}],
                           'decryption': 'mlkem768x25519plus.native.0s.' + encode(private)},
              'streamSettings': {'network': 'xhttp', 'security': 'none',
                                 'xhttpSettings': {'path': '/fixture', 'mode': 'packet-up'}}},
              {'protocol': 'freedom', 'settings': {}})
    inbounds = json.loads((server_dir / 'inbounds.json').read_text())
    inbounds.append({'tag': 'probe-in', 'protocol': 'vless', 'listen': '127.0.0.1',
                     'port': probe_port, 'outboundTag': 'fin-out',
                     'settings': {'clients': [{'id': str(USER)}]}})
    (server_dir / 'inbounds.json').write_text(json.dumps(inbounds))
    timeouts(server_dir, 8, {'maxConnections': 3, 'maxConnectionsPerIP': 3})
    resources.spawn([args.binary, '--config-dir', server_dir], server_dir / 'child.log')
    reader, writer = await resources.connect(front)
    writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4))
    await writer.drain()
    peer = Peer(resources, reader, writer, raw=True)

    async def down(sid):
        writer.write(h2frame(1, 5, sid, request_headers('xhttp', False, f'/fixture/s{sid}', 'GET')))
        await writer.drain()
        await until(lambda: peer.closed or any(t == 1 and stream == sid for t, _, stream, _ in peer.frames))
        assert not peer.closed

    # The real encrypted client uses TCP. This byte bridge only maps its bytes
    # onto XHTTP: it never implements or bypasses the product encryption handshake.
    next_sid = 1
    uploads = {}

    async def bridge(client_reader, client_writer):
        nonlocal next_sid
        sid = next_sid
        next_sid += 2
        uploads[sid] = 0

        async def downlink():
            while not peer.closed:
                pending = peer.messages.get(sid)
                if pending:
                    client_writer.write(bytes(pending))
                    pending.clear()
                    await client_writer.drain()
                if any(stream == sid and (t == 3 or (t in (0, 1) and flags & 1))
                       for t, flags, stream, _ in peer.frames):
                    break
                await asyncio.sleep(0.001)
            client_writer.close()

        task = asyncio.create_task(downlink())
        resources.tasks.add(task)
        try:
            sequence = 0
            while data := await client_reader.read(65536):
                await packet(resources, front, f's{sid}', sequence, data)
                sequence += 1
                uploads[sid] = sequence
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    bridge_port = await resources.listen(bridge)
    client_port = available_port()
    client_dir = output / 'client'
    client_dir.mkdir(exist_ok=True)
    configure(client_dir, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': client_port,
              'settings': {'clients': [{'id': str(USER)}]}},
              {'protocol': 'vless', 'settings': {'address': '127.0.0.1', 'port': bridge_port,
               'id': str(USER), 'encryption': 'mlkem768x25519plus.native.1rtt.' + encode(public)}})
    timeouts(client_dir, 20)
    resources.spawn([args.binary, '--config-dir', client_dir], client_dir / 'child.log')
    await down(1)
    survivor, survivor_writer = await resources.connect(client_port)
    survivor_writer.write(vless(target, b'A'))
    await survivor_writer.drain()
    assert await asyncio.wait_for(survivor.readexactly(2 + len(READY)), 5) == b'\0\0' + READY
    await down(3)
    opened_at = time.monotonic()
    writer.transport.pause_reading()
    states[b'A']['go'].set()
    buffered = await wait_for_backpressure(states[b'A'])
    result.update(target_backpressured=True, target_pending_bytes=buffered,
                  target_sent_before_timeout=states[b'A']['sent'],
                  backpressure_seconds=time.monotonic() - opened_at)
    victim, victim_writer = await resources.connect(client_port)
    victim_writer.write(vless(target, b'V'))
    await victim_writer.drain()
    await until(lambda: uploads.get(3, 0) > 0 or bool(resources.errors), 3)
    assert uploads.get(3, 0) > 0, resources.errors
    result['encrypted_hello_age_seconds'] = time.monotonic() - opened_at
    assert result['encrypted_hello_age_seconds'] < 7, 'fixture missed the logical handshake window'
    result['encrypted_hello_committed_while_sibling_blocked'] = True

    async def probe(tag, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            probe_reader, probe_writer = await resources.connect(probe_port)
            try:
                probe_writer.write(vless(target, tag))
                await probe_writer.drain()
                payload = await asyncio.wait_for(probe_reader.readexactly(2 + len(READY)), 0.5)
                assert payload == b'\0\0' + READY
                return probe_reader, probe_writer
            except (ConnectionError, asyncio.IncompleteReadError, TimeoutError):
                probe_writer.close()
                await asyncio.sleep(0.02)
        raise AssertionError('expired encrypted child retained its admission quota while sibling was blocked')

    # Q=max(1,active_children). With limit=3, a live sibling plus an expired
    # child must leave two admission slots, even before physical writes resume.
    first = await probe(b'P', 1)
    second = await probe(b'Q', 10)
    assert not states[b'A']['closed'] and not states[b'A']['drained']
    assert not peer.closed and not writer.transport.is_reading()
    assert b'V' not in states, 'expired encrypted handshake reached the destination'
    result.update(quota_recovered_before_resume=True, sibling_alive_at_expiry=True)
    for probe_reader, probe_writer in (first, second):
        probe_writer.write_eof()
        await probe_writer.drain()
        assert await asyncio.wait_for(probe_reader.read(), 2) == b''
        probe_writer.close()
        await probe_writer.wait_closed()
    writer.transport.resume_reading()
    remaining = flood_count * len(FLOOD)
    result['flood_remaining'] = remaining
    while remaining:
        data = await asyncio.wait_for(survivor.read(min(65536, remaining)), 8)
        assert data and data == b'A' * len(data), 'surviving encrypted stream lost flood data'
        remaining -= len(data)
        result['flood_remaining'] = remaining
    survivor_writer.write(ECHO)
    await survivor_writer.drain()
    assert await asyncio.wait_for(survivor.readexactly(len(ECHO)), 5) == ECHO
    await peer.ping(b'survived')
    await until(lambda: any(sid == 3 and (t == 3 or (t in (0, 1) and flags & 1))
                           for t, flags, sid, _ in peer.frames), 3)
    result.update(passed=not peer.error and not peer.closed, sibling_survived=True,
                  expired_child_terminated=True, encrypted_flood_bytes=flood_count * len(FLOOD))


async def websocket_close_case(args, output, result, resources):
    target_closed = asyncio.Event()

    async def destination(reader, writer):
        try:
            while data := await reader.read(8192):
                writer.write(data)
                await writer.drain()
        finally:
            target_closed.set()
            writer.close()
            await writer.wait_closed()

    target = await resources.listen(destination)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
              'settings': {'clients': [{'id': str(USER)}]},
              'streamSettings': {'network': 'ws', 'security': 'none',
                                 'wsSettings': {'path': '/fixture'}}},
              {'protocol': 'freedom', 'settings': {}})
    timeouts(output, 1)
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    upgrade = (b'GET /fixture HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n'
               b'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
               b'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
    if result['case'] == 'ws-upgrade-rejection':
        invalid = (
            upgrade.replace(b'GET ', b'POST ', 1),
            upgrade.replace(b'HTTP/1.1', b'HTTP/1.0', 1),
            upgrade.replace(b'Connection: Upgrade', b'Connection: keep-alive', 1),
            upgrade.replace(b'Version: 13', b'Version: 12', 1),
            upgrade.replace(b'dGhlIHNhbXBsZSBub25jZQ==', b'not-a-key', 1),
            upgrade.replace(b'dGhlIHNhbXBsZSBub25jZQ==', b'a' * 24, 1))
        for request in invalid:
            rejected_reader, rejected_writer = await resources.connect(port)
            rejected_writer.write(request)
            await rejected_writer.drain()
            try:
                response = await asyncio.wait_for(rejected_reader.read(), 3)
            except ConnectionResetError:
                response = b''
            assert not response, 'invalid WebSocket request reached HTTP upgrade'
        result['rejected_handshakes'] = len(invalid)
        upgrade = upgrade.replace(b'Connection: Upgrade', b'Connection: keep-alive, uPgRaDe', 1)
    reader, writer = await resources.connect(port)
    writer.write(upgrade)
    await writer.drain()
    header = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 3)
    assert header.startswith(b'HTTP/1.1 101 '), header

    def frame(opcode, payload):
        mask = b'loop'
        size = len(payload)
        if size < 126:
            length = bytes((0x80 | size,))
        elif size <= 65535:
            length = b'\xfe' + size.to_bytes(2, 'big')
        else:
            length = b'\xff' + size.to_bytes(8, 'big')
        return bytes((0x80 | opcode,)) + length + mask + bytes(
            byte ^ mask[index % 4] for index, byte in enumerate(payload))

    async def receive():
        header = await reader.readexactly(2)
        assert not header[1] & 0x80, 'server sent a masked WebSocket frame'
        size = header[1] & 127
        if size >= 126:
            size = int.from_bytes(await reader.readexactly(2 if size == 126 else 8), 'big')
        assert size <= 65536
        return header[0] & 15, await reader.readexactly(size)

    writer.write(frame(2, vless(target, READY)))
    await writer.drain()
    case = result['case']
    expected = (bytes(range(251)) * 2 if case == 'ws-extended-resume' else
                b'A' * 65536 if case == 'ws-large-extended-resume' else ECHO)
    continuation = frame(9, b'ping-owned') if case == 'ws-ping-resume' else frame(2, expected)
    prefix_size = {'ws-prefix-resume': 1, 'ws-mask-resume': 4,
                   'ws-extended-resume': 3, 'ws-large-extended-resume': 6,
                   'ws-payload-resume': 11, 'ws-ping-resume': 8}.get(case, 0)
    if prefix_size:
        writer.write(continuation[:prefix_size])
        await writer.drain()
    pending = bytearray()

    async def exact(count):
        while len(pending) < count:
            opcode, payload = await asyncio.wait_for(receive(), 3)
            assert opcode in (0, 2), 'control frame leaked into proxy bytes'
            pending.extend(payload)
        output = bytes(pending[:count])
        del pending[:count]
        return output

    assert await exact(2 + len(READY)) == b'\0\0' + READY
    early = b''
    if case == 'ws-payload-resume':
        early = await exact(prefix_size - 6)
        assert early == expected[:len(early)], 'partial data frame was withheld or corrupted'
    if prefix_size:
        writer.write(continuation[prefix_size:])
        await writer.drain()
        if case == 'ws-ping-resume':
            opcode, payload = await asyncio.wait_for(receive(), 3)
            assert opcode == 10 and payload == b'ping-owned'
            writer.write(frame(2, expected))
            await writer.drain()
        assert early + await exact(len(expected) - len(early)) == expected
    started = time.monotonic()
    writer.write(frame(8, b'\x03\xe8'))
    await writer.drain()
    opcode, payload = await asyncio.wait_for(receive(), 2)
    assert opcode == 8 and payload[:2] == b'\x03\xe8'
    assert await asyncio.wait_for(reader.read(), 2) == b''
    await asyncio.wait_for(target_closed.wait(), 2)
    result.update(passed=True, close_seconds=time.monotonic() - started,
                  target_closed_before_half_close_deadline=True)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for case in ('h1-packet-up', 'h1-stream-up', 'h2-encrypted-blocked', 'ws-full-close',
                 'ws-prefix-resume', 'ws-mask-resume', 'ws-extended-resume',
                 'ws-large-extended-resume', 'ws-payload-resume', 'ws-ping-resume',
                 'ws-upgrade-rejection'):
        if args.case and case != args.case:
            continue
        output = args.output / case
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': case, 'passed': False}
        try:
            if case.startswith('ws-'):
                scenario = websocket_close_case(args, output, result, resources)
            elif case.startswith('h2'):
                scenario = h2_case(args, output, result, resources)
            else:
                scenario = h1_case(args, case[3:], output, result, resources)
            await asyncio.wait_for(scenario, 45)
        except Exception as error:
            result.update(passed=False, error=repr(error), traceback=traceback.format_exc())
        finally:
            result['children_alive_before_cleanup'] = bool(resources.children) and all(
                child.poll() is None for child in resources.children)
            await resources.close()
        result['peer_errors'] = resources.errors
        result['passed'] &= result['children_alive_before_cleanup'] and not resources.errors
        results.append(result)
        print(json.dumps(result), flush=True)
    assert results, 'unknown case'
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps({'binary_sha256': digest, 'cases': results}, indent=2))
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--output', required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--case', choices=('h1-packet-up', 'h1-stream-up', 'h2-encrypted-blocked',
        'ws-full-close', 'ws-prefix-resume', 'ws-mask-resume', 'ws-extended-resume',
        'ws-large-extended-resume', 'ws-payload-resume', 'ws-ping-resume',
        'ws-upgrade-rejection'))
    raise SystemExit(asyncio.run(main(parser.parse_args())))

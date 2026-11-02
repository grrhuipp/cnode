"""HTTP/2 stream resets must preserve another gRPC stream on the same socket.

Uses uncompressed HPACK literals and raw frames so malformed shared writes are
observed directly, without a client library hiding frames on reset streams.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct
import time
import traceback

from anytls_fin_integration import Resources, USER, available_port, configure, tls_settings, until


READY = b'ready'
ECHO = b'other-stream-alive'
FLOOD = b'A' * 65536


def h2frame(kind, flags=0, sid=0, body=b''):
    return len(body).to_bytes(3, 'big') + bytes([kind, flags]) + struct.pack('!I', sid) + body


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result + bytes([value]))


def grpc(payload):
    body = b'\x0a' + varint(len(payload)) + payload
    return b'\0' + len(body).to_bytes(4, 'big') + body


def headers(tls, raw=False):
    values = [(':method', 'POST'), (':scheme', 'https' if tls else 'http'),
              (':authority', 'localhost'), (':path', '/fixture' if raw else '/fixture/Tun'),
              ('content-type', 'application/octet-stream' if raw else 'application/grpc'),
              ('te', 'trailers')]
    return b''.join(b'\0' + bytes([len(key)]) + key.encode() + bytes([len(value)]) + value.encode()
                    for key, value in values)


def vless(port, payload):
    return b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', port) + b'\1\x7f\0\0\1' + payload


class Peer:
    def __init__(self, resources, reader, writer, raw=False):
        self.reader, self.writer = reader, writer
        self.raw = raw
        self.frames = []
        self.messages = {}
        self.pending = {}
        self.closed = False
        self.error = None
        self.task = asyncio.create_task(self.read())
        resources.tasks.add(self.task)

    async def read(self):
        try:
            while True:
                header = await self.reader.readexactly(9)
                length = int.from_bytes(header[:3], 'big')
                kind, flags = header[3:5]
                sid = int.from_bytes(header[5:], 'big') & 0x7fffffff
                if length > 16384 or kind > 9:
                    raise AssertionError(f'malformed HTTP/2 frame header {header.hex()}')
                body = await self.reader.readexactly(length)
                self.frames.append((kind, flags, sid, body if kind != 0 else len(body)))
                if kind == 4 and not flags & 1:
                    self.writer.write(h2frame(4, 1))
                elif kind == 0 and self.raw:
                    self.messages.setdefault(sid, bytearray()).extend(body)
                elif kind == 0:
                    pending = self.pending.setdefault(sid, bytearray())
                    pending.extend(body)
                    while len(pending) >= 5:
                        size = int.from_bytes(pending[1:5], 'big')
                        assert pending[0] == 0 and size <= 1024 * 1024, 'invalid gRPC message header'
                        if len(pending) < size + 5:
                            break
                        message = pending[5:5 + size]
                        del pending[:5 + size]
                        assert message and message[0] == 10, 'invalid Hunk tag'
                        value, shift, offset = 0, 0, 1
                        while True:
                            part = message[offset]
                            offset += 1
                            value |= (part & 127) << shift
                            if part < 128:
                                break
                            shift += 7
                            assert shift < 35
                        assert len(message) - offset == value, 'invalid Hunk length'
                        self.messages.setdefault(sid, bytearray()).extend(message[offset:])
                await self.writer.drain()
        except asyncio.IncompleteReadError:
            pass
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.error = repr(error)
        finally:
            self.closed = True

    async def open(self, sid, target_port, tag, tls, end=False):
        self.writer.write(h2frame(1, 4, sid, headers(tls, self.raw)))
        payload = vless(target_port, tag)
        encoded = payload if self.raw else grpc(payload)
        for offset in range(0, len(encoded), 16384):
            last = offset + 16384 >= len(encoded)
            self.writer.write(h2frame(0, int(end and last), sid, encoded[offset:offset + 16384]))
        await self.writer.drain()

    async def wait_message(self, sid, value):
        await until(lambda: self.closed or bytes(self.messages.get(sid, b'')) == value, 5)
        assert bytes(self.messages.get(sid, b'')) == value, f'stream {sid} lost data: {self.error}'

    async def ping(self, token):
        self.writer.write(h2frame(6, 0, 0, token))
        await self.writer.drain()
        await until(lambda: self.closed or (6, 1, 0, token) in self.frames, 5)
        assert (6, 1, 0, token) in self.frames, f'connection lost PING: {self.error}'


async def wait_for_backpressure(state, timeout=10, quiet_period=0.3):
    # Loopback TCP buffers can absorb megabytes after the peer stops reading.
    # Observe sustained blocked progress instead of assuming they fill within a
    # fixed startup delay. A flood that drains or closes never meets this test.
    deadline = time.monotonic() + timeout
    stable_since = time.monotonic()
    previous = state['sent']
    while time.monotonic() < deadline:
        buffered = state['writer'].transport.get_write_buffer_size()
        if state['drained'] or state['closed']:
            break
        if state['sent'] != previous or buffered == 0:
            previous = state['sent']
            stable_since = time.monotonic()
        elif time.monotonic() - stable_since >= quiet_period:
            return buffered
        await asyncio.sleep(0.01)
    raise AssertionError('fixture did not produce sustained backpressure')


async def scenario(args, mode, tls, output, result, resources):
    states = {}

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
                for _ in range(1024):
                    writer.write(FLOOD)
                    await writer.drain()
                    state['sent'] += len(FLOOD)
                state['drained'] = True
            while payload := await reader.read(1024):
                writer.write(payload)
                await writer.drain()
        finally:
            state['closed'] = True

    target_port = await resources.listen(destination)
    front_port = available_port()
    transport = tls_settings(True) if tls else {'security': 'none'}
    transport.update(network='grpc', grpcSettings={'serviceName': 'fixture'})
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
              'settings': {'clients': [{'id': str(USER)}]}, 'streamSettings': transport},
              {'protocol': 'freedom', 'settings': {}})
    if mode in ('slow-handshake', 'quota-one'):
        config_path = output / 'config.json'
        config = json.loads(config_path.read_text())
        if mode == 'slow-handshake':
            config['timeouts']['handshake'] = 1
        else:
            config['limits'] = {'maxConnections': 1, 'maxConnectionsPerIP': 1}
        config_path.write_text(json.dumps(config), encoding='utf-8')
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    reader, writer = await resources.connect(front_port, tls=tls)
    writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4))
    await writer.drain()
    peer = Peer(resources, reader, writer)
    if mode == 'slow-handshake':
        writer.write(h2frame(1, 4, 1, headers(tls)) + h2frame(0, 0, 1, grpc(b'\0')))
        await writer.drain()
        await peer.open(3, target_port, b'S', tls)
        await peer.wait_message(3, b'\0\0' + READY)
        await until(lambda: peer.closed or any(sid == 1 and
                    (kind == 3 or (kind in (0, 1) and flags & 1))
                    for kind, flags, sid, _ in peer.frames), 4)
        assert not peer.closed, 'slow logical handshake cancelled the physical connection'
        writer.write(h2frame(0, 0, 3, grpc(ECHO)))
        await writer.drain()
        await peer.wait_message(3, b'\0\0' + READY + ECHO)
        await peer.open(5, target_port, b'N', tls)
        await peer.wait_message(5, b'\0\0' + READY)
        await peer.ping(b'deadline')
        result.update(passed=not peer.error, slow_handshake_terminated=True,
                      sibling_survived=True, recovered_stream=5)
        return
    if mode == 'quota-one':
        await peer.open(1, target_port, b'V', tls)
        await peer.wait_message(1, b'\0\0' + READY)
        await peer.open(3, target_port, b'S', tls)
        await until(lambda: peer.closed or any(sid == 3 and
                    (kind == 3 or (kind in (0, 1) and flags & 1))
                    for kind, flags, sid, _ in peer.frames), 3)
        assert not peer.closed and b'S' not in states, 'concurrent request bypassed quota=1'
        writer.write(h2frame(0, 0, 1, grpc(ECHO)))
        await writer.drain()
        await peer.wait_message(1, b'\0\0' + READY + ECHO)
        writer.write(h2frame(3, 0, 1, struct.pack('!I', 8)))
        await writer.drain()
        await until(lambda: states[b'V']['closed'], 3)
        await peer.ping(b'now-idle')
        # A demux with no active requests must retain its physical admission
        # slot. A second physical socket is refused before a TLS handshake.
        context = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        rejected_writer = None
        try:
            rejected_reader, rejected_writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', front_port, ssl=context), 3)
            resources.writers.add(rejected_writer)
            rejected_writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4))
            await rejected_writer.drain()
            assert await asyncio.wait_for(rejected_reader.read(1), 3) == b'', \
                'idle demux released its admission floor'
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            if rejected_writer is not None:
                rejected_writer.close()
        await peer.open(5, target_port, b'N', tls)
        await peer.wait_message(5, b'\0\0' + READY)
        assert not peer.error, peer.error
        writer.close()
        await until(lambda: peer.closed and states[b'N']['closed'], 3)
        recovered = None
        for attempt in range(20):
            fresh_reader, fresh_writer = await resources.connect(front_port, tls=tls)
            fresh_writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4))
            try:
                await fresh_writer.drain()
                candidate = Peer(resources, fresh_reader, fresh_writer)
                await until(lambda: candidate.closed or any(
                    kind == 4 and not flags & 1 for kind, flags, _, _ in candidate.frames), 3)
                if not candidate.closed:
                    recovered = candidate
                    break
            except ConnectionError:
                pass
            fresh_writer.close()
            await asyncio.sleep(0.01)
        assert recovered is not None, 'physical close did not restore admission quota'
        await recovered.open(1, target_port, b'R', tls)
        await recovered.wait_message(1, b'\0\0' + READY)
        await recovered.ping(b'quota-ok')
        result.update(passed=not recovered.error,
                      first_request_admitted=True, concurrent_request_rejected=True,
                      idle_admission_retained=True, same_connection_reused=True,
                      final_admission_recovered=True)
        return
    await peer.open(1, target_port, b'A' if mode == 'blocked-reset' else b'V', tls,
                    end=mode == 'half-close')
    await peer.open(3, target_port, b'S', tls)
    await peer.wait_message(1, b'\0\0' + READY)
    await peer.wait_message(3, b'\0\0' + READY)
    await peer.ping(b'prepared')
    if mode == 'blocked-reset':
        writer.transport.pause_reading()
        states[b'A']['go'].set()
        buffered = await wait_for_backpressure(states[b'A'])
        result.update(target_sent=states[b'A']['sent'], target_pending_bytes=buffered)
        result['target_backpressured'] = True
    if mode != 'half-close':
        writer.write(h2frame(3, 0, 1, struct.pack('!I', 8)) * 3)
        await writer.drain()
    if mode == 'blocked-reset':
        await asyncio.sleep(0.2)
        result['target_closed_before_resume'] = states[b'A']['closed']
        writer.transport.resume_reading()
    writer.write(h2frame(0, 0, 3, grpc(ECHO)))
    await writer.drain()
    await peer.wait_message(3, b'\0\0' + READY + ECHO)
    await peer.ping(b'survived')
    barrier_index = peer.frames.index((6, 1, 0, b'survived'))
    await peer.open(5, target_port, b'N', tls)
    await peer.wait_message(5, b'\0\0' + READY)
    await peer.ping(b'recovery')
    late = [(kind, flags, sid) for kind, flags, sid, _ in peer.frames[barrier_index + 1:] if sid == 1]
    if mode == 'half-close':
        try:
            await until(lambda: peer.closed or any(kind == 1 and flags & 1 and sid == 1
                        for kind, flags, sid, _ in peer.frames), 5)
        finally:
            result.update(target_closed=states[b'V']['closed'], victim_frames=[
                [kind, flags, sid, body if isinstance(body, int) else body.hex()]
                for kind, flags, sid, body in peer.frames if sid == 1], peer_frame_error=peer.error)
        assert any(kind == 1 and flags & 1 and sid == 1 for kind, flags, sid, _ in peer.frames), 'missing terminal trailers'
    else:
        assert not late, 'frames emitted on a reset stream after PING barrier'
    result.update(passed=not peer.closed and not peer.error, shared_connection_survived=True,
                  recovered_stream=5, survivor_bytes=len(peer.messages[3]), late_frames=late,
                  http2_frames=len(peer.frames), peer_frame_error=peer.error)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for tls in (False, True):
        for mode in ('idle-reset', 'blocked-reset', 'half-close', 'slow-handshake', 'quota-one'):
            output = args.output / (mode + ('-tls' if tls else '-tcp'))
            if args.case and output.name != args.case:
                continue
            output.mkdir(parents=True, exist_ok=True)
            resources = Resources()
            result = {'case': output.name, 'passed': False}
            try:
                await asyncio.wait_for(scenario(args, mode, tls, output, result, resources), 20)
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
    parser.add_argument('--case')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

"""Real VLESS -> cnode -> AnyTLS/TLS large-response and slow-consumer checks."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import time
import uuid

USER = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811')


def frame(command, sid, payload=b''):
    return struct.pack('!BIH', command, sid, len(payload)) + payload


class Peer:
    def __init__(self, payload):
        self.payload = payload
        self.connections = 0
        self.requests = 0
        self.closed = {}
        self.errors = []
        self.tasks = set()
        self.writers = set()
        self.heart_responses = 0

    async def send(self, writer, sid, payload):
        try:
            for start in range(0, len(payload), 16384):
                if len(payload) > 65536 and start // 16384 == (len(payload) // 2) // 16384:
                    writer.write(frame(8, 0))
                writer.write(frame(2, sid, payload[start:start + 16384]))
                await writer.drain()
            writer.write(frame(3, sid))
            await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        self.connections += 1
        connection = self.connections
        children = []
        requests = {}
        started = set()
        try:
            auth = await reader.readexactly(34)
            if auth[:32] != hashlib.sha256(b'secret').digest():
                raise AssertionError('authentication mismatch')
            await reader.readexactly(int.from_bytes(auth[32:], 'big'))
            writer.write(frame(10, 0, b'v=2'))
            await writer.drain()
            while True:
                command, sid, length = struct.unpack('!BIH', await reader.readexactly(7))
                payload = await reader.readexactly(length)
                if command == 1:
                    requests[sid] = bytearray()
                    writer.write(frame(7, sid))
                    await writer.drain()
                elif command == 2 and sid not in started:
                    data = requests[sid]
                    data.extend(payload)
                    if not data or data[0] == 3 and len(data) < 2:
                        continue
                    header = 7 if data[0] == 1 else 4 + data[1]
                    if len(data) < header:
                        continue
                    udp = data[0] == 3
                    expected = (b'\1\1\x7f\0\0\1\1\xbb\0\5' if udp else b'') + b'probe'
                    if len(data) < header + len(expected):
                        continue
                    assert bytes(data[header:]) == expected, 'application request framing mismatch'
                    started.add(sid)
                    self.requests += 1
                    children.append(asyncio.create_task(self.send(writer, sid, self.payload)))
                elif command == 8:
                    writer.write(frame(9, 0))
                    await writer.drain()
                elif command == 9:
                    self.heart_responses += 1
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            self.closed[connection] = time.monotonic()
            for child in children:
                child.cancel()
            outcomes = await asyncio.gather(*children, return_exceptions=True)
            self.errors.extend(repr(x) for x in outcomes if isinstance(x, Exception)
                               and not isinstance(x, (ConnectionError, ssl.SSLError)))
            self.writers.discard(writer)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (ConnectionError, TimeoutError):
                writer.transport.abort()
            self.tasks.discard(task)

    async def close(self):
        for writer in tuple(self.writers):
            writer.transport.abort()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def request(port, udp, action):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    started = time.monotonic()
    aborted = None
    output = bytearray()
    try:
        if action != 'fast':
            writer.transport.pause_reading()
        first = b'probe'
        writer.write(b'\0' + USER.bytes + b'\0' + bytes([2 if udp else 1])
                     + struct.pack('!H', 443) + b'\1\x7f\0\0\1'
                     + (struct.pack('!H', len(first)) if udp else b'') + first)
        await writer.drain()
        if action == 'cancel':
            await asyncio.sleep(0.4)
            aborted = time.monotonic()
            writer.transport.abort()
        else:
            if action != 'fast':
                await asyncio.sleep(1.4 if action == 'timeout' else 0.4)
                writer.transport.resume_reading()
            while data := await asyncio.wait_for(reader.read(131072), 15):
                output.extend(data)
        return bytes(output), started, aborted
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (ConnectionError, TimeoutError):
            writer.transport.abort()


async def run_case(binary, output, udp, action):
    output.mkdir(parents=True, exist_ok=True)
    pattern = bytes(range(251))
    if udp:
        payload = b''.join(struct.pack('!H', size) + (pattern * (size // 251 + 1))[:size]
                           for _ in range(128) for size in (9000, 19999))
    else:
        size = 2 * 1024 * 1024 if action == 'fast' else 8 * 1024 * 1024
        payload = (pattern * (size // 251 + 1))[:size]
    peer = Peer(payload)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    fixtures = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
    tls.load_cert_chain(fixtures / 'cert.pem', fixtures / 'key.pem')
    server = await asyncio.start_server(peer.handle, '127.0.0.1', 0, ssl=tls)
    peer_port = server.sockets[0].getsockname()[1]
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        inbound_port = reserved.getsockname()[1]
    configs = {
        'config.json': {'workers': 1, 'log': {'enable': False, 'logDir': (output / 'logs').as_posix()},
                        'timeouts': {'handshake': 5, 'connIdle': 1 if action == 'timeout' else 10, 'write': 10}},
        'inbounds.json': [{'tag': 'pressure-in', 'protocol': 'vless', 'listen': '127.0.0.1',
                          'port': inbound_port,
                          'settings': {'clients': [{'id': str(USER)}]}}],
        'outbounds.json': [{'tag': 'pressure-out', 'protocol': 'anytls',
                           'settings': {'server': '127.0.0.1', 'server_port': peer_port, 'password': 'secret',
                                        'idleSessionCheckInterval': 1, 'idleSessionTimeout': 30, 'minIdleSession': 1},
                           'streamSettings': {'network': 'tcp', 'security': 'tls',
                                              'tlsSettings': {'serverName': 'localhost', 'allowInsecure': True}}}],
        'routing.json': {'rules': [{'type': 'field', 'inboundTag': ['pressure-in'], 'outboundTag': 'pressure-out'}]},
    }
    for name, config in configs.items():
        (output / name).write_text(json.dumps(config), encoding='utf-8')
    result = {'udp': udp, 'action': action, 'expected_bytes': len(payload),
              'expected_sha256': hashlib.sha256(payload).hexdigest()}
    with (output / 'child.log').open('w', encoding='utf-8') as logfile:
        child = subprocess.Popen([str(binary), '--config-dir', str(output)], stdout=logfile,
                                 stderr=subprocess.STDOUT,
                                 creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        try:
            deadline = time.monotonic() + 8
            while 'server started' not in (output / 'child.log').read_text(encoding='utf-8', errors='replace'):
                if child.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError('cnode did not start')
                await asyncio.sleep(0.05)
            received, started, aborted = await asyncio.wait_for(request(inbound_port, udp, action), 20)
            result['received_bytes'] = max(0, len(received) - 2)
            result['received_sha256'] = hashlib.sha256(received[2:]).hexdigest()
            if action in ('cancel', 'timeout'):
                deadline = time.monotonic() + 3
                while 1 not in peer.closed and time.monotonic() < deadline:
                    await asyncio.sleep(0.02)
                closed = peer.closed.get(1)
                result['closed_seconds'] = None if closed is None else round(closed - started, 3)
                if action == 'cancel':
                    valid = closed is not None and aborted <= closed < aborted + 3
                else:
                    valid = closed is not None and 0.7 <= closed - started < 2 and len(received) < len(payload)
            else:
                valid = received == b'\0\0' + payload
                valid &= peer.heart_responses == 1
            if udp and action in ('fast', 'pause'):
                lengths = []
                remaining = received[2:]
                while len(remaining) >= 2:
                    length = int.from_bytes(remaining[:2], 'big')
                    if len(remaining) < length + 2:
                        break
                    lengths.append(length)
                    remaining = remaining[2 + length:]
                result['datagrams'] = len(lengths)
                valid &= not remaining and lengths == [9000, 19999] * 128
            peer.payload = b'recovery-probe'
            recovery, _, _ = await asyncio.wait_for(request(inbound_port, False, 'fast'), 10)
            result['recovery'] = recovery == b'\0\0' + peer.payload
            result['connections'] = peer.connections
            result['heart_responses'] = peer.heart_responses
            result['peer_errors'] = peer.errors
            result['passed'] = (valid and result['recovery'] and not peer.errors
                                and peer.connections == (2 if action in ('cancel', 'timeout') else 1))
        except Exception as error:
            result['error'] = repr(error)
            result['peer_errors'] = peer.errors
            result['passed'] = False
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            server.close()
            await server.wait_closed()
            await peer.close()
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    cases = [(False, 'fast'), (False, 'pause'), (True, 'fast'), (True, 'pause'),
             (False, 'cancel'), (False, 'timeout')]
    if args.baseline:
        cases = cases[:2]
    results = []
    for udp, action in cases:
        name = ('udp-' if udp else 'tcp-') + action
        results.append(await run_case(args.binary.resolve(), args.output.resolve() / name, udp, action))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--baseline', action='store_true')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

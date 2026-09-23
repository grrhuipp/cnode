"""Compare AnyTLS stream closure with pinned, unmodified anytls-go binaries.

Build cmd/client and cmd/server at REFERENCE_COMMIT outside the source tree.
All peers, ports, credentials and certificates below belong to this loopback test.
FIN expectations come from the published protocol, not cnode's relay behavior.
"""
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
import traceback
import uuid

REFERENCE_COMMIT = 'fd6167acd6d73b9fa3e607659951847fbc9e6c50'
USER = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811')
REQUEST = b'request!'
BANNER = b'accepted'
LATE = b'forbidden-after-fin'
RECOVERY = b'recovery'
CERTIFICATES = Path(__file__).resolve().parent / 'fixtures/anytls-pool'


def frame(command, sid=0, payload=b''):
    return struct.pack('!BIH', command, sid, len(payload)) + payload


def available_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def target(port):
    return b'\1\x7f\0\0\1' + struct.pack('!H', port)


async def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError('observation deadline')
        await asyncio.sleep(0.01)


class Resources:
    """Join every accepted handler/reader before returning a case result."""
    def __init__(self):
        self.tasks = set()
        self.writers = set()
        self.servers = []
        self.children = []
        self.files = []
        self.errors = []

    async def listen(self, handler, tls=False):
        async def owned(reader, writer):
            task = asyncio.current_task()
            self.tasks.add(task)
            self.writers.add(writer)
            try:
                await handler(reader, writer)
            except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
                pass
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self.errors.append(repr(error))
            finally:
                writer.close()
                self.writers.discard(writer)
                self.tasks.discard(task)
        context = None
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(CERTIFICATES / 'cert.pem', CERTIFICATES / 'key.pem')
        server = await asyncio.start_server(owned, '127.0.0.1', 0, ssl=context)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    def spawn(self, command, log):
        file = log.open('w', encoding='utf-8')
        self.files.append(file)
        child = subprocess.Popen([str(x) for x in command], stdout=file, stderr=subprocess.STDOUT,
                                 creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        self.children.append(child)
        return child

    async def connect(self, port, tls=False):
        context = None
        if tls:
            # The reference executable generates a fresh self-signed test certificate.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        deadline = time.monotonic() + 8
        while True:
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', port, ssl=context)
                self.writers.add(writer)
                return reader, writer
            except OSError:
                if time.monotonic() >= deadline or any(c.poll() is not None for c in self.children):
                    raise
                await asyncio.sleep(0.02)

    async def close(self):
        try:
            async with asyncio.timeout(5):
                for server in self.servers:
                    server.close()
                for writer in tuple(self.writers):
                    writer.transport.abort()
                tasks = tuple(self.tasks)
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.gather(*(s.wait_closed() for s in self.servers))
        except TimeoutError:
            self.errors.append('fixture cleanup exceeded five seconds')
        finally:
            # A failed async cleanup must never leave a product child running.
            for child in self.children:
                if child.poll() is None:
                    child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                    self.errors.append('fixture child required forced termination')
            for file in self.files:
                file.close()


class Frames:
    def __init__(self, resources, reader):
        self.values = []
        self.closed = False
        self.task = asyncio.create_task(self.read(reader))
        resources.tasks.add(self.task)

    async def read(self, reader):
        try:
            while True:
                command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
                self.values.append((command, sid, await reader.readexactly(size)))
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            self.closed = True

    def count(self, command, sid=None):
        return sum(c == command and (sid is None or s == sid) for c, s, _ in self.values)

    def payload(self, sid):
        return b''.join(p for c, s, p in self.values if c == 2 and s == sid)

    async def barrier(self, writer):
        before = self.count(9)
        writer.write(frame(8))
        await writer.drain()
        await until(lambda: self.count(9) > before)


def configure(output, inbound, outbound):
    values = {
        'config.json': {'workers': 1, 'timeouts': {'handshake': 5, 'connIdle': 15,
                        'write': 5, 'uplinkOnly': 10, 'downlinkOnly': 10},
                        'log': {'enable': False, 'logDir': (output / 'logs').as_posix()}},
        'inbounds.json': [dict(inbound, tag='fin-in')],
        'outbounds.json': [dict(outbound, tag='fin-out')],
        'routing.json': {'rules': [{'type': 'field', 'inboundTag': ['fin-in'], 'outboundTag': 'fin-out'}]},
    }
    for name, value in values.items():
        (output / name).write_text(json.dumps(value), encoding='utf-8')


def tls_settings(server=False):
    settings = {'certificates': [{'certificateFile': (CERTIFICATES / 'cert.pem').as_posix(),
                                  'keyFile': (CERTIFICATES / 'key.pem').as_posix()}]} if server else {
                                      'serverName': 'localhost', 'allowInsecure': True}
    return {'network': 'tcp', 'security': 'tls', 'tlsSettings': settings}


async def observe_eof(reader, timeout=1):
    data = bytearray()
    start = time.monotonic()
    eof = False
    try:
        async with asyncio.timeout(timeout):
            while chunk := await reader.read(65536):
                data.extend(chunk)
            eof = True
    except TimeoutError:
        pass
    return bytes(data), eof, round(time.monotonic() - start, 3)


async def server_case(args, implementation, mode, output, resources):
    release = asyncio.Event()
    requests = []
    late_target = bytearray()
    target_eof = False

    async def destination(reader, writer):
        nonlocal target_eof
        request = await reader.readexactly(len(REQUEST))
        requests.append(request)
        if len(requests) > 1:
            writer.write(RECOVERY)
            await writer.drain()
            return
        writer.write(BANNER)
        await writer.drain()
        await release.wait()
        writer.write(LATE)
        await writer.drain()
        writer.write_eof()
        while data := await reader.read(65536):
            late_target.extend(data)
        target_eof = True

    destination_port = await resources.listen(destination)
    port = available_port()
    if implementation == 'reference':
        resources.spawn([args.reference_server, '-l', f'127.0.0.1:{port}', '-p', 'secret'], output / 'child.log')
    else:
        configure(output, {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': port,
                           'settings': {'clients': [{'password': 'secret'}]},
                           'streamSettings': tls_settings(True)}, {'protocol': 'freedom', 'settings': {}})
        resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    reader, writer = await resources.connect(port, tls=True)
    received = Frames(resources, reader)
    writer.write(hashlib.sha256(b'secret').digest() + b'\0\0' + frame(4, payload=b'v=2')
                 + frame(1, 1) + frame(2, 1, target(destination_port) + REQUEST))
    await writer.drain()
    await until(lambda: received.payload(1) == BANNER)
    if mode == 'remote-fin':
        writer.write(frame(3, 1))
        await received.barrier(writer)  # FIN has passed the session parser before the late response.
    release.set()
    await asyncio.sleep(0.35)
    await received.barrier(writer)
    if mode == 'local-eof':
        await until(lambda: received.count(3, 1) > 0)
        writer.write(frame(2, 1, LATE))
        await received.barrier(writer)
        try:
            await until(lambda: target_eof or late_target, timeout=1)
        except TimeoutError:
            pass
    response = received.payload(1)
    fins = received.count(3, 1)
    first_passed = response == (BANNER if mode == 'remote-fin' else BANNER + LATE)
    first_passed &= fins == (0 if mode == 'remote-fin' else 1)
    first_passed &= not late_target
    if mode == 'local-eof':
        first_passed &= target_eof
    # The same TLS session must still accept a different logical stream.
    writer.write(frame(1, 3) + frame(2, 3, target(destination_port) + REQUEST))
    await writer.drain()
    try:
        await until(lambda: received.count(3, 3) != 0, timeout=1)
    except TimeoutError:
        pass
    recovery = received.payload(3) == RECOVERY and received.count(3, 3) == 1 and not received.closed
    return {'passed': bool(first_passed and recovery), 'received_hex': response.hex(),
            'fin_replies': fins, 'recovery': recovery, 'session_closed': received.closed,
            'target_requests': len(requests), 'late_target_bytes': len(late_target),
            'target_eof': target_eof}


class ControlledServer:
    def __init__(self):
        self.sessions = []
        self.requests = 0

    async def handle(self, reader, writer):
        auth = await reader.readexactly(34)
        assert auth[:32] == hashlib.sha256(b'secret').digest()
        await reader.readexactly(int.from_bytes(auth[32:], 'big'))
        session = {'writer': writer, 'frames': [], 'streams': {}, 'closed': False}
        self.sessions.append(session)
        writer.write(frame(10, payload=b'v=2'))
        await writer.drain()
        try:
            while True:
                command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
                payload = await reader.readexactly(size)
                session['frames'].append((command, sid, payload))
                if command == 1:
                    session['streams'][sid] = bytearray()
                    writer.write(frame(7, sid))
                elif command == 2:
                    data = session['streams'][sid]
                    previous = len(data)
                    data.extend(payload)
                    if previous < 7 + len(REQUEST) <= len(data):
                        assert bytes(data[:7]) == target(443)
                        assert bytes(data[7:7 + len(REQUEST)]) == REQUEST
                        self.requests += 1
                        writer.write(frame(2, sid, BANNER if self.requests == 1 else RECOVERY))
                        if self.requests > 1:
                            writer.write(frame(3, sid))
                elif command == 8:
                    writer.write(frame(9))
                await writer.drain()
        finally:
            session['closed'] = True

    async def barrier(self, session):
        before = sum(c == 9 for c, _, _ in session['frames'])
        session['writer'].write(frame(8))
        await session['writer'].drain()
        await until(lambda: sum(c == 9 for c, _, _ in session['frames']) > before)


async def open_application(resources, port, reference):
    reader, writer = await resources.connect(port)
    if reference:
        writer.write(b'\5\1\0')
        await writer.drain()
        assert await reader.readexactly(2) == b'\5\0'
        writer.write(b'\5\1\0' + target(443))
        await writer.drain()
        reply = await reader.readexactly(4)
        assert reply[:2] == b'\5\0'
        await reader.readexactly({1: 6, 4: 18}[reply[3]])
        writer.write(REQUEST)
    else:
        writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', 443) + b'\1\x7f\0\0\1' + REQUEST)
    await writer.drain()
    if not reference:
        assert await reader.readexactly(2) == b'\0\0'
    return reader, writer


async def client_case(args, implementation, mode, output, resources):
    peer = ControlledServer()
    peer_port = await resources.listen(peer.handle, tls=True)
    port = available_port()
    reference = implementation == 'reference'
    if reference:
        resources.spawn([args.reference_client, '-l', f'127.0.0.1:{port}', '-s', f'127.0.0.1:{peer_port}',
                         '-p', 'secret', '-m', '1'], output / 'child.log')
    else:
        configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                           'settings': {'clients': [{'id': str(USER)}]}},
                  {'protocol': 'anytls', 'settings': {'server': '127.0.0.1', 'server_port': peer_port,
                   'password': 'secret', 'minIdleSession': 1, 'idleSessionTimeout': 30,
                   'idleSessionCheckInterval': 1}, 'streamSettings': tls_settings()})
        resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    reader, writer = await open_application(resources, port, reference)
    assert await reader.readexactly(len(BANNER)) == BANNER
    session = peer.sessions[0]
    sid = next(iter(session['streams']))
    if mode == 'remote-fin':
        # Data preceding FIN must survive a clean close with the upload still open.
        expected = (bytes(range(251)) * 1045)[:256 * 1024]
        for offset in range(0, len(expected), 16384):
            session['writer'].write(frame(2, sid, expected[offset:offset + 16384]))
        session['writer'].write(frame(3, sid))
        await session['writer'].drain()
        observation = asyncio.create_task(observe_eof(reader))
        resources.tasks.add(observation)
        await peer.barrier(session)
        # Observe delivery and EOF with the upload still open before attempting
        # a post-close write. On Windows that write can abort this same local
        # socket's pending read with 10053, even after all bytes were delivered.
        data, eof, seconds = await observation
        try:
            writer.write(LATE)
            await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
    else:
        expected = b''
        writer.write_eof()
        await until(lambda: any(c == 3 and s == sid for c, s, _ in session['frames']))
        # A closed ID cannot be reopened by a peer's subsequent PSH.
        session['writer'].write(frame(2, sid, LATE))
        await session['writer'].drain()
        observation = asyncio.create_task(observe_eof(reader))
        resources.tasks.add(observation)
        await peer.barrier(session)
        data, eof, seconds = await observation
    await peer.barrier(session)
    fins = sum(c == 3 and s == sid for c, s, _ in session['frames'])
    late_upload = bytes(session['streams'][sid][7 + len(REQUEST):])
    valid = data == expected and eof and not late_upload and fins == (0 if mode == 'remote-fin' else 1)
    writer.close()
    recovery_reader, recovery_writer = await open_application(resources, port, reference)
    recovery_payload = await recovery_reader.readexactly(len(RECOVERY))
    recovery_writer.close()
    recovery = recovery_payload == RECOVERY and len(peer.sessions) == 1
    return {'passed': bool(valid and recovery), 'received_bytes': len(data), 'expected_bytes': len(expected),
            'received_sha256': hashlib.sha256(data).hexdigest(),
            'expected_sha256': hashlib.sha256(expected).hexdigest(), 'eof': eof, 'observe_seconds': seconds,
            'fin_replies': fins, 'late_upload_bytes': len(late_upload), 'recovery': recovery,
            'physical_sessions': len(peer.sessions)}


async def main(args):
    args.output.mkdir(parents=True, exist_ok=True)
    binaries = {name: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                for name, path in [('cnode', args.binary), ('reference_client', args.reference_client),
                                   ('reference_server', args.reference_server)]}
    for kind, path in [('client', args.reference_client), ('server', args.reference_server)]:
        metadata = subprocess.run([str(args.go), 'version', '-m', str(path)], check=True,
                                  capture_output=True, text=True).stdout
        assert f'vcs.revision={REFERENCE_COMMIT}' in metadata, 'unverified reference revision'
        assert 'vcs.modified=false' in metadata, 'reference must be unmodified'
        assert f'path\tanytls/cmd/{kind}' in metadata, 'wrong reference executable'
        (args.output / f'reference-{kind}-build.txt').write_text(metadata, encoding='utf-8')
    results = []
    for side, probe in (('server', server_case), ('client', client_case)):
        for mode in ('remote-fin', 'local-eof'):
            for implementation in ('reference', 'cnode'):
                name = f'{side}-{mode}-{implementation}'
                output = args.output / name
                output.mkdir(parents=True, exist_ok=True)
                resources = Resources()
                result = {'name': name, 'passed': False}
                try:
                    result.update(await asyncio.wait_for(probe(args, implementation, mode, output, resources), 15))
                except Exception as error:
                    result['error'] = repr(error)
                    result['traceback'] = traceback.format_exc()
                finally:
                    result['children_alive_before_cleanup'] = all(c.poll() is None for c in resources.children)
                    await resources.close()
                result['peer_errors'] = resources.errors
                result['passed'] &= not resources.errors and result['children_alive_before_cleanup']
                (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
                results.append(result)
                print(json.dumps(result), flush=True)
    for value in binaries.values():
        assert hashlib.sha256(Path(value['path']).read_bytes()).hexdigest() == value['sha256'], 'binary changed during run'
    report = {'reference_commit': REFERENCE_COMMIT, 'binaries': binaries, 'cases': results}
    (args.output / 'results.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--reference-server', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--reference-client', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--go', default='go')
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

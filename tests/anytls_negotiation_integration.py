"""Loopback TLS checks of both sides of AnyTLS session negotiation."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import time
import uuid

from anytls_identity_integration import IdentityFixture, until
from anytls_pool_integration import USER_ID, REPLY, frame, request
from substream_cancellation_integration import USER, available_port

CERTS = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
INBOUND_CASES = {
    'v1': (b'v=1', False, None), 'v2': (b'v=2', True, None),
    'future': (b'v=3', True, None), 'maximum': (b'v=4294967295', True, None),
    'missing-version': (b'client=test', False, None),
    'fake-version': (b'client=has-v=2\nnot-v=2', False, None),
    'crlf': (b'v=2\r\nclient=test\r\n', True, None),
    'trailing': (b'v=2garbage', None, None), 'overflow': (b'v=4294967296', None, None),
    'duplicate-key': (b'v=1\nv=2', None, None), 'zero': (b'v=0', None, None),
    'duplicate-frame': (b'v=2', True, frame(4, 0, b'v=1')),
    'wrong-sid': (b'v=2', None, 'wrong-sid'),
    'v1-heartbeat': (b'v=1', False, frame(8, 0)),
    'wrong-direction': (b'v=2', True, frame(10, 0, b'v=2')),
}
OUTBOUND_CASES = {
    'no-settings': (None, False, False), 'v1': (b'v=1', False, False),
    'v2': (b'v=2', True, False), 'future': (b'v=3', True, False),
    'maximum': (b'v=4294967295', True, False),
    'fake-version': (b'note=v=2\nv=1', False, False),
    'trailing': (b'v=2garbage', False, True), 'overflow': (b'v=4294967296', False, True),
    'duplicate-key': (b'v=1\nv=2', False, True),
    'duplicate-frame': (b'v=2', True, True),
    'wrong-sid': (b'v=2', False, True), 'v1-heartbeat': (b'v=1', False, True),
}


async def connect_node(child, port, context=None):
    deadline = time.monotonic() + 8
    while True:
        try:
            return await asyncio.open_connection('127.0.0.1', port, ssl=context)
        except OSError:
            assert child.poll() is None and time.monotonic() < deadline, 'node did not accept'
            await asyncio.sleep(0.02)


def stop_child(child):
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=3)


async def inbound_case(binary, output, mode):
    output.mkdir(parents=True, exist_ok=True)
    settings, v2, extra = INBOUND_CASES[mode]
    fixture = IdentityFixture(available_port())
    panel = await asyncio.start_server(fixture.panel, '127.0.0.1', 0)
    peer = await asyncio.start_server(fixture.peer, '127.0.0.1', 0)
    config = {'workers': 1, 'log': {'enable': False, 'logDir': str(output / 'logs')},
              'panels': [{'Name': 'negotiation-test', 'Type': 'V2board',
                          'APIHost': f'http://127.0.0.1:{panel.sockets[0].getsockname()[1]}',
                          'Key': 'local-test-key', 'NodeIDs': [1], 'NodeType': 'anytls',
                          'ListenIP': '127.0.0.1', 'TLSEnable': True,
                          'TLSCert': str(CERTS / 'cert.pem'), 'TLSKey': str(CERTS / 'key.pem')}]}
    (output / 'config.json').write_text(json.dumps(config), encoding='utf-8')
    result = {'direction': 'inbound', 'mode': mode, 'passed': False}
    client = None
    reader_task = None
    responses = []
    closed = asyncio.Event()
    with (output / 'child.log').open('w', encoding='utf-8') as logfile:
        child = subprocess.Popen([str(binary), '--config-dir', str(output)], stdout=logfile, stderr=subprocess.STDOUT)
        try:
            await until(lambda: fixture.users_requested or child.poll() is not None, 8)
            tls = ssl.create_default_context(cafile=str(CERTS / 'cert.pem'))
            tls.check_hostname = False
            reader, client = await connect_node(child, fixture.node_port, tls)
            async def read_frames():
                try:
                    while True:
                        command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
                        responses.append((command, sid, await reader.readexactly(size)))
                except (asyncio.IncompleteReadError, ConnectionError):
                    pass
                finally:
                    closed.set()
            reader_task = asyncio.create_task(read_frames())
            target = b'\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', peer.sockets[0].getsockname()[1])
            data = b'negotiated-user-payload'
            client.write(hashlib.sha256(str(USER).encode()).digest() + b'\0\0'
                         + frame(4, 7 if extra == 'wrong-sid' else 0, settings)
                         + frame(1, 1) + frame(2, 1, target + data))
            await client.drain()
            if v2 is None:
                await asyncio.wait_for(closed.wait(), 2)
                assert any(c == 5 and sid == 0 and p for c, sid, p in responses), 'invalid settings missing Alert'
                assert not fixture.connections, 'invalid negotiation opened a target'
            else:
                await until(lambda: b''.join(p for c, sid, p in responses if c == 2 and sid == 1) == data)
                assert any(c == 10 for c, _, _ in responses) == v2, 'ServerSettings feature gate mismatch'
                assert any(c == 7 and sid == 1 for c, sid, _ in responses) == v2, 'SYNACK feature gate mismatch'
                if extra:
                    client.write(extra)
                    await client.drain()
                    await asyncio.wait_for(closed.wait(), 2)
                    assert any(c == 5 for c, _, _ in responses), 'invalid state transition missing Alert'
                    assert len(fixture.connections) == 1
                else:
                    client.write(frame(1, 2) + frame(2, 2, target + data))
                    if v2:
                        client.write(frame(8, 0))
                    await client.drain()
                    await until(lambda: b''.join(p for c, sid, p in responses if c == 2 and sid == 2) == data)
                    if v2:
                        await until(lambda: any(c == 9 for c, _, _ in responses))
                    assert not closed.is_set() and len(fixture.connections) == 2
                    assert sum(c == 7 for c, _, _ in responses) == (2 if v2 else 0)
                    assert not any(c == 5 for c, _, _ in responses)
            result.update(passed=True, target_connections=len(fixture.connections), session_closed=closed.is_set())
        except Exception as error:
            result['error'] = repr(error)
        finally:
            result['controls'] = [[c, sid] for c, sid, _ in responses if c != 2]
            if reader_task:
                reader_task.cancel()
                await asyncio.gather(reader_task, return_exceptions=True)
            if client:
                client.close()
            stop_child(child)
            panel.close()
            peer.close()
            await panel.wait_closed()
            await peer.wait_closed()
            await fixture.close()
            result['peer_errors'] = fixture.errors
            if fixture.errors:
                result['passed'] = False
    return result


class ServerPeer:
    def __init__(self, mode):
        self.mode = mode
        self.settings, self.v2, self.invalid = OUTBOUND_CASES[mode]
        self.tasks = set()
        self.writers = set()
        self.errors = []
        self.closed = asyncio.Event()
        self.connections = 0
        self.streams = []
        self.client_settings = []
        self.heart_responses = 0

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        self.connections += 1
        requests = {}
        answered = set()
        try:
            auth = await reader.readexactly(34)
            assert auth[:32] == hashlib.sha256(b'secret').digest()
            await reader.readexactly(int.from_bytes(auth[32:34], 'big'))
            while True:
                command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
                payload = await reader.readexactly(size)
                if command == 4:
                    self.client_settings.append(payload.decode())
                    if self.settings is not None:
                        writer.write(frame(10, 5 if self.mode == 'wrong-sid' else 0, self.settings))
                    if self.mode == 'v1-heartbeat':
                        writer.write(frame(8, 0))
                elif command == 1:
                    requests[sid] = bytearray()
                    self.streams.append(sid)
                    if self.mode == 'duplicate-frame' and sid >= 2:
                        writer.write(frame(10, 0, b'v=1'))
                    elif self.v2:
                        writer.write(frame(7, sid))
                        if not self.invalid:
                            writer.write(frame(8, 0))
                elif command == 9:
                    self.heart_responses += 1
                elif command == 2 and sid not in answered:
                    requests[sid].extend(payload)
                    if bytes(requests[sid]) == b'\1\x7f\0\0\1\1\xbbpool-probe' and (
                            not self.invalid or self.mode == 'duplicate-frame' and sid == 1):
                        answered.add(sid)
                        writer.write(frame(2, sid, REPLY) + frame(3, sid))
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            self.closed.set()
            writer.close()
            self.writers.discard(writer)
            self.tasks.discard(task)

    async def close(self):
        for writer in tuple(self.writers):
            writer.close()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def outbound_case(binary, output, mode):
    output.mkdir(parents=True, exist_ok=True)
    peer = ServerPeer(mode)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(CERTS / 'cert.pem', CERTS / 'key.pem')
    server = await asyncio.start_server(peer.handle, '127.0.0.1', 0, ssl=tls)
    port = available_port()
    configs = {
        'config.json': {'workers': 1, 'log': {'enable': False, 'logDir': str(output / 'logs')}},
        'inbounds.json': [{'tag': 'negotiation-in', 'protocol': 'vless', 'listen': '127.0.0.1',
                          'port': port, 'routingEnabled': True,
                          'settings': {'clients': [{'id': str(uuid.UUID(bytes=USER_ID))}]}}],
        'outbounds.json': [{'tag': 'negotiation-out', 'protocol': 'anytls',
                           'settings': {'server': '127.0.0.1', 'server_port': server.sockets[0].getsockname()[1],
                                        'password': 'secret', 'minIdleSession': 1},
                           'streamSettings': {'network': 'tcp', 'security': 'tls',
                                              'tlsSettings': {'serverName': 'localhost', 'allowInsecure': True}}}],
        'routing.json': {'rules': [{'type': 'field', 'inboundTag': ['negotiation-in'], 'outboundTag': 'negotiation-out'}]},
    }
    for name, config in configs.items():
        (output / name).write_text(json.dumps(config), encoding='utf-8')
    result = {'direction': 'outbound', 'mode': mode, 'passed': False}
    with (output / 'child.log').open('w', encoding='utf-8') as logfile:
        child = subprocess.Popen([str(binary), '--config-dir', str(output)], stdout=logfile, stderr=subprocess.STDOUT)
        try:
            _, startup = await connect_node(child, port)
            startup.close()
            started = time.monotonic()
            if peer.invalid:
                if mode == 'duplicate-frame':
                    await asyncio.wait_for(request(port, 'complete'), 4)
                failed = False
                try:
                    await asyncio.wait_for(request(port, 'complete'), 4)
                except (asyncio.IncompleteReadError, ConnectionError):
                    failed = True
                assert failed, 'invalid negotiation did not fail the request'
                await asyncio.wait_for(peer.closed.wait(), 1)
                assert time.monotonic() - started < 2, 'invalid negotiation only ended after a request timeout'
            else:
                for _ in range(2):
                    await asyncio.wait_for(request(port, 'complete'), 4)
                assert peer.connections == 1 and peer.streams == [1, 2], 'valid negotiation must reuse one TLS session'
                assert not peer.closed.is_set()
                if peer.v2:
                    await until(lambda: peer.heart_responses == 2)
                else:
                    assert peer.heart_responses == 0
            result.update(passed=True, seconds=round(time.monotonic() - started, 3),
                          tls_connections=peer.connections, streams=peer.streams,
                          heart_responses=peer.heart_responses, client_settings=peer.client_settings)
        except Exception as error:
            result.update(error=repr(error), tls_connections=peer.connections, streams=peer.streams)
        finally:
            stop_child(child)
            server.close()
            await server.wait_closed()
            await peer.close()
            result['peer_errors'] = peer.errors
            if peer.errors:
                result['passed'] = False
    return result


async def main(args):
    cases = args.case or [f'inbound:{mode}' for mode in INBOUND_CASES] + [f'outbound:{mode}' for mode in OUTBOUND_CASES]
    results = []
    for case in cases:
        direction, mode = case.split(':')
        function = inbound_case if direction == 'inbound' else outbound_case
        result = await function(args.binary.resolve(), args.output.resolve() / f'{direction}-{mode}', mode)
        results.append(result)
        print(json.dumps(result), flush=True)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

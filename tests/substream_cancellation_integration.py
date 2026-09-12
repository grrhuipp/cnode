"""Loopback panel -> user store -> VLESS Mux/AnyTLS -> dispatcher -> relay."""
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

USER = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811')
CHUNK = b'R' * 60000


def available_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def anytls_frame(command, payload=b'', sid=1):
    return struct.pack('!BIH', command, sid, len(payload)) + payload


def mux_frame(status, payload=b'', port=None):
    metadata = struct.pack('!HBB', 1, status, int(bool(payload)))
    if port is not None:
        metadata += struct.pack('!BHB', 1, port, 1) + socket.inet_aton('127.0.0.1')
    return struct.pack('!H', len(metadata)) + metadata + (struct.pack('!H', len(payload)) + payload if payload else b'')


class Fixture:
    def __init__(self, node_port):
        self.node_port = node_port
        self.tasks = set()
        self.writers = set()
        self.errors = []
        self.received = bytearray()
        self.first_batches = asyncio.Event()
        self.peer_closed = asyncio.Event()
        self.users_requested = 0
        self.closed_at = None

    async def panel(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        try:
            while True:
                header = await reader.readuntil(b'\r\n\r\n')
                lines = header.decode('ascii').split('\r\n')
                method, path, _ = lines[0].split(' ', 2)
                fields = dict(line.lower().split(':', 1) for line in lines[1:] if ':' in line)
                await reader.readexactly(int(fields.get('content-length', '0')))
                if method == 'GET' and '/config?' in path:
                    value = {'server_port': self.node_port, 'network': 'tcp', 'tls': 0,
                             'base_config': {'pull_interval': 60, 'push_interval': 60}}
                elif method == 'GET' and '/user?' in path:
                    self.users_requested += 1
                    value = {'users': [{'id': 1, 'uuid': str(USER), 'speed_limit': 1}]}
                else:
                    value = {}
                body = json.dumps(value).encode()
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
                             + str(len(body)).encode() + b'\r\nConnection: keep-alive\r\n\r\n' + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        except Exception as error:
            self.errors.append(f'panel: {error!r}')
        finally:
            writer.close()
            self.writers.discard(writer)
            self.tasks.discard(task)

    async def peer(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        try:
            while data := await reader.read(65536):
                self.received.extend(data)
                if len(self.received) >= 2 * len(CHUNK):
                    self.first_batches.set()
            self.closed_at = time.monotonic()
        except ConnectionError:
            self.closed_at = time.monotonic()
        except Exception as error:
            self.errors.append(f'peer: {error!r}')
        finally:
            self.peer_closed.set()
            writer.close()
            self.writers.discard(writer)
            self.tasks.discard(task)

    async def close(self):
        for writer in tuple(self.writers):
            writer.close()
        pending = tuple(self.tasks)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


async def run_case(binary, output, protocol, terminate):
    output.mkdir(parents=True, exist_ok=True)
    node_port = available_port()
    fixture = Fixture(node_port)
    panel = await asyncio.start_server(fixture.panel, '127.0.0.1', 0)
    peer = await asyncio.start_server(fixture.peer, '127.0.0.1', 0)
    panel_port = panel.sockets[0].getsockname()[1]
    peer_port = peer.sockets[0].getsockname()[1]
    certificates = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
    config = {'workers': 1, 'log': {'enable': False, 'logDir': str(output / 'logs')},
              'timeouts': {'connIdle': 10, 'uplinkOnly': 3, 'downlinkOnly': 3},
              'panels': [{'Name': 'substream-test', 'Type': 'V2board',
                          'APIHost': f'http://127.0.0.1:{panel_port}', 'Key': 'local-test-key',
                          'NodeIDs': [1], 'NodeType': 'anytls' if protocol == 'anytls' else 'vless',
                          'ListenIP': '127.0.0.1', 'TLSEnable': protocol == 'anytls',
                          'TLSCert': str(certificates / 'cert.pem'), 'TLSKey': str(certificates / 'key.pem')}]}
    (output / 'config.json').write_text(json.dumps(config), encoding='utf-8')
    result = {'protocol': protocol, 'mode': 'session-failure' if terminate else 'logical-fin', 'passed': False}
    client = None
    reader_task = None
    with (output / 'child.log').open('w', encoding='utf-8') as logfile:
        child = subprocess.Popen([str(binary), '--config-dir', str(output)], stdout=logfile, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            while fixture.users_requested == 0:
                if child.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError('node did not fetch the speed-limited panel user')
                await asyncio.sleep(0.02)
            context = None
            if protocol == 'anytls':
                context = ssl.create_default_context(cafile=str(certificates / 'cert.pem'))
                context.check_hostname = False
            while True:
                try:
                    reader, client = await asyncio.open_connection('127.0.0.1', node_port, ssl=context)
                    break
                except OSError:
                    if child.poll() is not None or time.monotonic() > deadline:
                        raise
                    await asyncio.sleep(0.02)

            async def drain_response():
                while await reader.read(65536):
                    pass
            reader_task = asyncio.create_task(drain_response())
            if protocol == 'anytls':
                target = b'\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', peer_port)
                client.write(hashlib.sha256(str(USER).encode()).digest() + b'\0\0'
                             + anytls_frame(4, b'v=2', 0) + anytls_frame(1)
                             + anytls_frame(2, target) + anytls_frame(2, CHUNK) + anytls_frame(2, CHUNK))
                data = anytls_frame(2, CHUNK)
                end = anytls_frame(99) if terminate else anytls_frame(3)
            else:
                client.write(b'\0' + USER.bytes + b'\0\3' + mux_frame(1, CHUNK, peer_port) + mux_frame(2, CHUNK))
                data = mux_frame(2, CHUNK)
                end = b'\0\3\0\1\2\0' if terminate else mux_frame(3)
            await client.drain()
            await asyncio.wait_for(fixture.first_batches.wait(), 5)
            assert len(fixture.received) == 120000, 'unexpected initial traffic'
            client.write(data)
            await client.drain()
            await asyncio.sleep(0.05)
            assert len(fixture.received) == 120000, 'panel rate limit was not applied to the third batch'
            assert not fixture.peer_closed.is_set(), 'target closed before the termination trigger'
            started = time.monotonic()
            client.write(end)
            await client.drain()
            await asyncio.wait_for(fixture.peer_closed.wait(), 2)
            elapsed = fixture.closed_at - started
            expected = CHUNK * (2 if terminate else 3)
            assert fixture.received == expected, 'queued bytes were sent after cancellation or dropped on logical FIN'
            assert 0 <= elapsed < 0.25 if terminate else 0.20 < elapsed < 1.5, f'incorrect termination timing: {elapsed}'
            assert not fixture.errors, fixture.errors
            result.update(passed=True, bytes=len(fixture.received), close_seconds=round(elapsed, 4),
                          sha256=hashlib.sha256(fixture.received).hexdigest(), panel_user_requests=fixture.users_requested)
        except Exception as error:
            result.update(error=repr(error), bytes=len(fixture.received))
        finally:
            if reader_task:
                reader_task.cancel()
                await asyncio.gather(reader_task, return_exceptions=True)
            if client:
                client.close()
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
            panel.close()
            peer.close()
            await panel.wait_closed()
            await peer.wait_closed()
            await fixture.close()
            result['peer_errors'] = fixture.errors
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    results = []
    for protocol in ('mux', 'anytls'):
        for terminate in (True, False):
            results.append(await run_case(args.binary.resolve(), args.output.resolve() / f'{protocol}-{terminate}', protocol, terminate))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(item['passed'] for item in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(asyncio.run(main(parser.parse_args())))

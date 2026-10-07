"""Real TLS/panel AnyTLS stream identity and session reuse checks."""
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

from substream_cancellation_integration import Fixture, USER, anytls_frame, available_port


async def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, 'condition did not complete before deadline'
        await asyncio.sleep(0.01)


class IdentityFixture(Fixture):
    def __init__(self, node_port):
        super().__init__(node_port)
        self.connections = []

    async def peer(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        record = {'bytes': bytearray(), 'closed': False}
        self.connections.append(record)
        try:
            while data := await reader.read(65536):
                record['bytes'].extend(data)
                writer.write(data)
                await writer.drain()
        except ConnectionError:
            pass
        except Exception as error:
            self.errors.append(f'peer: {error!r}')
        finally:
            record['closed'] = True
            writer.close()
            self.writers.discard(writer)
            self.tasks.discard(task)


async def run_case(binary, output, mode):
    output.mkdir(parents=True, exist_ok=True)
    fixture = IdentityFixture(available_port())
    panel = await asyncio.start_server(fixture.panel, '127.0.0.1', 0)
    peer = await asyncio.start_server(fixture.peer, '127.0.0.1', 0)
    certificates = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
    config = {'workers': 1, 'log': {'enable': False, 'logDir': str(output / 'logs')},
              'timeouts': {'connIdle': 10, 'uplinkOnly': 3, 'downlinkOnly': 3},
              'panels': [{'Name': 'identity-test', 'Type': 'V2board',
                          'APIHost': f'http://127.0.0.1:{panel.sockets[0].getsockname()[1]}',
                          'Key': 'local-test-key', 'NodeIDs': [1], 'NodeType': 'anytls',
                          'ListenIP': '127.0.0.1', 'TLSEnable': True,
                          'TLSCert': str(certificates / 'cert.pem'), 'TLSKey': str(certificates / 'key.pem')}]}
    (output / 'config.json').write_text(json.dumps(config), encoding='utf-8')
    result = {'mode': mode, 'passed': False}
    client = None
    reader_task = None
    responses = []
    closed = asyncio.Event()
    with (output / 'child.log').open('w', encoding='utf-8') as logfile:
        child = subprocess.Popen([str(binary), '--config-dir', str(output)], stdout=logfile, stderr=subprocess.STDOUT)
        try:
            await until(lambda: fixture.users_requested != 0 or child.poll() is not None, 8)
            assert child.poll() is None, 'node exited before fetching users'
            context = ssl.create_default_context(cafile=str(certificates / 'cert.pem'))
            context.check_hostname = False
            deadline = time.monotonic() + 5
            while True:
                try:
                    reader, client = await asyncio.open_connection('127.0.0.1', fixture.node_port, ssl=context)
                    break
                except OSError:
                    assert child.poll() is None and time.monotonic() < deadline, 'node did not accept TLS'
                    await asyncio.sleep(0.02)

            async def read_frames():
                try:
                    while True:
                        command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
                        payload = await reader.readexactly(size)
                        responses.append((command, sid, payload))
                except (asyncio.IncompleteReadError, ConnectionError):
                    pass
                finally:
                    closed.set()
            reader_task = asyncio.create_task(read_frames())
            target = b'\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', peer.sockets[0].getsockname()[1])
            first = b'first-logical-stream'
            second = b'second-logical-stream'
            client.write(hashlib.sha256(str(USER).encode()).digest() + b'\0\0'
                         + anytls_frame(4, b'v=2', 0) + anytls_frame(1, sid=7)
                         + anytls_frame(2, target, 7) + anytls_frame(2, first, 7))
            await client.drain()
            await until(lambda: len(fixture.connections) == 1 and fixture.connections[0]['bytes'] == first)
            assert not closed.is_set(), 'initial request unexpectedly ended the session'
            if mode == 'reuse-completed':
                client.write(anytls_frame(3, sid=7))
                await client.drain()
                await until(lambda: fixture.connections[0]['closed'])
                assert not any(c == 3 and sid == 7 for c, sid, _ in responses), 'remote FIN must not be acknowledged with FIN'
                assert not closed.is_set(), 'completed stream must leave the session usable'
            next_sid = 19 if mode == 'valid-gap' else 6 if mode == 'descending' else 7
            client.write(anytls_frame(1, sid=next_sid) + anytls_frame(2, target, next_sid)
                         + anytls_frame(2, second, next_sid))
            await client.drain()
            if mode == 'valid-gap':
                await until(lambda: len(fixture.connections) == 2 and fixture.connections[1]['bytes'] == second)
                client.write(anytls_frame(3, sid=7) + anytls_frame(3, sid=19))
                await client.drain()
                await until(lambda: all(x['closed'] for x in fixture.connections))
                client.write(anytls_frame(8, sid=0))
                await client.drain()
                await until(lambda: any(command == 9 for command, _, _ in responses))
                assert not closed.is_set(), 'valid increasing IDs must preserve the TLS session'
                assert [bytes(x['bytes']) for x in fixture.connections] == [first, second]
                assert not any(command == 5 for command, _, _ in responses), 'valid IDs must not be rejected'
            else:
                await asyncio.wait_for(closed.wait(), 3)
                await until(lambda: fixture.connections[0]['closed'])
                assert len(fixture.connections) == 1, 'invalid SYN opened a second target connection'
                assert fixture.connections[0]['bytes'] == first, 'invalid request bytes reached the existing target'
                assert any(command == 5 and sid == 0 and payload for command, sid, payload in responses), 'missing rejection alert'
            assert not fixture.errors, fixture.errors
            result.update(passed=True, target_connections=len(fixture.connections),
                          target_bytes=[len(x['bytes']) for x in fixture.connections],
                          sha256=[hashlib.sha256(x['bytes']).hexdigest() for x in fixture.connections],
                          alerts=[p.decode('utf-8') for c, _, p in responses if c == 5],
                          session_closed=closed.is_set(), panel_user_requests=fixture.users_requested)
        except Exception as error:
            result.update(error=repr(error), target_connections=len(fixture.connections))
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
    for mode in ('duplicate-active', 'reuse-completed', 'descending', 'valid-gap'):
        results.append(await run_case(args.binary.resolve(), args.output.resolve() / mode, mode))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(asyncio.run(main(parser.parse_args())))

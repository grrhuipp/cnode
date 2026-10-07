"""Owned loopback peers verify protocol setup, initial payload and later data.

Uses only the standard library and the repository's public TLS test fixture.
Run separately from CTest; every observation is made before child cleanup.
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
import uuid

USER = uuid.UUID('11111111-1111-4111-8111-111111111111')
BANNER = b'initial-payload-peer-ready'
TAIL = b'later-payload-' * 9


def frame(command, sid, payload=b''):
    return struct.pack('!BIH', command, sid, len(payload)) + payload


class Peer:
    def __init__(self, protocol, expected):
        self.protocol = protocol
        self.expected = expected
        self.received = b''
        self.errors = []
        self.writers = set()
        self.tasks = set()

    async def handle(self, reader, writer):
        self.tasks.add(asyncio.current_task())
        self.writers.add(writer)
        try:
            if self.protocol == 'anytls':
                auth = await reader.readexactly(34)
                assert auth[:32] == hashlib.sha256(b'secret').digest(), 'AnyTLS authentication changed'
                await reader.readexactly(int.from_bytes(auth[32:], 'big'))
                target_seen = False
                done = False
                while True:
                    command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
                    payload = await reader.readexactly(size)
                    if command == 2 and not target_seen:
                        assert payload == b'\1\x7f\0\0\1\1\xbb', 'AnyTLS target changed'
                        target_seen = True
                        writer.write(frame(2, sid, BANNER))
                    elif command == 2 and target_seen:
                        self.received += payload
                        assert len(self.received) <= len(self.expected), 'duplicate AnyTLS payload'
                        if len(self.received) == len(self.expected) and not done:
                            assert self.received == self.expected, 'AnyTLS payload changed'
                            done = True
                            writer.write(frame(2, sid, self.received) + frame(3, sid))
                    elif command == 8:
                        writer.write(frame(9, sid))
                    await writer.drain()
            else:
                if self.protocol == 'vless':
                    prefix = await reader.readexactly(18)
                    assert prefix[:17] == b'\0' + USER.bytes, 'VLESS authentication changed'
                    await reader.readexactly(prefix[17])
                    assert await reader.readexactly(8) == b'\1\1\xbb\1\x7f\0\0\1', 'VLESS target changed'
                    writer.write(b'\0\0')
                elif self.protocol == 'trojan':
                    assert await reader.readexactly(58) == hashlib.sha224(b'secret').hexdigest().encode() + b'\r\n', 'Trojan authentication changed'
                    assert await reader.readexactly(10) == b'\1\1\x7f\0\0\1\1\xbb\r\n', 'Trojan target changed'
                writer.write(BANNER)
                await writer.drain()
                self.received = await reader.readexactly(len(self.expected))
                assert self.received == self.expected, 'initial/later byte order changed'
                writer.write(self.received)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError) as error:
            if self.received != self.expected:
                self.errors.append(repr(error))
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            self.writers.discard(writer)
            self.tasks.discard(asyncio.current_task())
            writer.close()

    async def close(self):
        for writer in tuple(self.writers):
            writer.close()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def run_case(binary, output, protocol, prefix_size):
    output.mkdir(parents=True, exist_ok=True)
    prefix = bytes((index * 37 + 11) & 255 for index in range(prefix_size))
    expected = prefix + TAIL
    peer = Peer(protocol, expected)
    tls = None
    if protocol in ('trojan', 'anytls'):
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        fixtures = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
        tls.load_cert_chain(fixtures / 'cert.pem', fixtures / 'key.pem')
    server = await asyncio.start_server(peer.handle, '127.0.0.1', 0, ssl=tls)
    peer_port = server.sockets[0].getsockname()[1]
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        inbound_port = reserved.getsockname()[1]
    outbound = {'tag': 'initial-out', 'protocol': protocol, 'settings': {}}
    if protocol == 'vless':
        outbound['settings'] = {'vnext': [{'address': '127.0.0.1', 'port': peer_port,
                                          'users': [{'id': str(USER), 'encryption': 'none'}]}]}
    elif protocol == 'trojan':
        outbound['settings'] = {'servers': [{'address': '127.0.0.1', 'port': peer_port, 'password': 'secret'}]}
    elif protocol == 'anytls':
        outbound['settings'] = {'server': '127.0.0.1', 'server_port': peer_port, 'password': 'secret',
                                'idleSessionCheckInterval': 1, 'idleSessionTimeout': 1, 'minIdleSession': 0}
    if tls:
        outbound['streamSettings'] = {'network': 'tcp', 'security': 'tls',
                                      'tlsSettings': {'serverName': 'localhost', 'allowInsecure': True}}
    configs = {
        'config.json': {'workers': 1, 'timeouts': {'downlinkOnly': 3},
                        'log': {'enable': False, 'logDir': (output / 'logs').as_posix()}},
        'inbounds.json': [{'tag': 'initial-probe', 'protocol': 'vless', 'listen': '127.0.0.1',
                           'port': inbound_port, 'sniffing': {'enabled': False},
                           'settings': {'clients': [{'id': str(USER)}]}}],
        'outbounds.json': [outbound],
        'routing.json': {'rules': [{'type': 'field', 'inboundTag': ['initial-probe'], 'outboundTag': 'initial-out'}]},
    }
    for name, value in configs.items():
        (output / name).write_text(json.dumps(value), encoding='utf-8')
    result = {'protocol': protocol, 'prefix_bytes': prefix_size, 'later_bytes': len(TAIL)}
    client = None
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
            reader, client = await asyncio.open_connection('127.0.0.1', inbound_port)
            target_port = peer_port if protocol == 'freedom' else 443
            client.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', target_port)
                         + b'\1\x7f\0\0\1' + prefix)
            await client.drain()
            assert await asyncio.wait_for(reader.readexactly(2 + len(BANNER)), 5) == b'\0\0' + BANNER, 'server-first greeting failed'
            client.write(TAIL)
            await client.drain()
            if protocol != 'anytls':
                client.write_eof()
            echoed = await asyncio.wait_for(reader.readexactly(len(expected)), 5)
            assert echoed == expected, 'client received reordered/duplicate payload'
            assert not await asyncio.wait_for(reader.read(), 5), 'unexpected extra response bytes'
            assert peer.received == expected and not peer.errors, 'peer payload validation failed'
            result.update(received_bytes=len(peer.received), sha256=hashlib.sha256(peer.received).hexdigest(), passed=True)
        except Exception as error:
            result.update(passed=False, error=repr(error))
        finally:
            result['peer_errors'] = list(peer.errors)
            if client:
                client.close()
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
            server.close()
            await server.wait_closed()
            await peer.close()
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    binary, output = args.binary.resolve(), args.output.resolve()
    results = []
    for protocol in ('freedom', 'vless', 'trojan', 'anytls'):
        for size in (0, 17, 24000):
            results.append(await run_case(binary, output / f'{protocol}-{size}', protocol, size))
    (output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(item['passed'] for item in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(asyncio.run(main(parser.parse_args())))

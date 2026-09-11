"""Owned loopback VLESS -> UDP integration tests for Freedom and Shadowsocks.

Requires Python and cryptography for the independent AES-GCM test peer. DNS
timeout cases use an owned silent UDP listener on a dynamically assigned
loopback port. No external server or credentials are involved.
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

USER = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811')


class SilentDns(asyncio.DatagramProtocol):
    def __init__(self):
        self.requests = 0

    def datagram_received(self, data, peer):
        self.requests += 1


class EchoPeer(asyncio.DatagramProtocol):
    def __init__(self, protocol, mode):
        self.protocol = protocol
        self.mode = mode
        self.received = []
        self.errors = []
        self.transport = None
        self.delayed = []

    def connection_made(self, transport):
        self.transport = transport

    @staticmethod
    def cipher(salt):
        master = hashlib.md5(b'secret').digest()
        key = HKDF(algorithm=hashes.SHA1(), length=16, salt=salt, info=b'ss-subkey').derive(master)
        return AESGCM(key)

    def datagram_received(self, data, peer):
        try:
            if self.protocol == 'shadowsocks':
                plain = self.cipher(data[:16]).decrypt(b'\0' * 12, data[16:], None)
                if plain[:7] != b'\1\x7f\0\0\1\0\x35':
                    raise AssertionError('Shadowsocks embedded target changed')
                self.received.append(len(plain) - 7)
                # An unauthenticated packet must not prevent the valid reply.
                self.transport.sendto(b'invalid encrypted datagram', peer)
                salt = os.urandom(16)
                reply = salt + self.cipher(salt).encrypt(b'\0' * 12, plain, None)
            else:
                self.received.append(len(data))
                reply = data
            if self.mode == 'late_reply':
                self.delayed.append(asyncio.get_running_loop().call_later(0.2, self.transport.sendto, reply, peer))
            else:
                self.transport.sendto(reply, peer)
        except Exception as error:
            self.errors.append(repr(error))


async def close_writer(writer):
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (ConnectionError, TimeoutError):
        writer.transport.abort()


class Client:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.response_header = False

    @classmethod
    async def connect(cls, port, target_host, target_port):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        if target_host == '127.0.0.1':
            address = b'\1\x7f\0\0\1'
        else:
            name = target_host.encode('ascii')
            address = b'\2' + bytes([len(name)]) + name
        writer.write(b'\0' + USER.bytes + b'\0\2' + struct.pack('!H', target_port) + address)
        await writer.drain()
        return cls(reader, writer)

    async def send(self, payload):
        self.writer.write(struct.pack('!H', len(payload)) + payload)
        await self.writer.drain()

    async def receive(self, expected):
        if not self.response_header:
            if await asyncio.wait_for(self.reader.readexactly(2), 4) != b'\0\0':
                raise AssertionError('VLESS response header changed')
            self.response_header = True
        size = struct.unpack('!H', await asyncio.wait_for(self.reader.readexactly(2), 4))[0]
        packet = await asyncio.wait_for(self.reader.readexactly(size), 4)
        if packet != expected:
            raise AssertionError(f'UDP datagram changed: expected {len(expected)}, received {size}')


async def run_case(binary, output, protocol, mode):
    output.mkdir(parents=True, exist_ok=True)
    dns = SilentDns()
    loop = asyncio.get_running_loop()
    dns_transport = None
    if mode in ('dns_timeout', 'shared_cancel'):
        dns_transport, _ = await loop.create_datagram_endpoint(lambda: dns, local_addr=('127.77.0.2', 0))
    dns_server = f'127.77.0.2:{dns_transport.get_extra_info("sockname")[1]}' if dns_transport else '127.77.0.2'
    peer = EchoPeer(protocol, mode)
    peer_transport, _ = await loop.create_datagram_endpoint(lambda: peer, local_addr=('127.0.0.1', 0))
    peer_port = peer_transport.get_extra_info('sockname')[1]
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        inbound_port = reserved.getsockname()[1]
    outbound = {'tag': 'udp-out', 'protocol': protocol, 'settings': {}}
    if protocol == 'shadowsocks':
        outbound['settings'] = {'servers': [{
            'address': 'udp-sink.test' if mode == 'dns_timeout' else '127.0.0.1',
            'port': peer_port, 'method': 'aes-128-gcm', 'password': 'secret'}]}
    configs = {
        'config.json': {'workers': 1, 'timeouts': {'write': 1, 'connIdle': 30, 'downlinkOnly': 1},
                        'dns': {'servers': [dns_server], 'timeout': 10},
                        'log': {'disableUpload': True, 'logDir': (output / 'logs').as_posix()}},
        'inbounds.json': [{'tag': 'udp-probe', 'protocol': 'vless', 'listen': '127.0.0.1',
                           'port': inbound_port, 'routingEnabled': True,
                           'settings': {'clients': [{'id': str(USER)}]}}],
        'outbounds.json': [outbound],
        'routing.json': {'rules': [{'type': 'field', 'inboundTag': ['udp-probe'], 'outboundTag': 'udp-out'}]},
    }
    for name, config in configs.items():
        (output / name).write_text(json.dumps(config), encoding='utf-8')
    clients = []
    result = {'protocol': protocol, 'mode': mode}
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
            if mode in ('dns_timeout', 'shared_cancel'):
                blocked = await Client.connect(inbound_port,
                                               'udp-sink.test' if protocol == 'freedom' else '127.0.0.1', 53)
                clients.append(blocked)
                started = time.monotonic()
                await blocked.send(b'waiting-for-dns')
                if mode == 'shared_cancel':
                    survivor = await Client.connect(inbound_port, '127.0.0.1', peer_port)
                    clients.append(survivor)
                    await survivor.send(b'before-cancel')
                    await survivor.receive(b'before-cancel')
                reply = await asyncio.wait_for(blocked.reader.read(), 4)
                if reply:
                    raise AssertionError('silent DNS unexpectedly produced application data')
                result['request_seconds'] = round(time.monotonic() - started, 3)
                if not (0.5 <= result['request_seconds'] < 3 and dns.requests > 0):
                    raise AssertionError('UDP send did not honor its write budget during DNS')
                if mode == 'shared_cancel':
                    payload = bytes(range(256)) * 80
                    await survivor.send(payload)
                    await survivor.receive(payload)
                    result['survivor_after_cancel'] = len(payload)
            else:
                client = await Client.connect(inbound_port, '127.0.0.1',
                                              53 if protocol == 'shadowsocks' else peer_port)
                clients.append(client)
                if mode == 'late_reply':
                    await client.send(b'late')
                    client.writer.write_eof()
                    await client.receive(b'late')
                else:
                    for payload in (b'first-datagram', bytes(range(256)) * 80):
                        await client.send(payload)
                        await client.receive(payload)
                    client.writer.write_eof()
                if await asyncio.wait_for(client.reader.read(), 2):
                    raise AssertionError('unexpected data after both datagrams')
            result['dns_requests'] = dns.requests
            result['peer_packets'] = peer.received
            result['peer_errors'] = peer.errors
            expected = ([] if mode == 'dns_timeout' else [4] if mode == 'late_reply'
                        else [13, 20480] if mode == 'shared_cancel' else [14, 20480])
            result['passed'] = not peer.errors and peer.received == expected
        except Exception as error:
            result['error'] = repr(error)
            result['dns_requests'] = dns.requests
            result['peer_packets'] = peer.received
            result['peer_errors'] = peer.errors
            result['passed'] = False
        finally:
            for client in clients:
                await close_writer(client.writer)
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            for timer in peer.delayed:
                timer.cancel()
            if dns_transport:
                dns_transport.close()
            peer_transport.close()
            await asyncio.sleep(0)
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    results = []
    cases = [('shadowsocks', 'dns_timeout'), ('freedom', 'dns_timeout'),
             ('freedom', 'shared_cancel'), ('freedom', 'echo'), ('shadowsocks', 'echo'),
             ('freedom', 'late_reply'), ('shadowsocks', 'late_reply')]
    if args.case:
        selected = set(args.case)
        assert selected <= {f'{protocol}-{mode}' for protocol, mode in cases}
        cases = [(protocol, mode) for protocol, mode in cases if f'{protocol}-{mode}' in selected]
    for protocol, mode in cases:
        results.append(await run_case(args.binary.resolve(), args.output.resolve() / f'{protocol}-{mode}', protocol, mode))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

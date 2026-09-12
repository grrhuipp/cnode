"""Real TLS AnyTLS byte-stream target parsing, isolation and UoT probes."""
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

from anytls_identity_integration import IdentityFixture, until
from substream_cancellation_integration import USER, anytls_frame, available_port


class UdpPeer(asyncio.DatagramProtocol):
    def __init__(self):
        self.packets = []
        self.errors = []
        self.closed = asyncio.Event()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.packets.append(data)
        self.transport.sendto(data, address)

    def error_received(self, error):
        self.errors.append(repr(error))

    def connection_lost(self, error):
        if error:
            self.errors.append(repr(error))
        self.closed.set()


async def run_case(binary, output, mode):
    output.mkdir(parents=True, exist_ok=True)
    fixture = IdentityFixture(available_port())
    panel = await asyncio.start_server(fixture.panel, '127.0.0.1', 0)
    ipv6 = 'ipv6' in mode
    peer = await asyncio.start_server(fixture.peer, '::1' if ipv6 else '127.0.0.1', 0)
    udp_transport, udp = await asyncio.get_running_loop().create_datagram_endpoint(
        UdpPeer, local_addr=('127.0.0.1', 0))
    certificates = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
    config = {'workers': 1, 'log': {'enable': False, 'logDir': str(output / 'logs')},
              'timeouts': {'connIdle': 10, 'uplinkOnly': 2, 'downlinkOnly': 2},
              'panels': [{'Name': 'parsing-test', 'Type': 'V2board',
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
            await until(lambda: fixture.users_requested or child.poll() is not None, 8)
            assert child.poll() is None, 'node exited before users'
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
                        responses.append((command, sid, await reader.readexactly(size)))
                except (asyncio.IncompleteReadError, ConnectionError):
                    pass
                finally:
                    closed.set()
            reader_task = asyncio.create_task(read_frames())

            def received(sid):
                return b''.join(payload for command, stream, payload in responses if command == 2 and stream == sid)

            client.write(hashlib.sha256(str(USER).encode()).digest() + b'\0\0' + anytls_frame(4, b'v=2', 0))
            target = ((b'\4' + socket.inet_pton(socket.AF_INET6, '::1')) if ipv6 else
                      (b'\1' + socket.inet_aton('127.0.0.1'))) + struct.pack('!H', peer.sockets[0].getsockname()[1])
            data = bytes(i % 251 for i in range(60000))
            if mode.startswith('uot'):
                connect = 'connect' in mode
                v1 = mode.startswith('uot1')
                magic = b'sp.udp-over-tcp.arpa' if v1 else b'sp.v2.udp-over-tcp.arpa'
                target = b'\3' + bytes([len(magic)]) + magic + b'\0\0'
                endpoint = socket.inet_aton('127.0.0.1') + struct.pack('!H', udp_transport.get_extra_info('sockname')[1])
                request = b'' if v1 else bytes([int(connect)]) + b'\1' + endpoint
                packets = [data[:9000], data[9000:28999]]
                encoded = [(b'' if connect else b'\0' + endpoint) + struct.pack('!H', len(p)) + p for p in packets]
                wire = target + request + b''.join(encoded)
                client.write(anytls_frame(1, sid=1))
                if 'fragmented' in mode:
                    prefix_size = len(target + request) + 9
                    for byte in wire[:prefix_size]:
                        client.write(anytls_frame(2, bytes([byte]), 1) + anytls_frame(0, b'padding', 0))
                    client.write(anytls_frame(2, wire[prefix_size:prefix_size + 6000], 1))
                    client.write(anytls_frame(2, wire[prefix_size + 6000:], 1))
                else:
                    client.write(anytls_frame(2, wire, 1))
                await client.drain()
                expected = b''.join(encoded)
                await until(lambda: len(udp.packets) == 2 and received(1) == expected, 5)
                assert udp.packets == packets, 'UDP packet boundaries or payload changed'
                result.update(datagram_bytes=list(map(len, packets)),
                              sha256=[hashlib.sha256(p).hexdigest() for p in udp.packets],
                              reply_sha256=hashlib.sha256(received(1)).hexdigest())
            elif mode in ('interleaved', 'malformed', 'truncated'):
                client.write(anytls_frame(1, sid=1))
                if mode == 'malformed':
                    client.write(anytls_frame(2, b'\xff', 1))
                else:
                    client.write(anytls_frame(2, target[:2], 1))
                    if mode == 'truncated':
                        client.write(anytls_frame(3, sid=1))
                client.write(anytls_frame(1, sid=2) + anytls_frame(2, target + data, 2))
                await client.drain()
                await until(lambda: received(2) == data, 5)
                if mode == 'interleaved':
                    assert len(fixture.connections) == 1, 'incomplete address must not create an outbound'
                    client.write(anytls_frame(2, target[2:] + data[:17000], 1))
                    await client.drain()
                    await until(lambda: received(1) == data[:17000], 5)
                    assert len(fixture.connections) == 2
                else:
                    if mode == 'truncated':
                        assert not any(c == 3 and sid == 1 for c, sid, _ in responses), 'FIN cannot produce a FIN reply'
                    else:
                        await until(lambda: any(c == 3 and sid == 1 for c, sid, _ in responses))
                    assert len(fixture.connections) == 1, 'invalid logical request opened an outbound'
                result.update(target_bytes=[len(x['bytes']) for x in fixture.connections],
                              sha256=[hashlib.sha256(x['bytes']).hexdigest() for x in fixture.connections])
            else:
                client.write(anytls_frame(1, sid=1))
                if 'fragmented' in mode:
                    for byte in target[:-1]:
                        client.write(anytls_frame(2, bytes([byte]), 1) + anytls_frame(2, b'', 1))
                    client.write(anytls_frame(2, target[-1:] + data[:17000], 1))
                    client.write(anytls_frame(2, data[17000:], 1))
                else:
                    client.write(anytls_frame(2, target + data, 1))
                await client.drain()
                await until(lambda: received(1) == data, 5)
                assert len(fixture.connections) == 1 and fixture.connections[0]['bytes'] == data
                result.update(target_bytes=[len(data)], sha256=[hashlib.sha256(data).hexdigest()])
            client.write(anytls_frame(8, sid=0))
            await client.drain()
            await until(lambda: any(command == 9 for command, _, _ in responses))
            assert not closed.is_set() and not any(command == 5 for command, _, _ in responses)
            assert not fixture.errors and not udp.errors, (fixture.errors, udp.errors)
            result.update(passed=True, session_usable=True, target_connections=len(fixture.connections),
                          panel_user_requests=fixture.users_requested)
        except Exception as error:
            result.update(error=repr(error), target_connections=len(fixture.connections), udp_packets=len(udp.packets))
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
            udp_transport.close()
            await udp.closed.wait()
            await fixture.close()
            result['peer_errors'] = fixture.errors + udp.errors
            if result['peer_errors']:
                result['passed'] = False
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    modes = args.case or ['tcp-coalesced', 'tcp-fragmented', 'tcp-ipv6-coalesced', 'tcp-ipv6-fragmented',
                         'interleaved', 'malformed', 'truncated', 'uot1-coalesced', 'uot1-fragmented',
                         'uot2-connect-coalesced', 'uot2-connect-fragmented',
                         'uot2-packet-coalesced', 'uot2-packet-fragmented']
    results = [await run_case(args.binary.resolve(), args.output.resolve() / mode, mode) for mode in modes]
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

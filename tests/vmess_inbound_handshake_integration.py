"""Exercise segmented VMess/Trojan handshakes, EOF, and timeout on loopback."""
import argparse
import asyncio
import hashlib
import json
import struct
import uuid
from pathlib import Path

from anytls_fin_integration import Resources, available_port, configure, target, tls_settings, until

USER = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811')
PAYLOAD = b'vmess-inbound-handshake-regression'


def inbound_settings():
    return {'clients': [{'id': str(USER), 'email': 'handshake@example.test'}]}


def vmess_outbound(port):
    return {'protocol': 'vmess', 'settings': {
        'address': '127.0.0.1', 'port': port, 'id': str(USER)}}


def vless_inbound(port):
    return {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
            'settings': inbound_settings()}


def vmess_inbound(port):
    return {'protocol': 'vmess', 'listen': '127.0.0.1', 'port': port,
            'settings': inbound_settings()}


async def wait_started(path, child):
    await until(lambda: child.poll() is not None or
                'server started' in path.read_text(encoding='utf-8', errors='replace'), 8)
    assert child.poll() is None, path.read_text(encoding='utf-8', errors='replace')


async def probe_vless(port, destination_port):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', destination_port) +
                 b'\1\x7f\0\0\1' + PAYLOAD)
    await writer.drain()
    try:
        reply = await asyncio.wait_for(reader.readexactly(2 + len(PAYLOAD)), 6)
        assert reply == b'\0\0' + PAYLOAD
    finally:
        writer.close()
        await writer.wait_closed()


async def main(binary, output):
    binary, output = binary.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    try:
        received = []
        captured_vmess = bytearray()
        rejected_flow_port = None

        async def echo(reader, writer):
            data = await reader.readexactly(len(PAYLOAD))
            received.append(data)
            writer.write(data)
            await writer.drain()

        target_port = await resources.listen(echo)
        server_port, front_port = available_port(), available_port()
        while front_port == server_port:
            front_port = available_port()

        server_dir = output / 'vmess-server'
        server_dir.mkdir(parents=True, exist_ok=True)
        configure(server_dir, vmess_inbound(server_port), {'protocol': 'freedom', 'settings': {}})
        server_config = server_dir / 'config.json'
        settings = json.loads(server_config.read_text(encoding='utf-8'))
        settings['timeouts']['handshake'] = 2
        settings['log'].update(enable=True, loglevel='debug')
        server_config.write_text(json.dumps(settings), encoding='utf-8')
        server = resources.spawn([binary, '--config-dir', server_dir], server_dir / 'child.log')
        await wait_started(server_dir / 'child.log', server)

        async def split_vmess(reader, writer):
            upstream_reader, upstream_writer = await resources.connect(server_port)

            async def forward(source, destination, fragment):
                while data := await source.read(65536):
                    if fragment:
                        captured_vmess.extend(data)
                        for byte in data:
                            destination.write(bytes([byte]))
                            await destination.drain()
                            await asyncio.sleep(0.001)
                    else:
                        destination.write(data)
                        await destination.drain()
                if destination.can_write_eof():
                    destination.write_eof()

            try:
                await asyncio.gather(
                    forward(reader, upstream_writer, True),
                    forward(upstream_reader, writer, False))
            finally:
                upstream_writer.close()
                await upstream_writer.wait_closed()

        split_port = await resources.listen(split_vmess)

        client_dir = output / 'vmess-client'
        client_dir.mkdir(parents=True, exist_ok=True)
        configure(client_dir, vless_inbound(front_port), vmess_outbound(split_port))
        client_config = client_dir / 'config.json'
        settings = json.loads(client_config.read_text(encoding='utf-8'))
        settings['log'].update(enable=True, loglevel='debug')
        client_config.write_text(json.dumps(settings), encoding='utf-8')
        client = resources.spawn([binary, '--config-dir', client_dir], client_dir / 'child.log')
        await wait_started(client_dir / 'child.log', client)
        await probe_vless(front_port, target_port)
        assert received == [PAYLOAD], 'VMess inbound did not complete handshake and forward request'

        replay_reader, replay_writer = await resources.connect(server_port)
        replay_writer.write(captured_vmess)
        await replay_writer.drain()
        try:
            assert await asyncio.wait_for(replay_reader.read(), 3) == b''
        except ConnectionError:
            pass
        replay_writer.close()
        assert received == [PAYLOAD], 'VMess replay reached the backend'

        flow_reader, flow_writer = await resources.connect(front_port)
        rejected_flow_port = flow_writer.get_extra_info('sockname')[1]
        flow = b'xtls-rprx-vision'
        addons = b'\x0a' + bytes([len(flow)]) + flow
        flow_writer.write(b'\0' + USER.bytes + bytes([len(addons)]) + addons +
                          b'\2' + struct.pack('!H', target_port) + b'\1\x7f\0\0\1')
        await flow_writer.drain()
        try:
            assert await asyncio.wait_for(flow_reader.read(), 3) == b''
        except ConnectionError:
            pass
        flow_writer.close()

        # An EOF on the first inbound handshake read must tear down the connection.
        eof_reader, eof_writer = await resources.connect(server_port)
        eof_writer.write_eof()
        assert await asyncio.wait_for(eof_reader.read(), 3) == b'', 'EOF handshake was not closed'
        eof_writer.close()
        await eof_writer.wait_closed()

        # A silent peer remains pending briefly, then is closed by the handshake deadline.
        silent_reader, silent_writer = await resources.connect(server_port)
        try:
            try:
                async with asyncio.timeout(0.35):
                    assert await silent_reader.read() == b'', 'silent peer closed before handshake timeout'
                    raise AssertionError('silent peer unexpectedly reached EOF')
            except TimeoutError:
                pass
            assert await asyncio.wait_for(silent_reader.read(), 4) == b'', 'handshake timeout did not close silent peer'
        finally:
            silent_writer.close()
            await silent_writer.wait_closed()
        assert server.poll() is None and client.poll() is None

        trojan_port = available_port()
        trojan_dir = output / 'trojan-server'
        trojan_dir.mkdir(parents=True, exist_ok=True)
        configure(trojan_dir, {
            'protocol': 'trojan', 'listen': '127.0.0.1', 'port': trojan_port,
            'settings': {'clients': [{'password': 'segmented-secret'}]},
            'streamSettings': tls_settings(True),
        }, {'protocol': 'freedom', 'settings': {}})
        trojan = resources.spawn([binary, '--config-dir', trojan_dir], trojan_dir / 'child.log')
        await wait_started(trojan_dir / 'child.log', trojan)
        reader, writer = await resources.connect(trojan_port, tls=True)
        header = (hashlib.sha224(b'segmented-secret').hexdigest().encode() +
                  b'\r\n\1' + target(target_port) + b'\r\n')
        for byte in header:
            writer.write(bytes([byte]))
            await writer.drain()
            await asyncio.sleep(0.001)
        writer.write(PAYLOAD)
        await writer.drain()
        assert await asyncio.wait_for(reader.readexactly(len(PAYLOAD)), 6) == PAYLOAD
        writer.close()
        await writer.wait_closed()
        assert received == [PAYLOAD, PAYLOAD], 'segmented handshake lost or duplicated payload'
        assert trojan.poll() is None
        print('byte-segmented VMess/Trojan handshakes, first-read EOF, and silent timeout passed')
    finally:
        await resources.close()
        assert not resources.errors, '; '.join(resources.errors)
    server_logs = '\n'.join(path.read_text(errors='replace') for path in server_dir.rglob('*.log'))
    replay_lines = [line for line in server_logs.splitlines()
                    if 'rejected ' in line and 'session replay admission rejected' in line]
    assert any(f'tcp:127.0.0.1:{target_port}' in line and
               'email:handshake@example.test' in line for line in replay_lines), \
        'authenticated VMess replay lost target or identity'
    client_logs = '\n'.join(path.read_text(errors='replace') for path in client_dir.rglob('*.log'))
    flow_lines = [line for line in client_logs.splitlines()
                  if f'127.0.0.1:{rejected_flow_port}' in line and 'request flow not allowed' in line]
    assert any(f'udp:127.0.0.1:{target_port}' in line and
               'email:handshake@example.test' in line for line in flow_lines), \
        'authenticated VLESS flow rejection lost UDP target or identity'


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

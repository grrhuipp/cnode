"""Exercise VMess inbound handshake success, EOF, and timeout on loopback."""
import argparse
import asyncio
import json
import struct
import uuid
from pathlib import Path

from anytls_fin_integration import Resources, available_port, configure, until

USER = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811')
PAYLOAD = b'vmess-inbound-handshake-regression'


def inbound_settings():
    return {'clients': [{'id': str(USER)}]}


def vmess_outbound(port):
    return {'protocol': 'vmess', 'settings': {
        'address': '127.0.0.1', 'port': port, 'id': str(USER)}}


def vless_inbound(port):
    return {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
            'settings': {'clients': [{'id': str(USER)}]}}


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
        server_config.write_text(json.dumps(settings), encoding='utf-8')
        server = resources.spawn([binary, '--config-dir', server_dir], server_dir / 'child.log')
        await wait_started(server_dir / 'child.log', server)

        client_dir = output / 'vmess-client'
        client_dir.mkdir(parents=True, exist_ok=True)
        configure(client_dir, vless_inbound(front_port), vmess_outbound(server_port))
        client = resources.spawn([binary, '--config-dir', client_dir], client_dir / 'child.log')
        await wait_started(client_dir / 'child.log', client)
        await probe_vless(front_port, target_port)
        assert received == [PAYLOAD], 'VMess inbound did not complete handshake and forward request'

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
        print('VMess inbound handshake success, first-read EOF, and silent timeout passed')
    finally:
        await resources.close()
        assert not resources.errors, '; '.join(resources.errors)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

"""Exercise split XHTTP across source addresses and merging live H2 connections.

All payloads traverse the real VLESS dispatcher and TCP destination. A third H2
socket joins two already active sessions, forcing their ownership groups to meet;
merely assigning each new physical socket an independent owner cannot pass.
"""
import argparse
import asyncio
import json
from pathlib import Path
import re
import ssl
import struct

from anytls_fin_integration import Resources, USER, available_port, configure, tls_settings, until
from grpc_substream_integration import Peer, h2frame, vless
from http2_server_errors_integration import request_headers
from logical_transport_deadline_integration import Chunked, response


async def connect(resources, port, source, tls, h2=False):
    context = None
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(['h2' if h2 else 'http/1.1'])
    reader, writer = await asyncio.open_connection(
        '127.0.0.1', port, local_addr=(source, 0), ssl=context,
        server_hostname='localhost' if tls else None)
    resources.writers.add(writer)
    return reader, writer


async def start(args, root, resources, tls, mode, extra_port=None):
    async def echo(reader, writer):
        while payload := await reader.read(16384):
            writer.write(payload)
            await writer.drain()
    target = await resources.listen(echo)
    port = available_port()
    transport = tls_settings(True) if tls else {'security': 'none'}
    transport.update(network='xhttp', xhttpSettings={'path': '/fixture', 'mode': mode})
    configure(root, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                    'settings': {'clients': [{'id': str(USER)}]},
                    'streamSettings': transport},
              {'protocol': 'freedom', 'settings': {}})
    if extra_port is not None:
        path = root / 'inbounds.json'
        inbounds = json.loads(path.read_text())
        inbounds.append(dict(inbounds[0], tag='isolated-in', port=extra_port,
                             outboundTag='fin-out'))
        path.write_text(json.dumps(inbounds))
    config_path = root / 'config.json'
    config = json.loads(config_path.read_text())
    config['workers'] = 4
    config['log'].update(enable=True, loglevel='debug')
    config['timeouts'].update(handshake=15, connIdle=30)
    config_path.write_text(json.dumps(config))
    child = resources.spawn([args.binary, '--config-dir', root], root / 'child.log')
    await until(lambda: child.poll() is not None or
                'server started' in (root / 'child.log').read_text(errors='replace'), 10)
    assert child.poll() is None, (root / 'child.log').read_text(errors='replace')
    return port, target, child


async def h1_packet(resources, port, source, tls, session, seq, payload):
    reader, writer = await connect(resources, port, source, tls)
    writer.write((f'POST /fixture/{session}/{seq} HTTP/1.1\r\nHost: localhost\r\n'
                  f'Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n').encode() + payload)
    await writer.drain()
    await response(reader)
    writer.close()
    await writer.wait_closed()


async def h1_scenario(args, root, resources, tls, mode):
    port, target, child = await start(args, root, resources, tls, mode)
    sessions = []
    for index in range(8):
        session = f'h1-{index}'
        reader, writer = await connect(resources, port, f'127.0.0.{index + 2}', tls)
        writer.write(f'GET /fixture/{session} HTTP/1.1\r\nHost: localhost\r\n\r\n'.encode())
        await writer.drain()
        await response(reader)
        body = Chunked(reader)
        upload = None
        if mode == 'stream-up':
            up_reader, upload = await connect(resources, port, f'127.0.0.{index + 40}', tls)
            upload.write((f'POST /fixture/{session} HTTP/1.1\r\nHost: localhost\r\n'
                          'Transfer-Encoding: chunked\r\n\r\n').encode())
            await upload.drain()
            await response(up_reader)
        sessions.append((session, body, writer, upload))
    for sequence in range(5):
        async def exchange(index, entry):
            session, body, _, upload = entry
            payload = bytes([index, sequence]) + bytes(range(251)) * 7
            request = vless(target, payload) if sequence == 0 else payload
            if upload is None:
                await h1_packet(resources, port, f'127.0.0.{index + 60 + sequence * 8}',
                                tls, session, sequence, request)
            else:
                upload.write(f'{len(request):x}\r\n'.encode() + request + b'\r\n')
                await upload.drain()
            expected = (b'\0\0' if sequence == 0 else b'') + payload
            assert await asyncio.wait_for(body.exact(len(expected)), 8) == expected
        await asyncio.gather(*(exchange(i, entry) for i, entry in enumerate(sessions)))
    # Shutdown while all eight logical connections still have read operations.
    child.terminate()
    await until(lambda: child.poll() is not None, 8)
    assert child.returncode == 0, f'active-session shutdown returned {child.returncode}'
    return {'sessions': len(sessions), 'exchanges': 40, 'shutdown': child.returncode}


async def h2_connect(resources, port, source, tls):
    reader, writer = await connect(resources, port, source, tls, h2=True)
    writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4))
    await writer.drain()
    peer = Peer(resources, reader, writer, raw=True)
    await peer.ping(b'physical')
    return peer


async def h2_down(peer, sid, session, tls):
    peer.writer.write(h2frame(1, 5, sid, request_headers(
        'xhttp', tls, f'/fixture/{session}', 'GET')))
    await peer.writer.drain()
    await until(lambda: peer.closed or any(kind == 1 and stream == sid
                for kind, _, stream, _ in peer.frames), 5)
    assert not peer.closed, peer.error


async def h2_packet(peer, sid, session, sequence, payload, tls):
    peer.writer.write(h2frame(1, 4, sid, request_headers(
        'xhttp', tls, f'/fixture/{session}/{sequence}')) + h2frame(0, 1, sid, payload))
    await peer.writer.drain()
    def completed():
        return any(kind in (0, 1) and flags & 1 and stream == sid
                   for kind, flags, stream, _ in peer.frames)
    await until(lambda: peer.closed or completed() or any(kind == 3 and stream == sid
                for kind, _, stream, _ in peer.frames), 8)
    assert completed() and not peer.closed, f'packet {session}/{sequence} failed: {peer.error}'
    assert not any(kind == 3 and stream == sid for kind, _, stream, _ in peer.frames)


async def h2_scenario(args, root, resources, tls):
    port, target, child = await start(args, root, resources, tls, 'packet-up')
    left = await h2_connect(resources, port, '127.0.0.2', tls)
    right = await h2_connect(resources, port, '127.0.0.3', tls)
    await asyncio.gather(h2_down(left, 1, 'left', tls), h2_down(right, 1, 'right', tls))
    await asyncio.gather(
        h2_packet(left, 3, 'left', 0, vless(target, b'left-live'), tls),
        h2_packet(right, 3, 'right', 0, vless(target, b'right-live'), tls))
    await asyncio.gather(left.wait_message(1, b'\0\0left-live'),
                         right.wait_message(1, b'\0\0right-live'))
    # Each existing group has a live proxy request and pending destination read.
    # Both will become associated with the same third physical H2 connection.
    bridge = await h2_connect(resources, port, '127.0.0.4', tls)
    expected = [b'\0\0left-live', b'\0\0right-live']
    next_stream = {left: 5, right: 5, bridge: 1}
    for sequence in range(1, 13):
        source = bridge if sequence % 2 else (left if sequence % 4 else right)
        for index, (name, down) in enumerate((('left', left), ('right', right))):
            payload = struct.pack('!II', index, sequence) + bytes(range(251)) * 9
            sid = next_stream[source]
            next_stream[source] += 2
            await h2_packet(source, sid, name, sequence, payload, tls)
            expected[index] += payload
            await down.wait_message(1, expected[index])
        await asyncio.gather(left.ping(b'leftlive'), right.ping(b'rightliv'),
                             bridge.ping(b'joined!!'))
    # Abrupt loss of the linking socket must not terminate the logical downlinks.
    bridge.writer.transport.abort()
    await bridge.writer.wait_closed()
    for index, (name, down) in enumerate((('left', left), ('right', right))):
        payload = f'{name}-after-detach'.encode()
        await h1_packet(resources, port, f'127.0.0.{80 + index}', tls, name, 13, payload)
        expected[index] += payload
        await down.wait_message(1, expected[index])
        assert not down.error
    child.terminate()
    await until(lambda: child.poll() is not None, 8)
    assert child.returncode == 0, f'merged-group shutdown returned {child.returncode}'
    return {'joined_live_sessions': 2, 'joined_physical_connections': 3,
            'survived_bridge_close': True, 'shutdown': child.returncode}


async def isolation_scenario(args, root, resources, tls):
    extra = available_port()
    port, target, child = await start(args, root, resources, tls, 'packet-up', extra)
    assert port != extra, 'fixture selected a duplicate listener port'
    peers = [await h2_connect(resources, port, '127.0.0.7', tls),
             await h2_connect(resources, extra, '127.0.0.8', tls)]
    await asyncio.gather(*(h2_down(peer, 1, 'same-id', tls) for peer in peers))
    expected = [b'\0\0', b'\0\0']
    for sequence in range(4):
        for index, (listener, peer) in enumerate(zip((port, extra), peers)):
            payload = f'inbound-{index}-sequence-{sequence}'.encode()
            request = vless(target, payload) if sequence == 0 else payload
            await h1_packet(resources, listener, f'127.0.0.{90 + index}', tls,
                            'same-id', sequence, request)
            expected[index] += payload
            await peer.wait_message(1, expected[index])
    child.terminate()
    await until(lambda: child.poll() is not None, 8)
    assert child.returncode == 0
    return {'isolated_namespaces': 2, 'same_session_id': True, 'shutdown': child.returncode}


async def main(args):
    results = []
    for tls in (False, True):
        for mode in ('packet-up', 'stream-up', 'h2-merge', 'isolation'):
            root = args.output / f'{"tls" if tls else "plain"}-{mode}'
            root.mkdir(parents=True, exist_ok=True)
            resources = Resources()
            try:
                if mode == 'h2-merge':
                    result = await h2_scenario(args, root, resources, tls)
                elif mode == 'isolation':
                    result = await isolation_scenario(args, root, resources, tls)
                else:
                    result = await h1_scenario(args, root, resources, tls, mode)
                logs = (root / 'child.log').read_text(errors='replace')
                for path in (root / 'logs').glob('error*.log'):
                    logs += path.read_text(errors='replace')
                accepted_workers = sorted(set(re.findall(r'Worker\[(\d+)\]: accepted TCP', logs)))
                results.append(dict(tls=tls, mode=mode, accepted_workers=accepted_workers, **result))
            finally:
                await resources.close()
            assert not resources.errors, resources.errors
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.binary, args.output = args.binary.resolve(), args.output.resolve()
    asyncio.run(main(args))

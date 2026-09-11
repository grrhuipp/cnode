"""Exercise HTTP/2 resource rejection and connection errors on real shared sockets."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import struct
import traceback

from anytls_fin_integration import Resources, USER, available_port, configure, tls_settings, until
from grpc_substream_integration import Peer, READY, ECHO, grpc, h2frame, vless


MODES = ('overflow', 'capacity', 'initial-end', 'reset-empty', 'reset-long', 'reset-zero', 'reset-idle',
         'early-reset', 'early-settings', 'early-ping')


def request_headers(network, tls):
    fields = [(':method', 'POST'), (':scheme', 'https' if tls else 'http'),
              (':authority', 'localhost'),
              (':path', '/fixture/Tun' if network == 'grpc' else
               '/fixture/' if network == 'xhttp' else '/fixture')]
    if network == 'grpc':
        fields += [('content-type', 'application/grpc'), ('te', 'trailers')]
    return b''.join(b'\0' + bytes([len(k)]) + k.encode() + bytes([len(v)]) + v.encode()
                    for k, v in fields)


async def scenario(args, network, tls, mode, output, result, resources):
    states = {}

    async def destination(reader, writer):
        tag = await reader.readexactly(1)
        states[tag] = writer
        writer.write(READY)
        await writer.drain()
        if tag == b'A':
            writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            writer.transport.pause_reading()
            await asyncio.Event().wait()
        while data := await reader.read(8192):
            writer.write(data)
            await writer.drain()

    target_port = await resources.listen(destination)
    front_port = available_port()
    transport = tls_settings(True) if tls else {'security': 'none'}
    transport['network'] = network
    if network == 'grpc':
        transport['grpcSettings'] = {'serviceName': 'fixture'}
    elif network == 'xhttp':
        transport['xhttpSettings'] = {'path': '/fixture', 'mode': 'stream-one'}
    else:
        transport['httpSettings'] = {'path': '/fixture', 'method': 'POST'}
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
              'settings': {'clients': [{'id': str(USER)}]}, 'streamSettings': transport},
              {'protocol': 'freedom', 'settings': {}})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')

    async def connect():
        reader, writer = await resources.connect(front_port, tls=tls)
        writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4))
        await writer.drain()
        peer = Peer(resources, reader, writer, raw=network != 'grpc')
        await until(lambda: peer.closed or any(t == 4 and not flags & 1 for t, flags, _, _ in peer.frames), 3)
        settings = [body for t, flags, _, body in peer.frames if t == 4 and not flags & 1]
        assert settings and len(settings[0]) % 6 == 0
        result['advertised_settings'] = {str(int.from_bytes(settings[0][i:i+2], 'big')):
            int.from_bytes(settings[0][i+2:i+6], 'big') for i in range(0, len(settings[0]), 6)}
        return peer

    def encode(data):
        return grpc(data) if network == 'grpc' else data

    async def send(peer, sid, data):
        encoded = encode(data)
        for offset in range(0, len(encoded), 16384):
            peer.writer.write(h2frame(0, 0, sid, encoded[offset:offset + 16384]))
        await peer.writer.drain()

    async def open_stream(peer, sid, tag):
        peer.writer.write(h2frame(1, 4, sid, request_headers(network, tls)))
        await send(peer, sid, vless(target_port, tag))

    peer = await connect()
    if mode.startswith('early-'):
        wire, code = {
            'early-reset': (h2frame(3, 0, 1, struct.pack('!I', 8)), 1),
            'early-settings': (h2frame(4, 1, 0, b'\0' * 6), 6),
            'early-ping': (h2frame(6, 0, 1, b'bad-ping'), 1),
        }[mode]
        peer.writer.write(wire)
        await peer.writer.drain()
        await until(lambda: peer.closed, 3)
        goaways = [body for t, _, _, body in peer.frames if t == 7]
        result.update(goaways=[body.hex() for body in goaways], connection_closed=peer.closed)
        assert goaways == [struct.pack('!II', 0, code)]
        peer = await connect()
        await open_stream(peer, 1, b'N')
        await peer.wait_message(1, b'\0\0' + READY)
        await peer.ping(b'recovery')
        result.update(passed=not peer.closed and not peer.error, new_connection_recovered=True)
        return
    if mode == 'initial-end':
        block = request_headers(network, tls)
        peer.writer.write(h2frame(1, 1, 1, block[:3]) + h2frame(9, 4, 1, block[3:]))
        await peer.writer.drain()
        await open_stream(peer, 3, b'S')
        await peer.wait_message(3, b'\0\0' + READY)
        await peer.ping(b'survived')
        def terminal():
            # An empty proxy request can terminate by graceful response or by
            # cancelling the invalid application stream, both driven by EOF.
            return any(sid == 1 and ((t in (0, 1) and flags & 1) or
                       (t == 3 and body == struct.pack('!I', 8)))
                       for t, flags, sid, body in peer.frames)
        await until(lambda: peer.closed or terminal(), 3)
        result.update(initial_end_observed=terminal(), shared_connection_survived=not peer.closed,
                      terminal_frames=[[t, flags, body.hex() if isinstance(body, bytes) else body]
                      for t, flags, sid, body in peer.frames if sid == 1])
        result['passed'] = result['initial_end_observed'] and not peer.closed and not peer.error
        return
    await open_stream(peer, 1, b'A' if mode == 'overflow' else b'V')
    await open_stream(peer, 3, b'S')
    await peer.wait_message(1, b'\0\0' + READY)
    await peer.wait_message(3, b'\0\0' + READY)
    await peer.ping(b'prepared')
    recovery_sid = 5
    if mode == 'overflow':
        # Keep reading control frames and pace bounded batches on connection
        # credit updates. This pressure fixture is not a full flow-control oracle.
        # The target is explicitly paused. Only receipt of RST proves exhaustion.
        sent = 0
        for _ in range(768):
            if peer.closed or any(t == 3 and sid == 1 for t, _, sid, _ in peer.frames):
                break
            before = len(peer.frames)
            await send(peer, 1, b'F' * 32768)
            sent += 32768
            await until(lambda: peer.closed or any(t == 8 and sid == 0
                        for t, _, sid, _ in peer.frames[before:]), 3)
        resets = [body for t, _, sid, body in peer.frames if t == 3 and sid == 1]
        result.update(upload_bytes=sent, target_reading_paused=not states[b'A'].transport.is_reading(),
                      resets=[body.hex() for body in resets])
        assert resets, 'queue exhaustion did not produce RST_STREAM within 24 MiB'
        result['valid_reset'] = resets == [struct.pack('!I', 11)]
    elif mode == 'capacity':
        for sid in range(5, 512, 2):
            peer.writer.write(h2frame(1, 4, sid, request_headers(network, tls)))
        await peer.writer.drain()
        await peer.ping(b'full256!')
        result['accepted_headers'] = len({sid for t, _, sid, _ in peer.frames if t == 1})
        assert result['accepted_headers'] == 256
        # Incremental indexing on a refused stream must still update HPACK;
        # the recovery stream refers to that exact dynamic-table entry (62).
        indexed_field = b'\x40\x09x-fixture\x08rejected'
        peer.writer.write(h2frame(1, 4, 513, request_headers(network, tls) + indexed_field))
        await peer.writer.drain()
        await until(lambda: peer.closed or any(t == 3 and sid == 513 for t, _, sid, _ in peer.frames), 3)
        resets = [body for t, _, sid, body in peer.frames if t == 3 and sid == 513]
        result.update(resets=[body.hex() for body in resets], valid_reset=resets == [struct.pack('!I', 7)])
        # Free one admitted stream and ensure capacity is reclaimed.
        if not peer.closed:
            peer.writer.write(h2frame(3, 0, 1, struct.pack('!I', 8)))
            await peer.writer.drain()
            await peer.ping(b'freedone')
        recovery_sid = 515
    else:
        sid, body, code = {
            'reset-empty': (1, b'', 6), 'reset-long': (1, b'\0' * 8, 6),
            'reset-zero': (0, struct.pack('!I', 8), 1),
            'reset-idle': (5, struct.pack('!I', 8), 1),
        }[mode]
        peer.writer.write(h2frame(3, 0, sid, body))
        await peer.writer.drain()
        await until(lambda: peer.closed, 3)
        goaways = [body for t, _, _, body in peer.frames if t == 7]
        result.update(goaways=[body.hex() for body in goaways], connection_closed=peer.closed)
        assert goaways and len(goaways[-1]) >= 8 and int.from_bytes(goaways[-1][4:8], 'big') == code
        assert not peer.error or peer.error.startswith('ConnectionResetError('), peer.error
        peer = await connect()
        await open_stream(peer, 1, b'N')
        await peer.wait_message(1, b'\0\0' + READY)
        await peer.ping(b'recovery')
        result.update(passed=True, new_connection_recovered=True)
        return

    await send(peer, 3, ECHO)
    await peer.wait_message(3, b'\0\0' + READY + ECHO)
    await peer.ping(b'survived')
    barrier = len(peer.frames)
    if mode == 'capacity':
        peer.writer.write(h2frame(1, 4, recovery_sid, request_headers(network, tls) + b'\xbe'))
        await send(peer, recovery_sid, vless(target_port, b'N'))
        result['hpack_recovery_index'] = 62
    else:
        await open_stream(peer, recovery_sid, b'N')
    await peer.wait_message(recovery_sid, b'\0\0' + READY)
    await peer.ping(b'recovery')
    late = [(t, flags, sid) for t, flags, sid, _ in peer.frames[barrier:] if sid == 1]
    result.update(shared_connection_survived=True, recovered_stream=recovery_sid,
                  late_frames=late, peer_frame_error=peer.error,
                  passed=result['valid_reset'] and not late and not peer.error and not peer.closed)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for network in ('grpc', 'h2', 'xhttp'):
        for tls in (False, True):
            for mode in MODES:
                output = args.output / f'{network}-{mode}-{"tls" if tls else "tcp"}'
                if args.case and output.name != args.case:
                    continue
                output.mkdir(parents=True, exist_ok=True)
                resources = Resources()
                result = {'case': output.name, 'passed': False}
                try:
                    await asyncio.wait_for(scenario(args, network, tls, mode, output, result, resources), 25)
                except Exception as error:
                    result.update(passed=False, error=repr(error), traceback=traceback.format_exc())
                finally:
                    result['children_alive_before_cleanup'] = bool(resources.children) and all(c.poll() is None for c in resources.children)
                    await resources.close()
                result['peer_errors'] = resources.errors
                result['passed'] &= result['children_alive_before_cleanup'] and not resources.errors
                results.append(result)
                print(json.dumps(result), flush=True)
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps({'binary_sha256': digest, 'cases': results}, indent=2))
    return 0 if results and all(r['passed'] for r in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--case')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

"""Exercise bounded consumer backpressure and HTTP/2 errors on real shared sockets."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct
import traceback

from anytls_fin_integration import Resources, USER, available_port, configure, tls_settings, until
from grpc_substream_integration import Peer, READY, ECHO, grpc, h2frame, vless


MODES = ('backpressure', 'capacity', 'malformed-pseudo', 'malformed-host', 'initial-end', 'reset-empty', 'reset-long', 'reset-zero', 'reset-idle',
         'early-reset', 'early-settings', 'early-ping', 'early-hpack', 'packet-reset', 'packet-capacity', 'packet-tiny')


def request_headers(network, tls, path=None, method='POST'):
    fields = [(':method', method), (':scheme', 'https' if tls else 'http'),
              (':authority', 'localhost'),
              (':path', path if path is not None else
               '/fixture/Tun' if network == 'grpc' else
               '/fixture/' if network == 'xhttp' else '/fixture')]
    if network == 'grpc':
        fields += [('content-type', 'application/grpc'), ('te', 'trailers')]
    return b''.join(b'\0' + bytes([len(k)]) + k.encode() + bytes([len(v)]) + v.encode()
                    for k, v in fields)


async def scenario(args, network, tls, mode, output, result, resources):
    states = {}
    resume_upload = asyncio.Event()
    upload_done = asyncio.Event()
    upload_size = 768 * 32768
    upload_digest = hashlib.sha256()
    upload_received = 0

    async def destination(reader, writer):
        nonlocal upload_received
        tag = await reader.readexactly(1)
        states[tag] = writer
        writer.write(READY)
        await writer.drain()
        if tag == b'A':
            writer.transport.pause_reading()
            await resume_upload.wait()
            writer.transport.resume_reading()
            while upload_received < upload_size:
                data = await reader.read(min(65536, upload_size - upload_received))
                assert data, 'backpressured upload ended prematurely'
                upload_digest.update(data)
                upload_received += len(data)
            upload_done.set()
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
        transport['xhttpSettings'] = {'path': '/fixture',
                                     'mode': 'packet-up' if mode.startswith('packet-') else 'stream-one'}
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
        await peer.send_data(sid, encode(data))

    async def open_stream(peer, sid, tag):
        peer.writer.write(h2frame(1, 4, sid, request_headers(network, tls)))
        await send(peer, sid, vless(target_port, tag))

    peer = await connect()
    async def down(sid, session):
        peer.writer.write(h2frame(1, 5, sid, request_headers(
            network, tls, f'/fixture/{session}', 'GET')))
        await peer.writer.drain()

    async def packet(sid, session, sequence, payload, end=True):
        peer.writer.write(h2frame(1, 4, sid, request_headers(
            network, tls, f'/fixture/{session}/{sequence}')))
        peer.writer.write(h2frame(0, int(end), sid, payload))
        await peer.writer.drain()

    def reset(sid):
        return any(kind == 3 and stream_id == sid for kind, _, stream_id, _ in peer.frames)

    async def completed_upload(sid):
        def ended():
            return any(kind in (0, 1) and flags & 1 and stream_id == sid
                       for kind, flags, stream_id, _ in peer.frames)
        await until(lambda: peer.closed or reset(sid) or ended(), 3)
        assert ended() and not reset(sid) and not peer.closed, f'upload {sid} did not commit'

    if mode == 'packet-capacity':
        await down(1, 'capacity')
        await packet(3, 'capacity', 0, vless(target_port, b'S'))
        await peer.wait_message(1, b'\0\0' + READY)
        await completed_upload(3)
        pending = list(range(5, 133, 2))
        for sequence, sid in enumerate(pending, 1):
            await packet(sid, 'capacity', sequence, b'q', end=False)
        await peer.ping(b'uploads!')
        await packet(133, 'capacity', 65, b'x', end=False)
        await until(lambda: peer.closed or reset(133), 3)
        assert reset(133) and not peer.closed, '65th incomplete upload was not rejected'
        assert not any(reset(sid) for sid in pending), 'fewer than 64 uploads were admitted'
        # RST releases an in-flight reservation, without committing sequence 1.
        peer.writer.write(h2frame(3, 0, 5, struct.pack('!I', 8)))
        await peer.writer.drain()
        await peer.ping(b'rst-free')
        await packet(135, 'capacity', 1, ECHO)
        await completed_upload(135)
        await peer.wait_message(1, b'\0\0' + READY + ECHO)
        # A completed upload releases its slot too: refill all 64, reject the
        # next one, finish an original upload, then successfully admit another.
        await packet(137, 'capacity', 65, b'z', end=False)
        await peer.ping(b'refilled')
        await packet(139, 'capacity', 66, b'x', end=False)
        await until(lambda: peer.closed or reset(139), 3)
        assert reset(139) and not reset(137) and not peer.closed
        peer.writer.write(h2frame(0, 1, 7))
        await peer.writer.drain()
        await completed_upload(7)
        await peer.wait_message(1, b'\0\0' + READY + ECHO + b'q')
        await packet(141, 'capacity', 66, b'final')
        await completed_upload(141)
        await peer.ping(b'capacity')
        result.update(passed=not peer.closed and not peer.error,
                      incomplete_uploads_admitted=64, overflow_uploads_rejected=2,
                      rst_released_slot=True, end_stream_released_slot=True,
                      shared_connection_survived=True)
        return
    if mode == 'packet-tiny':
        await down(1, 'tiny')
        await packet(3, 'tiny', 0, vless(target_port, b'S'))
        await peer.wait_message(1, b'\0\0' + READY)
        await completed_upload(3)
        payload = bytes(index % 251 for index in range(1024))
        peer.writer.write(h2frame(1, 4, 5, request_headers(network, tls, '/fixture/tiny/1')))
        # Each fragment arrives in a distinct DATA frame. PING barriers keep
        # exercising the pending-upload path, rather than only a coalesced EOF.
        # 1024 separate 8-KiB allocations would exceed the 4-MiB upload budget.
        for offset, byte in enumerate(payload):
            peer.writer.write(h2frame(0, int(offset == len(payload) - 1), 5, bytes([byte])))
            if (offset + 1) % 64 == 0:
                await peer.writer.drain()
                await peer.ping(struct.pack('!Q', offset))
                assert not reset(5), 'tiny DATA fragments exhausted payload capacity'
        await completed_upload(5)
        await peer.wait_message(1, b'\0\0' + READY + payload)
        await packet(7, 'tiny', 2, ECHO)
        await completed_upload(7)
        await peer.wait_message(1, b'\0\0' + READY + payload + ECHO)
        result.update(passed=not peer.closed and not peer.error,
                      one_byte_data_frames=len(payload), ordered_payload_preserved=True,
                      fragmented_upload_committed=True, subsequent_upload_recovered=True)
        return
    if mode == 'packet-reset':

        await down(1, 'victim')
        await packet(3, 'victim', 0, vless(target_port, b'V'), end=False)
        await peer.ping(b'prefix!!')
        peer.writer.write(h2frame(3, 0, 3, struct.pack('!I', 8)))
        await peer.writer.drain()
        await down(5, 'sibling')
        await packet(7, 'sibling', 0, vless(target_port, b'S'))
        await peer.wait_message(5, b'\0\0' + READY)
        # Reusing sequence zero with a different complete proxy request proves
        # that RST did not commit even a valid-looking request prefix.
        await packet(9, 'victim', 0, vless(target_port, b'R'))
        await peer.wait_message(1, b'\0\0' + READY)
        await until(lambda: b'R' in states, 3)
        assert b'V' not in states, 'RST upload committed its buffered prefix'
        peer.writer.write(h2frame(3, 0, 1, struct.pack('!I', 8)))
        await peer.writer.drain()
        await packet(11, 'sibling', 1, ECHO)
        await peer.wait_message(5, b'\0\0' + READY + ECHO)
        await peer.ping(b'split-ok')
        await down(13, 'recovered')
        await packet(15, 'recovered', 0, vless(target_port, b'N'))
        await peer.wait_message(13, b'\0\0' + READY)
        assert b'V' not in states, 'reset prefix was dispatched after a later upload'
        result.update(passed=not peer.closed and not peer.error,
                      reset_prefix_discarded=True, sequence_zero_reused=True,
                      split_sibling_survived=True, recovered_stream=13)
        return
    if mode.startswith('early-'):
        wire, code = {
            'early-reset': (h2frame(3, 0, 1, struct.pack('!I', 8)), 1),
            'early-settings': (h2frame(4, 1, 0, b'\0' * 6), 6),
            'early-ping': (h2frame(6, 0, 1, b'bad-ping'), 1),
            # RFC 7541 6.1: index 0 is invalid; RFC 9113 4.3 COMPRESSION_ERROR.
            'early-hpack': (h2frame(1, 5, 1, b'\x80'), 9),
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
    await open_stream(peer, 1, b'A' if mode == 'backpressure' else b'V')
    await open_stream(peer, 3, b'S')
    await peer.wait_message(1, b'\0\0' + READY)
    await peer.wait_message(3, b'\0\0' + READY)
    await peer.ping(b'prepared')
    recovery_sid = 5
    if mode == 'backpressure':
        # A compliant sender must stop at the advertised stream window, not
        # overflow the receiver's queue or expect credit for unread bytes.
        async def flood():
            for _ in range(768):
                await send(peer, 1, b'F' * 32768)

        upload = asyncio.create_task(flood())
        resources.tasks.add(upload)
        previous = peer.sent_data.get(1, 0)
        stable_since = asyncio.get_running_loop().time()

        def stalled():
            nonlocal previous, stable_since
            assert not peer.closed and not peer.error and 1 not in peer.resets
            assert not upload.done(), 'unread consumer did not backpressure DATA'
            now = asyncio.get_running_loop().time()
            current = peer.sent_data.get(1, 0)
            if current != previous or peer.send_capacity(1) > 0:
                previous, stable_since = current, now
                return False
            return now - stable_since >= 0.3

        await until(stalled, 5)
        assert peer.stream_send_windows[1] == 0
        assert peer.connection_send_window > 0, 'one stalled stream monopolized the connection'
        assert not states[b'A'].transport.is_reading()
        result.update(stalled_wire_bytes=previous, target_reading_paused=True,
                      stream_window_exhausted=True)
        await send(peer, 3, ECHO)
        await peer.wait_message(3, b'\0\0' + READY + ECHO)
        await peer.ping(b'paused!!')
        resume_upload.set()
        await upload
        await until(upload_done.is_set, 5)
        assert upload_received == upload_size
        assert upload_digest.digest() == hashlib.sha256(b'F' * upload_size).digest()
        assert 1 not in peer.resets, 'compliant upload was reset instead of resumed'
        await send(peer, 1, ECHO)
        await peer.wait_message(1, b'\0\0' + READY + ECHO)
        result.update(upload_bytes=upload_received, upload_sha256=upload_digest.hexdigest(),
                      backpressure_recovered=True, sibling_while_paused=True)
        peer.writer.write(h2frame(3, 0, 1, struct.pack('!I', 8)))
        await peer.writer.drain()
        await peer.ping(b'released')
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
    elif mode.startswith('malformed-'):
        # RFC 9113 8.1.1: a malformed request is a stream error; the shared
        # connection and its open streams continue.
        extra = {'malformed-pseudo': (':path', '/fixture'),
                 'malformed-host': ('host', 'other.example')}[mode]
        field = b'\0' + bytes([len(extra[0])]) + extra[0].encode() + bytes([len(extra[1])]) + extra[1].encode()
        peer.writer.write(h2frame(1, 4, 5, request_headers(network, tls) + field))
        await peer.writer.drain()
        await until(lambda: peer.closed or any(t == 3 and sid == 5 for t, _, sid, _ in peer.frames), 3)
        resets = [body for t, _, sid, body in peer.frames if t == 3 and sid == 5]
        result.update(resets=[body.hex() for body in resets], valid_reset=resets == [struct.pack('!I', 1)])
        recovery_sid = 7
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

    if mode != 'backpressure':
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
                  passed=(result.get('valid_reset', False) or result.get('backpressure_recovered', False))
                  and not late and not peer.error and not peer.closed)


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for network in ('grpc', 'h2', 'xhttp'):
        for tls in (False, True):
            for mode in MODES:
                if mode.startswith('packet-') and network != 'xhttp':
                    continue
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

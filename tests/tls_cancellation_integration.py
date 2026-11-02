"""An AnyTLS logical FIN must join a pending Trojan/TLS outbound read.

This reaches the production TLS stack through the normal dispatcher/relay chain.
The existing AnyTLS pool pressure suite independently covers TLS write cancellation.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import ssl
import time

from anytls_fin_integration import (
    Resources, Frames, REQUEST, BANNER, CERTIFICATES, available_port, configure, frame, target, tls_settings, until,
)


async def main(args):
    args.output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    peer_writer = None
    peer_eof = asyncio.Event()
    partial_sent = asyncio.Event()
    extra = bytearray()
    close_notify_received = False
    record_tail = b''
    resume_payload = b'incomplete TLS record must never become payload'
    expected_payload = BANNER + (resume_payload if args.resume_record else b'')
    result = {'passed': False, 'partial_record': args.partial_record,
              'idle_seconds': args.idle_seconds, 'resume_record': args.resume_record,
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest()}

    async def trojan(reader, writer):
        nonlocal peer_writer, close_notify_received, record_tail
        peer_writer = writer
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERTIFICATES / 'cert.pem', CERTIFICATES / 'key.pem')
        secured = context.wrap_bio(incoming, outgoing, server_side=True)

        async def flush():
            writer.write(outgoing.read())
            await writer.drain()

        async def feed():
            await flush()
            data = await reader.read(65536)
            if not data:
                peer_eof.set()
                raise EOFError('TLS socket closed')
            incoming.write(data)

        while True:
            try:
                secured.do_handshake()
                break
            except ssl.SSLWantReadError:
                await feed()
        await flush()
        expected = hashlib.sha224(b'secret').hexdigest().encode() + b'\r\n\1' + target(443) + b'\r\n' + REQUEST
        request = bytearray()
        while len(request) < len(expected):
            try:
                request.extend(secured.read(len(expected) - len(request)))
            except ssl.SSLWantReadError:
                await feed()
        assert request == expected
        assert secured.write(BANNER) == len(BANNER)
        await flush()
        if args.partial_record:
            secured.write(resume_payload)
            encrypted = outgoing.read()
            assert len(encrypted) > 6
            record_tail = encrypted[6:]
            # Leave SSL waiting inside a record, after the TCP readability wait.
            writer.write(encrypted[:6])
            await writer.drain()
        partial_sent.set()
        while True:
            data = await reader.read(65536)
            if not data:
                peer_eof.set()
                break
            incoming.write(data)
            while True:
                try:
                    plain = secured.read(65536)
                    if not plain:
                        close_notify_received = True
                        # The incomplete record deliberately cannot be followed
                        # by another TLS record. Acknowledge shutdown with TCP
                        # EOF only after cnode has joined the cancelled read and
                        # emitted its own close_notify.
                        writer.write_eof()
                        break
                    extra.extend(plain)
                except (ssl.SSLWantReadError, ssl.SSLZeroReturnError):
                    break

    try:
        peer_port = await resources.listen(trojan)
        port = available_port()
        configure(args.output,
                  {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': port,
                   'settings': {'clients': [{'password': 'secret'}]}, 'streamSettings': tls_settings(True)},
                  {'protocol': 'trojan', 'settings': {'servers': [
                      {'address': '127.0.0.1', 'port': peer_port, 'password': 'secret'}]},
                   'streamSettings': tls_settings()})
        child = resources.spawn([args.binary, '--config-dir', args.output], args.output / 'child.log')
        reader, writer = await resources.connect(port, tls=True)
        received = Frames(resources, reader)
        writer.write(hashlib.sha256(b'secret').digest() + b'\0\0' + frame(4, payload=b'v=2')
                     + frame(1, 1) + frame(2, 1, target(443) + REQUEST))
        await writer.drain()
        await until(lambda: received.payload(1) == BANNER)
        await asyncio.wait_for(partial_sent.wait(), 1)
        # Normal heap collection runs every 10s; idle variants cross that boundary.
        result['stage'] = 'idle'
        await asyncio.sleep(args.idle_seconds)
        result['stage'] = 'resume-record' if args.resume_record else 'fin-barrier'
        if args.resume_record:
            assert args.partial_record and record_tail
            peer_writer.write(record_tail)
            await peer_writer.drain()
            await until(lambda: received.payload(1) == expected_payload)
        result['stage'] = 'fin-barrier'
        started = time.monotonic()
        writer.write(frame(3, 1))
        await received.barrier(writer)
        timely = True
        try:
            await asyncio.wait_for(peer_eof.wait(), 1)
        except TimeoutError:
            timely = False
        result['peer_eof_seconds'] = round(time.monotonic() - started, 3)
        result['timely'] = timely
        # Rescue a failing implementation after recording the missed deadline;
        # cleanup itself is never counted as successful request cancellation.
        if not timely and peer_writer:
            peer_writer.transport.abort()
        await received.barrier(writer)
        result.update(passed=timely and not extra and received.payload(1) == expected_payload
                      and close_notify_received and received.count(3, 1) == 0
                      and not received.closed and child.poll() is None,
                      close_notify_received=close_notify_received, extra_bytes=len(extra),
                      fin_replies=received.count(3, 1), session_alive=not received.closed)
    except Exception as error:
        result['error'] = repr(error)
        if 'received' in locals():
            result['received_frames'] = [(c, sid, len(p)) for c, sid, p in received.values]
            result['session_closed'] = received.closed
        if 'child' in locals():
            result['exit_code'] = child.poll()
    finally:
        await resources.close()
    result['peer_errors'] = resources.errors
    result['passed'] &= not resources.errors
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    if not result['passed']:
        for log in sorted((args.output / 'logs').glob('error*.log')):
            print(log.read_text(errors='replace')[-16000:], flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--partial-record', action='store_true')
    parser.add_argument('--idle-seconds', type=float, default=0.1)
    parser.add_argument('--resume-record', action='store_true')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

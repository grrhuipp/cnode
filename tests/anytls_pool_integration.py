"""Real VLESS -> cnode -> AnyTLS/TLS lifecycle probe; Python standard library only.

The certificate/key beside this test are public loopback fixtures. No external
network service is used. Every child and socket is owned by this test.

Run --suite pool for idle eviction/reuse, or --suite relay for request deadlines,
write backpressure, cancellation, and reuse after clearing request deadlines.
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

USER_ID = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811').bytes
REPLY = b'anytls-pool-reply'


def frame(command, sid, payload=b''):
    return struct.pack('!BIH', command, sid, len(payload)) + payload


class Peer:
    def __init__(self, initial_requests, mode):
        self.initial_requests = initial_requests
        self.mode = mode
        self.finished = 0
        self.barrier = asyncio.Event()
        self.accepted = 0
        self.closed = set()
        self.writers = set()
        self.errors = []
        self.tasks = set()
        self.trickle_frames = 0

    def start_task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.add(task)
        def completed(task):
            self.tasks.discard(task)
            if not task.cancelled() and (error := task.exception()) is not None:
                self.errors.append(repr(error))
        task.add_done_callback(completed)
        return task

    async def trickle(self, writer, sid, stopped):
        try:
            while True:
                await asyncio.sleep(0.1)
                if writer.is_closing() or stopped.is_set():
                    return
                writer.write(frame(2, sid, b'trickle'))
                await writer.drain()
                self.trickle_frames += 1
        except (ConnectionError, ssl.SSLError):
            pass

    async def resume_reading(self, writer):
        # Resume only after the one-second request budget. This lets the peer
        # observe the actual connection close, before the harness stops cnode.
        await asyncio.sleep(2)
        if not writer.is_closing():
            writer.transport.resume_reading()

    async def reject_stream(self, writer, sid):
        await asyncio.sleep(0.6)
        if writer.is_closing():
            return
        try:
            writer.write(frame(5, sid, b'rejected while upload is blocked'))
            await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass

    async def finish_stream(self, writer, sid):
        # Start upload pressure before closing the logical stream.
        await asyncio.sleep(0.6)
        if not writer.is_closing():
            writer.write(frame(3, sid))
            await writer.drain()

    async def handle(self, reader, writer):
        self.accepted += 1
        connection_id = self.accepted
        self.writers.add(writer)
        stalled = False
        children = []
        requests = {}
        answered = set()
        stopped = {}
        try:
            auth = await reader.readexactly(34)
            if auth[:32] != hashlib.sha256(b'secret').digest():
                raise AssertionError('AnyTLS authentication digest mismatch')
            await reader.readexactly(int.from_bytes(auth[32:34], 'big'))
            while True:
                command, sid, length = struct.unpack('!BIH', await reader.readexactly(7))
                payload = await reader.readexactly(length)
                if command == 1:
                    requests[sid] = bytearray()
                    stopped[sid] = asyncio.Event()
                if self.mode in ('stalled_write', 'write_timeout', 'alert_during_write') and command == 2 and not stalled:
                    stalled = True
                    writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                    writer.write(frame(2, sid, REPLY))
                    if self.mode == 'stalled_write':
                        children.append(self.start_task(self.finish_stream(writer, sid)))
                    await writer.drain()
                    writer.transport.pause_reading()
                    children.append(self.start_task(self.resume_reading(writer)))
                    if self.mode == 'alert_during_write':
                        children.append(self.start_task(self.reject_stream(writer, sid)))
                if command == 2 and not stalled and sid not in answered:
                    requests[sid].extend(payload)
                    if bytes(requests[sid]) != b'\1\x7f\0\0\1\1\xbbpool-probe':
                        continue
                    answered.add(sid)
                    self.finished += 1
                    if self.finished >= self.initial_requests:
                        self.barrier.set()
                    await self.barrier.wait()
                    writer.write(frame(2, sid, REPLY))
                    if self.mode == 'complete':
                        writer.write(frame(3, sid))
                    await writer.drain()
                    if self.mode == 'trickle_no_fin':
                        children.append(self.start_task(self.trickle(writer, sid, stopped[sid])))
                elif command == 3:
                    if sid in stopped:
                        stopped[sid].set()
                elif command == 8:
                    writer.write(frame(9, sid))
                    await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        except Exception as error:
            self.errors.append(str(error))
        finally:
            for task in children:
                task.cancel()
            await asyncio.gather(*children, return_exceptions=True)
            self.closed.add(connection_id)
            self.writers.discard(writer)
            writer.close()

    async def close(self):
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for writer in tuple(self.writers):
            writer.close()
        await asyncio.sleep(0)


async def request(port, mode):
    reader, writer = await asyncio.open_connection('127.0.0.1', port)
    try:
        # VLESS TCP request: version, UUID, addons length, command, target port,
        # IPv4 address type and target. The fake AnyTLS peer never dials it.
        writer.write(b'\0' + USER_ID + b'\0\1' + struct.pack('!H', 443)
                     + b'\1\x7f\0\0\1' + b'pool-probe')
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(2 + len(REPLY)), 10)
        if reply != b'\0\0' + REPLY:
            raise AssertionError(f'VLESS response mismatch: {reply!r}')
        if mode == 'trickle_no_fin':
            await asyncio.sleep(0.6)
            writer.write_eof()
        if mode in ('stalled_write', 'write_timeout', 'alert_during_write'):
            async def upload():
                sent = 0
                try:
                    for _ in range(1024):
                        writer.write(b'x' * 65536)
                        await writer.drain()
                        sent += 65536
                except ConnectionError:
                    pass
                return sent

            uploader = asyncio.create_task(upload())
            try:
                # Reading EOF alone does not prove the concurrently blocked
                # writer was cancelled. Require both directions to finish.
                async def read_to_close():
                    try:
                        await reader.read()
                    except ConnectionError:
                        pass
                _, sent = await asyncio.wait_for(asyncio.gather(read_to_close(), uploader), 5)
                if sent == 64 * 1024 * 1024:
                    raise AssertionError('test did not produce write backpressure')
                return {'uploaded_bytes': sent}
            finally:
                uploader.cancel()
                await asyncio.gather(uploader, return_exceptions=True)
        await asyncio.wait_for(reader.read(), 5)
        return {}
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (ConnectionError, TimeoutError):
            writer.transport.abort()


async def run_case(binary, output, minimum, mode='complete', timeouts=None):
    output.mkdir(parents=True, exist_ok=True)
    peer = Peer(1 if minimum == 0 else 2, mode)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    fixtures = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
    tls.load_cert_chain(fixtures / 'cert.pem', fixtures / 'key.pem')
    server = await asyncio.start_server(peer.handle, '127.0.0.1', 0, ssl=tls)
    peer_port = server.sockets[0].getsockname()[1]
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        inbound_port = reserved.getsockname()[1]
    configs = {
        'config.json': {'workers': 1, 'log': {'enable': False, 'logDir': (output / 'logs').as_posix()}},
        'inbounds.json': [{'tag': 'pool-probe', 'protocol': 'vless', 'listen': '127.0.0.1',
                          'port': inbound_port,
                          'settings': {'clients': [{'id': str(uuid.UUID(bytes=USER_ID))}]}}],
        'outbounds.json': [{'tag': 'pool-out', 'protocol': 'anytls',
                           'settings': {'server': '127.0.0.1', 'server_port': peer_port, 'password': 'secret',
                                        'idleSessionCheckInterval': 1, 'idleSessionTimeout': 1,
                                        'minIdleSession': minimum},
                           'streamSettings': {'network': 'tcp', 'security': 'tls',
                                              'tlsSettings': {'serverName': 'localhost', 'allowInsecure': True}}}],
        'routing.json': {'rules': [{'type': 'field', 'inboundTag': ['pool-probe'], 'outboundTag': 'pool-out'}]},
    }
    if timeouts is not None:
        configs['config.json']['timeouts'] = timeouts
    for name, config in configs.items():
        (output / name).write_text(json.dumps(config), encoding='utf-8')
    result = {'minimum': minimum, 'mode': mode}
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
            started = time.monotonic()
            result['requests'] = await asyncio.wait_for(asyncio.gather(
                *(request(inbound_port, mode) for _ in range(peer.initial_requests))), 15)
            result['request_seconds'] = round(time.monotonic() - started, 3)
            result['initial_connections'] = peer.accepted
            result['initial_requests_completed'] = peer.finished
            await asyncio.sleep(3.5)
            result['closed_while_idle'] = len(peer.closed)
            result['open_while_idle'] = peer.accepted - len(peer.closed)
            if minimum:
                await asyncio.wait_for(request(inbound_port, mode), 15)
                result['connections_after_reuse'] = peer.accepted
            result['peer_errors'] = peer.errors
            result['passed'] = (not peer.errors and result['initial_connections'] == peer.initial_requests
                                and result['open_while_idle'] == minimum
                                and (not minimum or result['connections_after_reuse'] == peer.initial_requests))
            if mode != 'complete':
                result['passed'] &= 0.5 <= result['request_seconds'] < 4
            if mode == 'trickle_no_fin':
                result['trickle_frames'] = peer.trickle_frames
                result['passed'] &= peer.trickle_frames >= 3
            if mode in ('alert_during_write', 'stalled_write'):
                # The peer resumes reading at 2s; cancellation must finish the
                # request before that, independently of transport timeouts.
                result['passed'] &= result['request_seconds'] < 1.8
        except Exception as error:
            result['error'] = repr(error)
            result['connections_before_cleanup'] = peer.accepted
            result['closed_before_cleanup'] = len(peer.closed)
            result['open_before_cleanup'] = peer.accepted - len(peer.closed)
            result['passed'] = False
        finally:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            server.close()
            await server.wait_closed()
            await peer.close()
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    results = []
    if args.suite == 'pool':
        cases = [(f'minimum-{minimum}', minimum, 'complete', None) for minimum in (0, 1)]
    else:
        cases = [
            ('idle-without-fin', 0, 'no_fin', {'connIdle': 1}),
            ('local-close-during-trickle', 0, 'trickle_no_fin', {'connIdle': 10}),
            ('remote-fin-during-write', 0, 'stalled_write', {'write': 30, 'connIdle': 30}),
            ('write-timeout', 0, 'write_timeout', {'write': 1}),
            ('alert-during-write', 0, 'alert_during_write', {'write': 30, 'connIdle': 30}),
            ('reuse-after-deadline', 1, 'complete', {'downlinkOnly': 1, 'connIdle': 1, 'write': 1}),
        ]
    if args.case:
        selected = set(args.case)
        assert selected <= {name for name, *_ in cases}, 'unknown case for the selected suite'
        cases = [case for case in cases if case[0] in selected]
    for name, minimum, mode, timeouts in cases:
        results.append(await run_case(args.binary.resolve(), args.output.resolve() / name, minimum, mode, timeouts))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--suite', choices=('pool', 'relay'), default='pool')
    parser.add_argument('--case', action='append')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

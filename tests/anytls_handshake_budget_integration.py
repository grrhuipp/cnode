"""Real TLS/panel tests of per-stream admission and absolute header deadlines."""
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


async def run_case(binary, output, mode):
    output.mkdir(parents=True, exist_ok=True)
    fixture = IdentityFixture(available_port())
    panel = await asyncio.start_server(fixture.panel, '127.0.0.1', 0)
    peer = await asyncio.start_server(fixture.peer, '127.0.0.1', 0)
    certificates = Path(__file__).resolve().parent / 'fixtures/anytls-pool'
    capacity = mode.startswith('capacity')
    version = 1 if mode == 'capacity-v1' else 2
    config = {'workers': 1, 'log': {'enable': False, 'logDir': str(output / 'logs')},
              'timeouts': {'handshake': 3 if capacity else 1, 'connIdle': 3, 'uplinkOnly': 2, 'downlinkOnly': 2},
              'panels': [{'Name': 'handshake-budget', 'Type': 'V2board',
                          'APIHost': f'http://127.0.0.1:{panel.sockets[0].getsockname()[1]}',
                          'Key': 'local-test-key', 'NodeIDs': [1], 'NodeType': 'anytls',
                          'ListenIP': '127.0.0.1', 'TLSEnable': True,
                          'TLSCert': str(certificates / 'cert.pem'), 'TLSKey': str(certificates / 'key.pem')}]}
    (output / 'config.json').write_text(json.dumps(config), encoding='utf-8')
    result = {'mode': mode, 'passed': False}
    client = None
    tasks = []
    frames = []
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
                    assert child.poll() is None and time.monotonic() < deadline
                    await asyncio.sleep(0.02)

            async def read_frames():
                try:
                    while True:
                        command, sid, size = struct.unpack('!BIH', await reader.readexactly(7))
                        frames.append((command, sid, await reader.readexactly(size), time.monotonic()))
                except (asyncio.IncompleteReadError, ConnectionError):
                    pass
                finally:
                    closed.set()

            async def activity():
                while True:
                    await asyncio.sleep(0.1)
                    client.write(anytls_frame(8 if version == 2 else 0, sid=0))
                    if mode == 'trickle':
                        client.write(anytls_frame(2, b'a', 1))
                    await client.drain()

            tasks = [asyncio.create_task(read_frames()), asyncio.create_task(activity())]
            client.write(hashlib.sha256(str(USER).encode()).digest() + b'\0\0' +
                         anytls_frame(4, f'v={version}'.encode(), 0))
            target = b'\1' + socket.inet_aton('127.0.0.1') + struct.pack('!H', peer.sockets[0].getsockname()[1])

            def received(sid):
                return b''.join(data for command, stream, data, _ in frames if command == 2 and stream == sid)

            def fin(sid):
                return next((at for command, stream, _, at in frames if command == 3 and stream == sid), None)

            def open_stream(sid, data=b'proof'):
                client.write(anytls_frame(1, sid=sid) + anytls_frame(2, target + data, sid))

            started = time.monotonic()
            if capacity:
                for sid in range(1, 129):
                    if mode == 'capacity-live':
                        open_stream(sid)
                    else:
                        client.write(anytls_frame(1, sid=sid))
                await client.drain()
                if mode == 'capacity-live':
                    await until(lambda: all(received(sid) == b'proof' for sid in range(1, 129)), 2)
                    assert len(fixture.connections) == 128
                client.write(anytls_frame(1, sid=129))
                await client.drain()
                await until(lambda: fin(129) is not None, 0.5)
                errors = [data for command, sid, data, _ in frames if command == 7 and sid == 129]
                assert bool(errors and errors[0]) == (version == 2), 'version-specific stream rejection missing'
                assert not closed.is_set(), 'capacity rejection closed existing streams'
                result['rejected_stream'] = 129
                if mode == 'capacity-live':
                    client.write(anytls_frame(2, b'-still-live', 128))
                    await client.drain()
                    await until(lambda: received(128) == b'proof-still-live')
                else:
                    client.write(anytls_frame(3, sid=1))
                    await client.drain()
                    before = sum(command == 9 for command, _, _, _ in frames)
                    if version == 2:
                        client.write(anytls_frame(8, sid=0))
                        await client.drain()
                        await until(lambda: sum(command == 9 for command, _, _, _ in frames) > before)
                    await asyncio.sleep(0.05)
                    assert fin(1) is None, 'remote FIN must not receive a FIN reply'
                    open_stream(130, b'new-slot')
                    await client.drain()
                    await until(lambda: received(130) == b'new-slot')
                    assert len(fixture.connections) == 1
                    result['released_slot_reused'] = True
            elif mode == 'prepared-survives':
                open_stream(1, b'before')
                await client.drain()
                await until(lambda: received(1) == b'before')
                await asyncio.sleep(1.35)
                client.write(anytls_frame(2, b'-after', 1))
                await client.drain()
                await until(lambda: received(1) == b'before-after')
                assert fin(1) is None and len(fixture.connections) == 1, 'header deadline escaped into relay'
                result['survived_handshake_budget'] = True
            else:
                client.write(anytls_frame(1, sid=1))
                if mode == 'half-address':
                    client.write(anytls_frame(2, target[:2], 1))
                elif mode == 'trickle':
                    client.write(anytls_frame(2, b'\3\x3f', 1))
                elif mode in ('uot1', 'uot2'):
                    magic = b'sp.udp-over-tcp.arpa' if mode == 'uot1' else b'sp.v2.udp-over-tcp.arpa'
                    client.write(anytls_frame(2, b'\3' + bytes([len(magic)]) + magic + b'\0\0', 1))
                await client.drain()
                await until(lambda: fin(1) is not None, 1.7)
                result['expired_seconds'] = round(fin(1) - started, 3)
                assert 0.7 <= result['expired_seconds'] <= 1.6, 'deadline moved with other frames or trickled bytes'
                assert not fixture.connections and not closed.is_set(), 'timed-out header reached a target or closed session'
                client.write(anytls_frame(2, target + b'late', 1))
                open_stream(2, b'new-stream')
                await client.drain()
                await until(lambda: received(2) == b'new-stream')
                assert len(fixture.connections) == 1 and fixture.connections[0]['bytes'] == b'new-stream'
            if version == 2:
                client.write(anytls_frame(8, sid=0))
                await client.drain()
                await until(lambda: any(command == 9 for command, _, _, _ in frames))
            assert not closed.is_set() and not any(command == 5 for command, _, _, _ in frames)
            assert not fixture.errors, fixture.errors
            result.update(passed=True, target_connections=len(fixture.connections),
                          heartbeats=sum(command == 9 for command, _, _, _ in frames), session_usable=True)
        except Exception as error:
            result.update(error=repr(error), target_connections=len(fixture.connections), session_closed=closed.is_set(),
                          fins=[sid for command, sid, _, _ in frames if command == 3],
                          heartbeats=sum(command == 9 for command, _, _, _ in frames))
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if client:
                client.transport.abort()
                try:
                    await client.wait_closed()
                except (ConnectionError, ssl.SSLError):
                    pass
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            panel.close()
            peer.close()
            await asyncio.gather(panel.wait_closed(), peer.wait_closed())
            await fixture.close()
    result['peer_errors'] = fixture.errors
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    modes = args.case or ['syn-only', 'half-address', 'trickle', 'uot1', 'uot2', 'prepared-survives',
                          'capacity-v1', 'capacity-v2', 'capacity-live']
    results = [await run_case(args.binary.resolve(), args.output.resolve() / mode, mode) for mode in modes]
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(x['passed'] for x in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

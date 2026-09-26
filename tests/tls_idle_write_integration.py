"""Keep a real TLS ciphertext write blocked across the idle-collection interval."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import socket

from anytls_fin_integration import Resources, Frames, REQUEST, configure, frame, target, tls_settings, available_port, until


async def main(args):
    args.output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    started = asyncio.Event()
    drained = asyncio.Event()
    data = bytes(range(256)) * (16 * 1024 * 1024 // 256)
    result = {'passed': False}

    async def backend(reader, writer):
        assert await reader.readexactly(len(REQUEST)) == REQUEST
        writer.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
        started.set()
        for offset in range(0, len(data), 65536):
            writer.write(data[offset:offset + 65536])
            await writer.drain()
        drained.set()
        await reader.read()

    try:
        backend_port = await resources.listen(backend)
        front_port = available_port()
        configure(args.output,
                  {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': front_port,
                   'settings': {'clients': [{'password': 'secret'}]}, 'streamSettings': tls_settings(True)},
                  {'protocol': 'freedom', 'settings': {}})
        config_file = args.output / 'config.json'
        config = json.loads(config_file.read_text())
        config['timeouts']['write'] = 30
        config['timeouts']['connIdle'] = 40
        config_file.write_text(json.dumps(config), encoding='utf-8')
        child = resources.spawn([args.binary, '--config-dir', args.output], args.output / 'child.log')
        reader, writer = await resources.connect(front_port, tls=True)
        sock = writer.get_extra_info('socket')
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        # Pause ciphertext reads, not only SSLProtocol's application delivery.
        raw_transport = writer.transport._ssl_protocol._transport
        raw_transport.pause_reading()
        writer.write(hashlib.sha256(b'secret').digest() + b'\0\0' + frame(4, payload=b'v=2')
                     + frame(1, 1) + frame(2, 1, target(backend_port) + REQUEST))
        await writer.drain()
        await asyncio.wait_for(started.wait(), 3)
        # Do not consume TLS application data. Cross the 10s Worker heap sweep
        # with backpressure still present, then demand exact byte recovery.
        await asyncio.sleep(12)
        result['blocked_across_collection'] = not drained.is_set()
        assert not drained.is_set(), 'fixture did not sustain write backpressure'
        assert child.poll() is None
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        raw_transport.resume_reading()
        received = Frames(resources, reader)
        await until(lambda: sum(len(p) for c, sid, p in received.values if c == 2 and sid == 1) >= len(data), timeout=15)
        recovered = received.payload(1)
        result['bytes'] = len(recovered)
        result['passed'] = recovered == data and child.poll() is None
        writer.write(frame(3, 1))
        await writer.drain()
    except Exception as error:
        result['error'] = repr(error)
    finally:
        await resources.close()
    result['peer_errors'] = resources.errors
    result['passed'] &= not resources.errors
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

"""Plaintext cnode -> official Xray stream-up interoperability.

Pass an unmodified Xray executable with --xray. This checks the current binary
only; it does not rerun the previously reported failing original version.
Reference behavior: Xray splithttp/dialer.go DisableKeepAlives and client.go
OpenStream's concurrent upload-response drain. Go net/http/server.go otherwise
drains an unfinished H1 request before flushing a response on a reusable socket.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from anytls_fin_integration import Resources, USER, available_port, configure


async def run(args):
    args.output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    result = {'passed': False, 'requests': [], 'backend_connections': 0}
    binary_hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in (args.binary, args.xray)}
    result['binaries'] = binary_hashes
    result['xray_version'] = subprocess.run(
        [str(args.xray), 'version'], check=True, capture_output=True, text=True).stdout
    observations = []

    async def backend(reader, writer):
        result['backend_connections'] += 1
        writer.write(b'ready')
        await writer.drain()
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()

    try:
        backend_port = await resources.listen(backend)
        xray_port = available_port()
        front_port = available_port()
        reference_config = {
            'log': {'loglevel': 'debug'},
            'inbounds': [{'listen': '127.0.0.1', 'port': xray_port, 'protocol': 'vless',
                          'settings': {'clients': [{'id': str(USER)}], 'decryption': 'none'},
                          'streamSettings': {'network': 'xhttp', 'security': 'none',
                                             'xhttpSettings': {'path': '/interop', 'mode': 'stream-up'}}}],
            'outbounds': [{'protocol': 'freedom',
                           'settings': {'finalRules': [{'action': 'allow'}]}}],
        }
        config_path = args.output / 'xray.json'
        config_path.write_text(json.dumps(reference_config), encoding='utf-8')
        resources.spawn([args.xray, 'run', '-config', config_path], args.output / 'xray.log')

        async def bridge(reader, writer):
            remote_reader, remote_writer = await resources.connect(xray_port)
            head = await reader.readuntil(b'\r\n\r\n')
            record = {'head': head.decode('latin1'), 'response_bytes': 0}
            result['requests'].append(record)
            remote_writer.write(head)
            await remote_writer.drain()

            async def copy(source, destination, count_response=False):
                while data := await source.read(65536):
                    if count_response:
                        record['response_bytes'] += len(data)
                    destination.write(data)
                    await destination.drain()
                destination.write_eof()

            try:
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(copy(reader, remote_writer))
                    tasks.create_task(copy(remote_reader, writer, True))
            except* ConnectionError:
                pass

        bridge_port = await resources.listen(bridge)
        configure(args.output,
                  {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
                   'settings': {'clients': [{'id': str(USER)}]}},
                  {'protocol': 'vless',
                   'settings': {'vnext': [{'address': '127.0.0.1', 'port': bridge_port,
                                           'users': [{'id': str(USER), 'encryption': 'none'}]}]},
                   'streamSettings': {'network': 'xhttp', 'security': 'none',
                                      'xhttpSettings': {'path': '/interop', 'mode': 'stream-up'}}})
        resources.spawn([args.binary, '--config-dir', args.output], args.output / 'cnode.log')

        async def exchange(index):
            reader, writer = await resources.connect(front_port)
            initial = f'initial-{index}'.encode()
            writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', backend_port)
                         + b'\1\x7f\0\0\1' + initial)
            await writer.drain()
            assert await reader.readexactly(2) == b'\0\0'
            assert await reader.readexactly(5) == b'ready'
            assert await reader.readexactly(len(initial)) == initial
            # The reference server's first upload-response padding flush must
            # not consume subsequent request chunks as keep-alive drain data.
            await asyncio.sleep(0.2)
            digest = hashlib.sha256()
            for number in range(8):
                payload = bytes([(index * 17 + number) % 256]) * 65536
                writer.write(payload)
                await writer.drain()
                echoed = await reader.readexactly(len(payload))
                assert echoed == payload
                digest.update(echoed)
            observations.append({'index': index, 'bytes': 8 * 65536,
                                 'sha256': digest.hexdigest()})
            writer.close()
            await writer.wait_closed()

        async with asyncio.timeout(25):
            await asyncio.gather(*(exchange(index) for index in range(4)))
        uploads = [record for record in result['requests'] if record['head'].startswith('POST ')]
        downloads = [record for record in result['requests'] if record['head'].startswith('GET ')]
        assert len(uploads) == len(downloads) == result['backend_connections'] == 4
        for record in uploads:
            assert '\r\nconnection: close\r\n' in record['head'].lower()
            assert record['response_bytes'] > 0, 'reference upload response was not observed'
        result['observations'] = observations
        result['passed'] = all(child.poll() is None for child in resources.children)
    except Exception as error:
        result['error'] = repr(error)
    finally:
        await resources.close()
    result['peer_errors'] = resources.errors
    result['passed'] &= not resources.errors
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == binary_hashes[str(path)]
               for path in (args.binary, args.xray))
    (args.output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('binary', 'xray', 'output'):
        parser.add_argument('--' + name, required=True, type=lambda value: Path(value).resolve())
    raise SystemExit(asyncio.run(run(parser.parse_args())))

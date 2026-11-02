"""Direct cnode/anytls-go interoperability through a counted TCP bridge."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from anytls_fin_integration import (
    Resources, USER, REQUEST, BANNER, REFERENCE_COMMIT,
    available_port, configure, target, tls_settings, observe_eof,
)


async def run_case(args, direction, mode, output):
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    accepted = 0
    backend_requests = []
    result = {'direction': direction, 'mode': mode, 'passed': False}
    response = (bytes(range(251)) * 1045)[:256 * 1024]

    async def backend(reader, writer):
        number = len(backend_requests)
        record = {'request': '', 'extra_bytes': 0, 'eof': False}
        backend_requests.append(record)
        record['request'] = (await reader.readexactly(len(REQUEST))).hex()
        assert record['request'] == REQUEST.hex()
        writer.write(BANNER)
        await writer.drain()
        if mode == 'local-eof' and number == 0:
            record['extra_bytes'] = len(await reader.read())
            record['eof'] = True
        else:
            writer.write(response)
            await writer.drain()

    try:
        backend_port = await resources.listen(backend)
        server_port = available_port()
        front_port = available_port()

        async def bridge(reader, writer):
            nonlocal accepted
            accepted += 1
            remote_reader, remote_writer = await resources.connect(server_port)

            async def copy(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
                destination.write_eof()

            try:
                async with asyncio.TaskGroup() as tasks:
                    tasks.create_task(copy(reader, remote_writer))
                    tasks.create_task(copy(remote_reader, writer))
            except* ConnectionError:
                pass

        bridge_port = await resources.listen(bridge)
        if direction == 'reference-client':
            configure(output,
                      {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': server_port,
                       'settings': {'clients': [{'password': 'secret'}]}, 'streamSettings': tls_settings(True)},
                      {'protocol': 'freedom', 'settings': {}})
            resources.spawn([args.binary, '--config-dir', output], output / 'cnode.log')
            resources.spawn([args.reference_client, '-l', f'127.0.0.1:{front_port}', '-s',
                             f'127.0.0.1:{bridge_port}', '-p', 'secret', '-m', '1'], output / 'reference.log')
        else:
            resources.spawn([args.reference_server, '-l', f'127.0.0.1:{server_port}', '-p', 'secret'],
                            output / 'reference.log')
            configure(output,
                      {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
                       'settings': {'clients': [{'id': str(USER)}]}},
                      {'protocol': 'anytls', 'settings': {'server': '127.0.0.1', 'server_port': bridge_port,
                       'password': 'secret', 'minIdleSession': 1}, 'streamSettings': tls_settings()})
            resources.spawn([args.binary, '--config-dir', output], output / 'cnode.log')

        observations = []
        for number in range(2):
            reader, writer = await resources.connect(front_port)
            if direction == 'reference-client':
                writer.write(b'\5\1\0')
                await writer.drain()
                assert await reader.readexactly(2) == b'\5\0'
                writer.write(b'\5\1\0' + target(backend_port))
                await writer.drain()
                reply = await reader.readexactly(4)
                assert reply[:2] == b'\5\0'
                await reader.readexactly({1: 6, 4: 18}[reply[3]])
                writer.write(REQUEST)
            else:
                writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', backend_port)
                             + b'\1\x7f\0\0\1' + REQUEST)
            await writer.drain()
            if direction != 'reference-client':
                assert await reader.readexactly(2) == b'\0\0'
            assert await reader.readexactly(len(BANNER)) == BANNER
            local_close = mode == 'local-eof' and number == 0
            if local_close:
                writer.write_eof()
            data, eof, seconds = await observe_eof(reader)
            expected = b'' if local_close else response
            observations.append({'eof': eof, 'seconds': seconds, 'bytes': len(data),
                                 'sha256': hashlib.sha256(data).hexdigest()})
            assert eof and data == expected
            if local_close:
                async with asyncio.timeout(1):
                    while not backend_requests[0]['eof']:
                        await asyncio.sleep(0.01)
                assert backend_requests[0]['extra_bytes'] == 0
            await asyncio.sleep(0.1)
        result.update(passed=accepted == 1 and len(backend_requests) == 2,
                      physical_connections=accepted, backend_requests=backend_requests, observations=observations)
    except Exception as error:
        result['error'] = repr(error)
    finally:
        result['children_alive_before_cleanup'] = all(c.poll() is None for c in resources.children)
        await resources.close()
    result['peer_errors'] = resources.errors
    result['passed'] &= not resources.errors and result['children_alive_before_cleanup']
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    binaries = [args.binary, args.reference_client, args.reference_server]
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in binaries}
    for kind, path in [('client', args.reference_client), ('server', args.reference_server)]:
        metadata = subprocess.run([str(args.go), 'version', '-m', str(path)], check=True,
                                  capture_output=True, text=True).stdout
        assert f'vcs.revision={REFERENCE_COMMIT}' in metadata and 'vcs.modified=false' in metadata
        assert f'path\tanytls/cmd/{kind}' in metadata
    results = []
    for direction in ('reference-client', 'reference-server'):
        for mode in ('remote-fin', 'local-eof'):
            results.append(await asyncio.wait_for(run_case(
                args, direction, mode, args.output / f'{direction}-{mode}'), 20))
    assert all(hashlib.sha256(path.read_bytes()).hexdigest() == hashes[str(path)] for path in binaries)
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    (args.output / 'binaries.json').write_text(json.dumps(hashes, indent=2), encoding='utf-8')
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('binary', 'reference-client', 'reference-server', 'output'):
        parser.add_argument('--' + name, required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--go', default='go')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

"""Real two-way Vision interoperability; no substitute protocol implementation.

Reference: https://github.com/XTLS/Xray-core/blob/
a4a3dff5b20c2faae567b742c172c7b95e75c083/proxy/proxy.go
Run after building both products:
python3 tests/vless_xray_interop.py --binary build/cnode --xray /path/to/xray \
    --output build/vless-xray-interop
TLS 1.3 exercises Xray's CommandPaddingDirect receive path, not just framing.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import ssl
import struct
import subprocess

from anytls_fin_integration import Resources, USER, CERTIFICATES, available_port, configure, target, tls_settings

REFERENCE_COMMIT = 'a4a3dff5b20c2faae567b742c172c7b95e75c083'
RELEASE_SHA256 = 'cc4b84d3069569f297a61f04b914f2bb37e9d202fd7b84cb50def1fc30fd40e1'


async def run_case(args, direction, mode, output):
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    request = bytes(range(251)) * 1045
    response = request[::-1]
    observations = []
    result = {'direction': direction, 'mode': mode, 'passed': False}

    async def backend(reader, writer):
        received = await reader.readexactly(len(request))
        assert received == request
        # Separate writes expose padding-end timing and post-command raw reads.
        for start, end in ((0, 1), (1, 899), (899, 900), (900, 8192), (8192, len(response))):
            writer.write(response[start:end])
            await writer.drain()
            await asyncio.sleep(0.005)
        observations.append(hashlib.sha256(received).hexdigest())

    try:
        backend_port = await resources.listen(backend, tls=mode != 'plain')
        server_port, front_port = available_port(), available_port()
        flow = 'xtls-rprx-vision'
        if direction == 'xray-client':
            configure(output,
                {'protocol': 'vless', 'listen': '127.0.0.1', 'port': server_port,
                 'settings': {'decryption': 'none', 'clients': [{'id': str(USER), 'flow': flow}]},
                 'streamSettings': tls_settings(True)},
                {'protocol': 'freedom', 'settings': {}})
            xray = {'inbounds': [{'listen': '127.0.0.1', 'port': front_port, 'protocol': 'socks',
                                  'settings': {'auth': 'noauth', 'udp': False}}],
                    'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{
                        'address': '127.0.0.1', 'port': server_port,
                        'users': [{'id': str(USER), 'encryption': 'none', 'flow': flow}]}]},
                        'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {
                            'serverName': 'localhost', 'certificates': [{'usage': 'verify',
                            'certificateFile': str(CERTIFICATES / 'cert.pem')}]}}}]}
        else:
            configure(output,
                {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
                 'settings': {'decryption': 'none', 'clients': [{'id': str(USER)}]}},
                {'protocol': 'vless', 'settings': {'address': '127.0.0.1', 'port': server_port,
                    'id': str(USER), 'encryption': 'none', 'flow': flow},
                    'streamSettings': tls_settings()})
            xray = {'inbounds': [{'listen': '127.0.0.1', 'port': server_port, 'protocol': 'vless',
                'settings': {'decryption': 'none', 'clients': [{'id': str(USER), 'flow': flow}]},
                'streamSettings': tls_settings(True)}], 'outbounds': [{'protocol': 'freedom',
                    'settings': {'finalRules': [{'action': 'allow'}]}}]}
        config_path = output / 'config.json'
        config = json.loads(config_path.read_text())
        config['workers'] = 4
        config_path.write_text(json.dumps(config))
        xray['log'] = {'loglevel': 'debug'}
        xray_path = output / 'xray.json'
        xray_path.write_text(json.dumps(xray))
        resources.spawn([args.xray, 'run', '-config', xray_path], output / 'xray.log')
        resources.spawn([args.binary, '--config-dir', output], output / 'cnode.log')
        for _ in range(2):
            reader, writer = await resources.connect(front_port)
            if direction == 'xray-client':
                writer.write(b'\5\1\0')
                await writer.drain()
                assert await reader.readexactly(2) == b'\5\0'
                writer.write(b'\5\1\0' + target(backend_port))
                await writer.drain()
                header = await reader.readexactly(4)
                assert header[:2] == b'\5\0'
                assert header[3] in (1, 4)
                await reader.readexactly(6 if header[3] == 1 else 18)
            else:
                writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', backend_port)
                             + b'\1\x7f\0\0\1')
                await writer.drain()
                # cnode emits its VLESS response on first target data. Start TLS
                # with a MemoryBIO below so that the response header is stripped
                # before any TLS record reaches the local TLS engine.
            if mode != 'plain':
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                version = ssl.TLSVersion.TLSv1_3 if mode == 'tls13' else ssl.TLSVersion.TLSv1_2
                context.minimum_version = context.maximum_version = version
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                engine = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname='localhost')
                response_header = direction == 'xray-server'

                async def flush():
                    while outgoing.pending:
                        writer.write(outgoing.read())
                    await writer.drain()

                async def feed():
                    nonlocal response_header
                    if response_header:
                        assert await reader.readexactly(2) == b'\0\0'
                        response_header = False
                    data = await reader.read(65536)
                    assert data, 'EOF inside inner TLS'
                    incoming.write(data)

                while True:
                    try:
                        engine.do_handshake()
                        await flush()
                        break
                    except ssl.SSLWantReadError:
                        await flush()
                        await feed()
                for offset in range(0, len(request), 8191):
                    engine.write(request[offset:offset + 8191])
                    await flush()
                received = bytearray()
                while len(received) < len(response):
                    try:
                        chunk = engine.read(len(response) - len(received))
                        assert chunk, 'inner TLS closed before complete response'
                        received.extend(chunk)
                    except ssl.SSLWantReadError:
                        await flush()
                        await feed()
                assert engine.version() == ('TLSv1.3' if mode == 'tls13' else 'TLSv1.2')
                while True:
                    try:
                        assert engine.read(65536) == b'', 'unexpected inner application data'
                        break
                    except ssl.SSLWantReadError:
                        await flush()
                        await feed()
                    except ssl.SSLZeroReturnError:
                        break
                assert incoming.pending == 0, 'extra records after inner close_notify'
                engine.unwrap()
                await flush()
            else:
                for offset in range(0, len(request), 8191):
                    writer.write(request[offset:offset + 8191])
                    await writer.drain()
                if direction == 'xray-server':
                    assert await reader.readexactly(2) == b'\0\0'
                received = await reader.readexactly(len(response))
            assert bytes(received) == response
            writer.write_eof()
            assert await reader.read() == b'', 'outer alert or trailing data leaked into inner stream'
            writer.close()
        assert len(observations) == 2
        result.update(passed=True, request_sha256=observations,
                      response_sha256=hashlib.sha256(response).hexdigest())
    except Exception as error:
        result['error'] = repr(error)
    finally:
        result['children_alive'] = all(child.poll() is None for child in resources.children)
        await resources.close()
    result['peer_errors'] = resources.errors
    result['passed'] &= not resources.errors and result['children_alive']
    (output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    metadata = subprocess.run([args.go, 'version', '-m', str(args.xray)], check=True,
                              capture_output=True, text=True).stdout
    binary_hash = hashlib.sha256(args.xray.read_bytes()).hexdigest()
    if binary_hash != RELEASE_SHA256:
        assert f'vcs.revision={REFERENCE_COMMIT}' in metadata, 'wrong Xray reference revision'
        assert 'vcs.modified=false' in metadata, 'reference source was modified'
    version = subprocess.run([str(args.xray), 'version'], check=True,
                             capture_output=True, text=True).stdout
    assert '26.10.31' in version and 'a4a3dff' in version, 'wrong Xray release'
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'xray-build.txt').write_text(metadata)
    hashes = {str(path): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in (args.binary, args.xray)}
    results = []
    for direction in ('xray-client', 'xray-server'):
        for mode in ('plain', 'tls12', 'tls13'):
            results.append(await asyncio.wait_for(run_case(args, direction, mode,
                args.output / f'{direction}-{mode}'), 40))
    assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == value for path, value in hashes.items())
    (args.output / 'binaries.json').write_text(json.dumps(hashes, indent=2))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2))
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('binary', 'xray', 'output'):
        parser.add_argument('--' + name, required=True, type=lambda value: Path(value).resolve())
    parser.add_argument('--go', default='go')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

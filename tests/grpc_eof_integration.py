"""EOF metadata crosses real protocol readers without adding protocol-aware relay."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import traceback

from anytls_fin_integration import (
    Resources, USER, REQUEST, available_port, configure, tls_settings,
    until, open_application, observe_eof,
)
from grpc_substream_integration import Peer, READY, ECHO, h2frame, grpc, vless


PAYLOAD = (bytes(range(251)) * 192)[:48001]


def grpc_transport(tls, server, raw=False):
    settings = tls_settings(server) if tls else {'security': 'none'}
    if raw:
        settings.update(network='h2', httpSettings={'path': '/fixture', 'method': 'POST'})
    else:
        settings.update(network='grpc', grpcSettings={'serviceName': 'fixture'})
    return settings


def protocol_settings(protocol, port=None):
    if protocol in ('vless', 'vmess'):
        settings = {'clients': [{'id': str(USER)}]} if port is None else {
            'server': '127.0.0.1', 'server_port': port, 'uuid': str(USER)}
    else:
        settings = {'password': 'fixture-secret'}
        if port is not None:
            settings.update(server='127.0.0.1', server_port=port)
        if protocol == 'shadowsocks':
            settings['method'] = 'aes-128-gcm'
    return settings


async def bridge(args, scenario, output, result, resources):
    protocol, security, empty_response = scenario
    requests = []
    observations = []
    response = b'' if empty_response else PAYLOAD

    async def destination(reader, writer):
        state = {'bytes': 0, 'eof': False}
        observations.append(state)
        data = bytearray()
        while chunk := await reader.read(65536):
            data.extend(chunk)
            state['bytes'] += len(chunk)
        state['eof'] = True
        requests.append(data)
        writer.write(response)
        await writer.drain()

    target_port = await resources.listen(destination)
    remote_port, front_port = available_port(), available_port()
    remote = output / 'remote'
    local = output / 'local'
    remote.mkdir()
    local.mkdir()
    configure(remote, {'protocol': protocol, 'listen': '127.0.0.1', 'port': remote_port,
        'settings': protocol_settings(protocol), 'streamSettings': grpc_transport(True, True)},
        {'protocol': 'freedom', 'settings': {}})
    outbound_settings = protocol_settings(protocol, remote_port)
    if security is not None:
        outbound_settings['security'] = security
    configure(local, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
        'settings': protocol_settings('vless'), 'streamSettings': grpc_transport(False, True)},
        {'protocol': protocol, 'settings': outbound_settings,
         'streamSettings': grpc_transport(True, False)})
    if args.debug:
        for folder in (remote, local):
            path = folder / 'config.json'
            config = json.loads(path.read_text())
            config['log']['loglevel'] = 'trace'
            path.write_text(json.dumps(config))
    resources.spawn([args.binary, '--config-dir', remote], remote / 'child.log')
    await until(lambda: 'server started' in (remote / 'child.log').read_text(), 6)
    resources.spawn([args.binary, '--config-dir', local], local / 'child.log')
    reader, writer = await resources.connect(front_port)
    writer.write(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + h2frame(4))
    await writer.drain()
    peer = Peer(resources, reader, writer)
    try:
        for sid in range(1, args.requests * 2, 2):
            await peer.open(sid, target_port, PAYLOAD, False, end=True)
            await peer.wait_message(sid, b'\0\0' + response)
            await until(lambda: peer.closed or any(kind == 1 and flags & 1 and stream_id == sid
                        for kind, flags, stream_id, _ in peer.frames), 5)
            assert not peer.closed and not peer.error
    finally:
        result['targets_before_cleanup'] = [dict(state) for state in observations]
    await peer.ping(b'eof-done')
    result.update(passed=requests == [PAYLOAD] * args.requests, requests=len(requests),
                  response_bytes=len(response),
                  payload_bytes=len(PAYLOAD), payload_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
                  same_front_connection=True, peer_frame_error=peer.error)


async def outbound(args, scenario, output, result, resources):
    tls, raw = scenario
    received = []

    async def server(reader, writer):
        assert await reader.readexactly(24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        peer = Peer(resources, reader, writer, raw=raw)
        writer.write(h2frame(4))
        await writer.drain()
        await until(lambda: peer.closed or any(kind == 1 for kind, _, _, _ in peer.frames))
        response_headers = b'\x88' if raw else b'\x88\0\x0ccontent-type\x10application/grpc'
        writer.write(h2frame(1, 4, 1, response_headers))
        await writer.drain()
        await peer.wait_message(1, vless(443, REQUEST))
        if raw:
            writer.write(h2frame(0, 1, 1, b'\0\0' + READY))
        else:
            writer.write(h2frame(0, 0, 1, grpc(b'\0\0' + READY)) +
                         h2frame(1, 5, 1, b'\0\x0bgrpc-status\x010'))
        await writer.drain()
        await peer.wait_message(1, vless(443, REQUEST) + ECHO)
        received.append(ECHO)
        await until(lambda: peer.closed, 5)
        assert not peer.error

    peer_port = await resources.listen(server, tls=tls)
    port = available_port()
    configure(output, {'protocol': 'vless', 'listen': '127.0.0.1', 'port': port,
                       'settings': protocol_settings('vless')},
              {'protocol': 'vless', 'settings': protocol_settings('vless', peer_port),
               'streamSettings': grpc_transport(tls, False, raw=raw)})
    resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
    reader, writer = await open_application(resources, port, False)
    data, eof, elapsed = await observe_eof(reader, 3)
    result.update(response_hex=data.hex(), eof=eof, eof_seconds=elapsed)
    assert data == READY and eof, 'response END_STREAM did not half-close the local write side'
    writer.write(ECHO)
    await writer.drain()
    await until(lambda: received == [ECHO], 5)
    writer.close()
    result.update(passed=True, upload_after_response_eof=len(ECHO))


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    cases = [('bridge-' + protocol, bridge, (protocol, None, False))
             for protocol in ('vless', 'vmess', 'trojan', 'shadowsocks')]
    cases += [('bridge-vmess-' + security, bridge, ('vmess', security, False))
              for security in ('chacha20-poly1305', 'none', 'zero')]
    cases += [('bridge-vmess-empty-response', bridge, ('vmess', None, True))]
    cases += [('outbound-tcp', outbound, (False, False)), ('outbound-tls', outbound, (True, False)),
              ('outbound-h2-tcp', outbound, (False, True)), ('outbound-h2-tls', outbound, (True, True))]
    results = []
    for name, scenario, value in cases:
        if args.case and name != args.case:
            continue
        output = args.output / name
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': name, 'passed': False}
        try:
            await asyncio.wait_for(scenario(args, value, output, result, resources), 20)
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
    return 0 if all(value['passed'] for value in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--case')
    parser.add_argument('--requests', type=int, default=8)
    parser.add_argument('--debug', action='store_true')
    raise SystemExit(asyncio.run(main(parser.parse_args())))

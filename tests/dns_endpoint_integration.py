"""Exercise normalized DNS endpoints through real VLESS -> Freedom requests."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import socket
import struct

from anytls_fin_integration import Resources, USER, REQUEST, BANNER, available_port, configure


class Resolver(asyncio.DatagramProtocol):
    def __init__(self, reject=False):
        self.reject = reject
        self.queries = []
        self.errors = []
        self.closed = asyncio.Event()

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, error):
        if error:
            self.errors.append(repr(error))
        self.closed.set()

    def error_received(self, error):
        self.errors.append(repr(error))

    def datagram_received(self, data, sender):
        try:
            pos = 12
            labels = []
            while data[pos]:
                size = data[pos]
                labels.append(data[pos + 1:pos + 1 + size].decode('ascii'))
                pos += size + 1
            pos += 1
            kind, cls = struct.unpack('!HH', data[pos:pos + 4])
            assert cls == 1 and kind in (1, 28)
            self.queries.append({'name': '.'.join(labels), 'type': kind})
            answer = b''
            if not self.reject and kind == 1:
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 30, 4) + socket.inet_aton('127.0.0.1')
            header = data[:2] + struct.pack('!HHHHH', 0x8182 if self.reject else 0x8180,
                                          1, bool(answer), 0, 0)
            self.transport.sendto(header + data[12:pos + 4] + answer, sender)
        except Exception as error:
            self.errors.append(repr(error))


async def run_case(args, mode):
    output = args.output / mode
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    resolvers = []
    transports = []
    result = {'mode': mode, 'passed': False}
    backend_requests = []

    async def backend(reader, writer):
        backend_requests.append(await reader.readexactly(len(REQUEST)))
        writer.write(BANNER)
        await writer.drain()

    try:
        host = '::1' if mode == 'ipv6' else '127.0.0.1'
        servers = []
        for rejected in ([True, False] if mode == 'fallback-same-address' else [False]):
            resolver = Resolver(rejected)
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda resolver=resolver: resolver, local_addr=(host, 0))
            resolvers.append(resolver)
            transports.append(transport)
            port = transport.get_extra_info('sockname')[1]
            servers.append(f'[{host}]:{port}' if ':' in host else f'{host}:{port}')
        backend_port = await resources.listen(backend)
        front_port = available_port()
        configure(output,
                  {'protocol': 'vless', 'listen': '127.0.0.1', 'port': front_port,
                   'settings': {'clients': [{'id': str(USER)}]}},
                  {'protocol': 'freedom', 'settings': {}})
        config_path = output / 'config.json'
        config = json.loads(config_path.read_text())
        config['workers'] = 2
        config['dns'] = {'servers': servers, 'timeout': 1, 'minTTL': 1, 'maxTTL': 30}
        config_path.write_text(json.dumps(config), encoding='utf-8')
        resources.spawn([args.binary, '--config-dir', output], output / 'child.log')
        domain = (mode + '.endpoint.test').encode()
        query_counts = []
        for _ in range(2):
            reader, writer = await resources.connect(front_port)
            writer.write(b'\0' + USER.bytes + b'\0\1' + struct.pack('!H', backend_port)
                         + b'\2' + bytes([len(domain)]) + domain + REQUEST)
            await writer.drain()
            assert await asyncio.wait_for(reader.readexactly(2 + len(BANNER)), 5) == b'\0\0' + BANNER
            query_counts.append(sum(len(resolver.queries) for resolver in resolvers))
            writer.transport.abort()
            await asyncio.sleep(0.05)
        assert all(resolver.queries for resolver in resolvers)
        assert all(query['name'] == domain.decode() for resolver in resolvers for query in resolver.queries)
        result.update(passed=backend_requests == [REQUEST, REQUEST] and query_counts[0] == query_counts[1],
                      servers=servers, queries=[resolver.queries for resolver in resolvers],
                      query_counts=query_counts, backend_connections=len(backend_requests))
    except Exception as error:
        result['error'] = repr(error)
    finally:
        result.setdefault('queries', [resolver.queries for resolver in resolvers])
        result.setdefault('backend_connections', len(backend_requests))
        result['children_alive_before_cleanup'] = all(c.poll() is None for c in resources.children)
        await resources.close()
        for transport in transports:
            transport.close()
        await asyncio.gather(*(resolver.closed.wait() for resolver in resolvers))
    result['peer_errors'] = resources.errors + [error for resolver in resolvers for error in resolver.errors]
    result['passed'] &= not result['peer_errors'] and result['children_alive_before_cleanup']
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = [await run_case(args, mode) for mode in ('ipv4', 'ipv6', 'fallback-same-address')]
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    (args.output / 'binary.sha256').write_text(digest + '\n', encoding='ascii')
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

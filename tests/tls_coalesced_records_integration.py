"""Two distinct TLS records in one TCP write must not await a new socket edge."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import ssl
from anytls_fin_integration import Resources, Frames, available_port, configure, frame, tls_settings, until


class Client:
    def __init__(self, reader, writer):
        self.reader, self.writer = reader, writer
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.secured = context.wrap_bio(self.incoming, self.outgoing, server_hostname='localhost')

    async def feed(self):
        self.writer.write(self.outgoing.read())
        await self.writer.drain()
        data = await self.reader.read(65536)
        if not data:
            raise asyncio.IncompleteReadError(b'', 1)
        self.incoming.write(data)

    async def handshake(self):
        while True:
            try:
                self.secured.do_handshake()
                break
            except ssl.SSLWantReadError:
                await self.feed()
        self.writer.write(self.outgoing.read())
        await self.writer.drain()

    def records(self, *payloads):
        # A separate SSL_write per payload creates separate TLS records, then
        # one socket write makes ciphertext coalescing deterministic.
        for payload in payloads:
            assert self.secured.write(payload) == len(payload)
        self.writer.write(self.outgoing.read())

    async def readexactly(self, length):
        data = bytearray()
        while len(data) < length:
            try:
                chunk = self.secured.read(length - len(data))
                if not chunk:
                    raise asyncio.IncompleteReadError(bytes(data), length)
                data.extend(chunk)
            except ssl.SSLWantReadError:
                await self.feed()
        return bytes(data)


async def main(args):
    args.output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    result = {'passed': False}
    try:
        port = available_port()
        configure(args.output,
                  {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': port,
                   'settings': {'clients': [{'password': 'secret'}]}, 'streamSettings': tls_settings(True)},
                  {'protocol': 'freedom', 'settings': {}})
        child = resources.spawn([args.binary, '--config-dir', args.output], args.output / 'child.log')
        reader, writer = await resources.connect(port)
        client = Client(reader, writer)
        async with asyncio.timeout(5):
            await client.handshake()
        received = Frames(resources, client)
        client.records(hashlib.sha256(b'secret').digest() + b'\0\0' + frame(4, payload=b'v=2'))
        await until(lambda: received.count(10) == 1)
        for phase, delay in [('active', 0), ('after-idle', 12)]:
            await asyncio.sleep(delay)
            result['phase'] = phase
            before = received.count(9)
            client.records(frame(8), frame(8))
            await until(lambda: received.count(9) == before + 2)
        result['passed'] = not received.closed and child.poll() is None
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
    parser.add_argument('--binary', required=True, type=lambda p: Path(p).resolve())
    parser.add_argument('--output', required=True, type=lambda p: Path(p).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

"""TLS wire proxy: fragment the first ClientHello record without changing its transcript."""
import asyncio


class FragmentingProxy:
    def __init__(self, target_port):
        self.target_port = target_port
        self.tasks = set()
        self.errors = []
        self.fragmented = 0
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self.handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        remote_writer = None
        try:
            remote_reader, remote_writer = await asyncio.open_connection("127.0.0.1", self.target_port)
            header = await asyncio.wait_for(reader.readexactly(5), 5)
            assert header[0] == 22, header
            body = await asyncio.wait_for(reader.readexactly(int.from_bytes(header[3:], "big")), 5)
            assert body[0] == 1, body[:4]
            offset = 0
            for limit in (1, 2, 3, 17, 127, 511, len(body)):
                part = body[offset:offset + limit]
                if not part:
                    break
                wire = header[:3] + len(part).to_bytes(2, "big") + part
                # First-byte and partial-header reads are deterministic even
                # when TCP joins later writes; separate records always remain.
                for byte in wire[:5]:
                    remote_writer.write(bytes([byte]))
                    await remote_writer.drain()
                    await asyncio.sleep(0.002)
                remote_writer.write(wire[5:])
                await remote_writer.drain()
                offset += len(part)
            assert offset == len(body)
            self.fragmented += 1

            async def pump(source, dest):
                while data := await source.read(65536):
                    dest.write(data)
                    await dest.drain()
                if dest.can_write_eof():
                    dest.write_eof()
            await asyncio.gather(pump(reader, remote_writer), pump(remote_reader, writer))
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.errors.append(repr(error))
        finally:
            for stream in (writer, remote_writer):
                if stream:
                    stream.close()
                    try:
                        await stream.wait_closed()
                    except ConnectionError:
                        pass
            self.tasks.discard(task)

    async def close(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)

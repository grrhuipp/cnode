"""HTTPUpgrade byte-stream regression: pending bytes, forwarding and EOF."""
import argparse
import asyncio
import json
from pathlib import Path
import struct

from anytls_fin_integration import Resources, USER, available_port, tls_settings, until

PAYLOAD = bytes(range(251)) * 719
UPGRADE = (b"GET /up HTTP/1.1\r\nHost: localhost\r\n"
           b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n")


def transport(tls=False, server=False):
    settings = tls_settings(server) if tls else {"security": "none"}
    return dict(settings, network="httpupgrade",
                httpupgradeSettings={"path": "/up", "host": "localhost"})


async def run(binary, output, mode):
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    observations = []
    try:
        async def echo(reader, writer):
            data = await reader.readexactly(len(PAYLOAD))
            assert data == PAYLOAD, "target received corrupted or reordered data"
            writer.write(data)
            await writer.drain()
            writer.write_eof()
            assert await reader.read() == b"", "extra target data after payload"
            observations.append({"bytes": len(data), "eof": True})

        target_port = await resources.listen(echo)
        upgrade_port, raw_port = available_port(), available_port()
        while raw_port == upgrade_port:
            raw_port = available_port()
        tls = mode == "chain-tls"
        inbound = {"protocol": "vless", "listen": "127.0.0.1",
                   "settings": {"clients": [{"id": str(USER)}]},
                   "sniffing": {"enabled": False}}
        values = {
            "config.json": {"workers": 1,
                "timeouts": {"handshake": 5, "connIdle": 10, "write": 5,
                             "uplinkOnly": 2, "downlinkOnly": 2},
                "log": {"enable": False, "logDir": (output / "logs").as_posix()}},
            "inbounds.json": [
                dict(inbound, tag="upgrade", port=upgrade_port, outboundTag="direct",
                     streamSettings=transport(tls, True)),
                dict(inbound, tag="raw", port=raw_port, outboundTag="next")],
            "outbounds.json": [
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "next", "protocol": "vless",
                 "settings": {"address": "127.0.0.1", "port": upgrade_port,
                              "id": str(USER), "encryption": "none"},
                 "streamSettings": transport(tls)}],
            "routing.json": {"rules": []},
        }
        for name, value in values.items():
            (output / name).write_text(json.dumps(value), encoding="utf-8")
        child = resources.spawn([binary, "--config-dir", output], output / "child.log")
        await until(lambda: child.poll() is not None or "server started" in
                    (output / "child.log").read_text(encoding="utf-8", errors="replace"), 10)
        assert child.poll() is None, (output / "child.log").read_text(
            encoding="utf-8", errors="replace")
        reader, writer = await resources.connect(raw_port if mode.startswith("chain") else upgrade_port)
        request = (b"\0" + USER.bytes + b"\0\1" + struct.pack("!H", target_port)
                   + b"\1\x7f\0\0\1")
        async with asyncio.timeout(10):
            if mode == "coalesced":
                writer.write(UPGRADE + request + PAYLOAD[:1024])
            elif mode == "fragmented":
                for part in (UPGRADE[:13], UPGRADE[13:-2], UPGRADE[-2:]):
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(0.02)
                response = await reader.readuntil(b"\r\n\r\n")
                assert response.startswith(b"HTTP/1.1 101 "), response
                writer.write(request + PAYLOAD[:1024])
            else:
                writer.write(request + PAYLOAD[:1024])
            await writer.drain()
            if mode == "coalesced":
                response = await reader.readuntil(b"\r\n\r\n")
                assert response.startswith(b"HTTP/1.1 101 "), response
            for offset in range(1024, len(PAYLOAD), 16381):
                writer.write(PAYLOAD[offset:offset + 16381])
                await writer.drain()
            writer.write_eof()
            assert await reader.readexactly(2) == b"\0\0", "invalid VLESS response header"
            assert await reader.readexactly(len(PAYLOAD)) == PAYLOAD, "truncated download"
            assert await reader.read() == b"", "download direction did not reach EOF"
            writer.close()
            await writer.wait_closed()
            await until(lambda: len(observations) == 1)
            assert child.poll() is None, "product exited during forwarding"
        result = {"mode": mode, "bytes": len(PAYLOAD), "target": observations,
                  "product_alive": True}
    finally:
        await resources.close()
    assert not resources.errors, resources.errors
    (output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


async def main(binary, output):
    results = []
    for mode in ("coalesced", "fragmented", "chain", "chain-tls"):
        results.append(await run(binary.resolve(), output.resolve() / mode, mode))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

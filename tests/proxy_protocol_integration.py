"""PROXY off/auto/on: header detection, default auto and fail-closed malformed input."""
import argparse
import asyncio
import json
from pathlib import Path
import struct

from anytls_fin_integration import Resources, USER, available_port, until

SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"
PAYLOAD = b"proxy-mode-boundary"


async def run(binary, output):
    output.mkdir(parents=True, exist_ok=True)
    resources = Resources()
    observations = []
    diagnostics = output / "error.log"
    previous_size = diagnostics.stat().st_size if diagnostics.exists() else 0
    closed_probes = []
    try:
        async def echo(reader, writer):
            data = await reader.readexactly(len(PAYLOAD))
            assert data == PAYLOAD
            writer.write(data)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        target = await resources.listen(echo)
        ports = set()
        while len(ports) < 4:
            ports.add(available_port())
        required, disabled, automatic, default = sorted(ports)
        inbound = {"protocol": "vless", "listen": "127.0.0.1",
                   "settings": {"clients": [{"id": str(USER)}]},
                   "sniffing": {"enabled": False}, "outboundTag": "direct"}
        config = {
            "config.json": {"workers": 2,
                            "timeouts": {"handshake": 2, "connIdle": 5},
                            "log": {"loglevel": "info", "logDir": str(output),
                                    "access": "access.log", "error": "error.log",
                                    "rotateDaily": False, "gzip": False}},
            "inbounds.json": [dict(inbound, tag="required", port=required, proxyProtocol="on"),
                              dict(inbound, tag="disabled", port=disabled, proxyProtocol="off"),
                              dict(inbound, tag="automatic", port=automatic, proxyProtocol="auto"),
                              dict(inbound, tag="default", port=default)],
            "outbounds.json": [{"tag": "direct", "protocol": "freedom"}],
            "routing.json": {"rules": []},
        }
        for name, value in config.items():
            (output / name).write_text(json.dumps(value), encoding="utf-8")
        child = resources.spawn([binary, "--config-dir", output], output / "child.log")
        await until(lambda: child.poll() is not None or "server started" in
                    (output / "child.log").read_text(encoding="utf-8", errors="replace"), 10)
        assert child.poll() is None, (output / "child.log").read_text(errors="replace")
        request = (b"\0" + USER.bytes + b"\0\1" + struct.pack("!H", target) +
                   b"\1\x7f\0\0\1" + PAYLOAD)
        v1 = b"PROXY TCP4 192.0.2.1 198.51.100.1 32100 443\r\n"
        v2 = SIGNATURE + b"\x21\x11\x00\x0c" + bytes([192, 0, 2, 1, 198, 51, 100, 1]) + struct.pack("!HH", 32100, 443)
        for name, port, prefix, fragmented in (
            ("disabled-plain", disabled, b"", False),
            ("required-v1", required, v1, False),
            ("required-v1-fragmented", required, v1, True),
            ("required-v2", required, v2, False),
            ("required-v2-fragmented", required, v2, True),
            ("required-v1-unknown", required, b"PROXY UNKNOWN\r\n", False),
            ("required-v2-local", required, SIGNATURE + b"\x20\x00\x00\x00", False),
            ("auto-plain", automatic, b"", False),
            ("auto-v1", automatic, v1, False),
            ("auto-v2-fragmented", automatic, v2, True),
            ("default-plain", default, b"", False),
            ("default-v1-fragmented", default, v1, True),
            ("default-v2", default, v2, False),
        ):
            async with asyncio.timeout(5):
                reader, writer = await resources.connect(port)
                if fragmented:
                    for byte in prefix:
                        writer.write(bytes([byte]))
                        await writer.drain()
                        await asyncio.sleep(0.001)
                    writer.write(request)
                else:
                    writer.write(prefix + request)
                await writer.drain()
                assert await reader.readexactly(2) == b"\0\0", name
                assert await reader.readexactly(len(PAYLOAD)) == PAYLOAD, name
                writer.close()
                await writer.wait_closed()
                observations.append({"case": name, "accepted": True})
        for name, port, wire in (
            ("required-missing", required, request),
            ("required-invalid", required, b"PROXY TCP4 invalid 198.51.100.1 1 2\r\n" + request),
            ("disabled-proxy-not-sniffed", disabled, v1 + request),
            ("auto-invalid", automatic, b"PROXY TCP4 invalid 198.51.100.1 1 2\r\n" + request),
            ("default-invalid", default, SIGNATURE + b"\x21\x11\x00\x01x"),
        ):
            async with asyncio.timeout(5):
                reader, writer = await resources.connect(port)
                writer.write(wire)
                await writer.drain()
                try:
                    assert await reader.read() == b"", name
                except ConnectionResetError:
                    pass
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionResetError:
                    pass
                observations.append({"case": name, "accepted": False})
        for truncated in (False, True):
            async with asyncio.timeout(5):
                reader, writer = await resources.connect(automatic)
                source_port = writer.get_extra_info("sockname")[1]
                closed_probes.append((source_port, truncated))
                if truncated:
                    writer.write(b"PROX")
                    await writer.drain()
                writer.write_eof()
                try:
                    assert await reader.read() == b""
                except ConnectionResetError:
                    pass
                writer.close()
                try:
                    await writer.wait_closed()
                except ConnectionResetError:
                    pass
                observations.append({"case": "auto-truncated" if truncated else "auto-empty-eof",
                                     "accepted": False})
        assert child.poll() is None, "product exited during PROXY boundary smoke"
    finally:
        await resources.close()
    assert not resources.errors, resources.errors
    error_lines = diagnostics.read_bytes()[previous_size:].decode().splitlines()
    for source_port, truncated in closed_probes:
        warnings = [line for line in error_lines if "[Warning]" in line and
                    f"127.0.0.1:{source_port}" in line]
        assert len(warnings) == int(truncated), (
            "empty EOF must be quiet; a truncated PROXY prefix must remain diagnosable", warnings)
    (output / "result.json").write_text(json.dumps(observations, indent=2), encoding="utf-8")
    print(json.dumps(observations, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(run(args.binary.resolve(), args.output.resolve()))

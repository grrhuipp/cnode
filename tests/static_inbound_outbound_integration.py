"""Verify static inbound forced selection and routed fallback via real VLESS requests."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import uuid

USER = uuid.UUID("11111111-1111-4111-8111-111111111111")
PAYLOAD = b"static-inbound-forced-outbound"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def configs(forced_port, routed_port, inbound_overrides=None):
    forced = {
        "tag": "forced", "protocol": "vless", "listen": "127.0.0.1",
        "port": forced_port, "outboundTag": "chosen",
        "settings": {"clients": [{"id": str(USER)}]},
    }
    if inbound_overrides:
        forced.update(inbound_overrides)
    routed = dict(forced, tag="routed", port=routed_port)
    routed.pop("outboundTag", None)
    return {
        "config.json": {"workers": 1, "log": {"enable": False}},
        "inbounds.json": [forced, routed],
        "outbounds.json": [{"tag": "chosen", "protocol": "freedom"}],
        "routing.json": {"rules": [{"type": "field", "inboundTag": ["forced", "routed"], "outboundTag": "blackhole"}]},
    }


def write_configs(root, values):
    root.mkdir(parents=True, exist_ok=True)
    values["config.json"].setdefault("log", {})["logDir"] = str(root / "logs")
    for name, value in values.items():
        (root / name).write_text(json.dumps(value), encoding="utf-8")


def reject_config(binary, root, overrides, reason):
    write_configs(root, configs(free_port(), free_port(), overrides))
    result = subprocess.run(
        [str(binary), "--config-dir", str(root)], capture_output=True,
        text=True, timeout=5,
    )
    assert result.returncode != 0, f"invalid config accepted: {overrides}"
    recorded = result.stdout + result.stderr
    for log in (root / "logs").glob("error*.log"):
        recorded += log.read_text(encoding="utf-8", errors="replace")
    assert reason in recorded, f"missing {reason!r}: {recorded}"


async def probe(port, destination_port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(
            b"\0" + USER.bytes + b"\0\1" +
            struct.pack("!H", destination_port) + b"\1\x7f\0\0\1" + PAYLOAD
        )
        await writer.drain()
        return await asyncio.wait_for(reader.readexactly(2 + len(PAYLOAD)), 5)
    finally:
        writer.close()
        await writer.wait_closed()


async def main(binary, root):
    binary = binary.resolve()
    root = root.resolve()
    forced_port, routed_port = free_port(), free_port()
    while routed_port == forced_port:
        routed_port = free_port()
    write_configs(root / "live", configs(forced_port, routed_port))

    received = []

    async def echo(reader, writer):
        try:
            data = await reader.readexactly(len(PAYLOAD))
            received.append(data)
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    destination_port = server.sockets[0].getsockname()[1]
    with (root / "live" / "child.log").open("w", encoding="utf-8") as logfile:
        child = subprocess.Popen(
            [str(binary), "--config-dir", str(root / "live")],
            stdout=logfile, stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        try:
            deadline = time.monotonic() + 10
            while "server started" not in (root / "live" / "child.log").read_text(
                encoding="utf-8", errors="replace"
            ):
                assert child.poll() is None and time.monotonic() < deadline, (
                    root / "live" / "child.log"
                ).read_text(encoding="utf-8", errors="replace")
                await asyncio.sleep(0.05)
            assert await probe(forced_port, destination_port) == b"\0\0" + PAYLOAD
            assert received == [PAYLOAD]
            try:
                assert await probe(routed_port, destination_port) != b"\0\0" + PAYLOAD
            except (TimeoutError, asyncio.IncompleteReadError):
                pass  # A silent blackhole may leave the inbound request open.
            await asyncio.sleep(0.1)
            assert received == [PAYLOAD], "unforced inbound bypassed the blackhole rule"
        finally:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
            server.close()
            await server.wait_closed()

    for index, (overrides, message) in enumerate((
        ({"outboundTag": "missing"}, "references unknown outboundTag"),
        ({"outboundTag": ""}, "outboundTag must not be empty"),
        ({"outboundTag": 3}, "outboundTag"),
        ({"routingEnabled": False}, "routingEnabled is removed"),
        ({"outbound_tag": "chosen"}, "must use outboundTag"),
        ({"outbound": "chosen"}, "must use outboundTag"),
    )):
        reject_config(binary, root / f"rejected-{index}", overrides, message)
    print("static inbound forced outbound bypasses routing; unconfigured inbound follows rules")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

"""Verify forwarding, routing and case-insensitive local keys without changing values."""
import argparse
import asyncio
import json
from pathlib import Path
import socket
import struct
import subprocess
import time
import uuid

from initial_payload_integration import run_case as run_payload_case

USER = uuid.UUID("11111111-1111-4111-8111-111111111111")
PAYLOAD = b"static-inbound-forced-outbound"


_USED_PORTS: set[int] = set()


def free_port():
    held = []
    try:
        while True:
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            if port not in _USED_PORTS:
                _USED_PORTS.add(port)
                sock.close()
                return port
            held.append(sock)
    finally:
        for sock in held:
            sock.close()


def configs(default_port, forced_port, routed_port, inbound_overrides=None):
    default_inbound = {
        "tag": "default-direct", "protocol": "vless", "listen": "127.0.0.1",
        "port": default_port,
        "settings": {"clients": [{"id": str(USER)}]},
    }
    forced = dict(
        default_inbound,
        tag="forced",
        port=forced_port,
        routingEnabled=True,
        outboundTag="Chosen",
    )
    if inbound_overrides:
        forced.update(inbound_overrides)
    routed = dict(default_inbound, tag="routed", port=routed_port, routingEnabled=True)
    return {
        "config.json": {"workers": 1, "log": {"enable": False}},
        "inbounds.json": [default_inbound, forced, routed],
        "outbounds.json": [{"tag": "Chosen", "protocol": "freedom"},
                           {"tag": "chosen", "protocol": "blackhole"}],
        "routing.json": {"rules": [{"type": "field", "inboundTag": ["default-direct", "forced", "routed"], "outboundTag": "blackhole"}]},
    }


def mixed_case_keys(value):
    if isinstance(value, dict):
        return {
            "".join(char.upper() if index % 2 == 0 else char.lower()
                    for index, char in enumerate(key)): mixed_case_keys(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [mixed_case_keys(item) for item in value]
    return value


def write_configs(root, values, mixed_case=False):
    root.mkdir(parents=True, exist_ok=True)
    values["config.json"].setdefault("log", {})["logDir"] = str(root / "CaseSensitiveLogs")
    if mixed_case:
        values["config.json"]["log"]["enable"] = True
    for name, value in values.items():
        if mixed_case:
            value = mixed_case_keys(value)
        (root / name).write_text(json.dumps(value), encoding="utf-8")


def reject_config(binary, root, overrides, reason):
    write_configs(root, configs(free_port(), free_port(), free_port(), overrides))
    result = subprocess.run(
        [str(binary), "--config-dir", str(root)], capture_output=True,
        text=True, timeout=5,
    )
    assert result.returncode > 0, (
        f"expected rejection ({reason}), got {result.returncode}: {overrides}\n"
        f"{result.stdout}\n{result.stderr}"
    )


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


async def run_live(binary, root, mixed_case=False):
    ports = set()
    while len(ports) < 3:
        ports.add(free_port())
    default_port, forced_port, routed_port = tuple(ports)
    write_configs(root / "live", configs(default_port, forced_port, routed_port), mixed_case)
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
            ([str(binary), "--config-file", str(root / "live" / "config.json")]
             if mixed_case else [str(binary), "--config-dir", str(root / "live")]),
            stdout=logfile, stderr=subprocess.STDOUT,
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
            assert await probe(default_port, destination_port) == b"\0\0" + PAYLOAD
            assert await probe(forced_port, destination_port) == b"\0\0" + PAYLOAD
            assert received == [PAYLOAD, PAYLOAD]
            try:
                assert await probe(routed_port, destination_port) != b"\0\0" + PAYLOAD
            except (TimeoutError, asyncio.IncompleteReadError):
                pass  # A silent blackhole may leave the inbound request open.
            await asyncio.sleep(0.1)
            assert received == [PAYLOAD, PAYLOAD], "routed inbound bypassed the blackhole rule"
            if mixed_case:
                # Inspect actual directory spelling even on case-insensitive filesystems.
                assert "CaseSensitiveLogs" in {entry.name for entry in (root / "live").iterdir()}
                assert any((root / "live" / "CaseSensitiveLogs").glob("*.log"))
        finally:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
            server.close()
            await server.wait_closed()



async def main(binary, root):
    binary, root = binary.resolve(), root.resolve()
    await run_live(binary, root / "canonical")
    await run_live(binary, root / "mixed-case", mixed_case=True)
    credentials = await run_payload_case(
        binary, root / "mixed-case-password", "trojan", 17, key_transform=mixed_case_keys,
    )
    assert credentials["passed"], credentials
    for index, (overrides, message) in enumerate((
        ({"outboundTag": "missing"}, "references unknown outboundTag"),
        ({"outboundTag": ""}, "outboundTag must not be empty"),
        ({"outboundTag": 3}, "outboundTag"),
        ({"routingEnabled": "true"}, "routingEnabled"),
        ({"routing_enabled": True}, "must use routingEnabled"),
        ({"outbound_tag": "chosen"}, "must use outboundTag"),
        ({"outbound": "chosen"}, "must use outboundTag"),
    )):
        reject_config(binary, root / f"rejected-{index}", overrides, message)
    print("static inbound defaults to direct; routingEnabled enables routing; outboundTag forces outbound")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

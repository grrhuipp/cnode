"""Real VLESS -> freedom TCP dials verify ordered source binding and fallback."""
import argparse
import asyncio
from pathlib import Path
import socket
import struct
import subprocess
import time

from static_inbound_outbound_integration import PAYLOAD, USER, free_port, probe, write_configs


class DualStackDns(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, query, peer):
        end = 12
        while query[end]:
            end += query[end] + 1
        end += 1
        kind = int.from_bytes(query[end:end + 2], "big")
        data = b"\0" * 15 + b"\1" if kind == 28 else b"\x7f\0\0\1"
        header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 60, len(data)) + data
        self.transport.sendto(header + query[12:end + 4] + answer, peer)


async def probe_domain(port, destination_port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    domain = b"dual.test"
    try:
        writer.write(
            b"\0" + USER.bytes + b"\0\1" + struct.pack("!H", destination_port) +
            bytes([2, len(domain)]) + domain + PAYLOAD
        )
        await writer.drain()
        return await asyncio.wait_for(reader.readexactly(2 + len(PAYLOAD)), 12)
    finally:
        writer.close()
        await writer.wait_closed()


def make_configs(inbound_port, addresses, strategy):
    return {
        "config.json": {"workers": 1, "log": {"enable": False}},
        "inbounds.json": [{
            "tag": "probe", "protocol": "vless", "listen": "127.0.0.1",
            "port": inbound_port, "outboundTag": "chosen",
            "settings": {"clients": [{"id": str(USER)}]},
        }],
        "outbounds.json": [{
            "tag": "chosen", "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv6v4"},
            "sendThrough": addresses, "sendThroughStrategy": strategy,
        }],
    }


async def run_case(binary, root, addresses, strategy, succeeds, *, domain=False):
    inbound_port = free_port()
    values = make_configs(inbound_port, addresses, strategy)
    dns_socket = None
    if domain:
        loop = asyncio.get_running_loop()
        dns_socket, _ = await loop.create_datagram_endpoint(
            DualStackDns, local_addr=("127.0.0.1", 0)
        )
        values["config.json"]["dns"] = {
            "servers": [f"127.0.0.1:{dns_socket.get_extra_info('sockname')[1]}"],
            "timeout": 5,
        }
    write_configs(root, values)
    received = []

    async def echo(reader, writer):
        received.append(writer.get_extra_info("peername")[0])
        try:
            data = await reader.readexactly(len(PAYLOAD))
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    refused_v6 = None
    for attempt in range(20):
        server = await asyncio.start_server(echo, "127.0.0.1", 0)
        destination_port = server.sockets[0].getsockname()[1]
        if not domain:
            break
        # Own the IPv6 port without listening. An unreserved ephemeral port
        # could belong to another test, or become the outbound socket's own
        # source port (a loopback TCP self-connection rather than refusal).
        refused_v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        refused_v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        try:
            refused_v6.bind(("::1", destination_port))
            break
        except OSError:
            refused_v6.close()
            refused_v6 = None
            server.close()
            await server.wait_closed()
            if attempt == 19:
                if dns_socket:
                    dns_socket.close()
                raise
    try:
        with (root / "child.log").open("w", encoding="utf-8") as log:
            child = subprocess.Popen(
                [str(binary), "--config-dir", str(root)], stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 10
                while "server started" not in (root / "child.log").read_text(
                    encoding="utf-8", errors="replace"
                ):
                    assert child.poll() is None and time.monotonic() < deadline, (
                        root / "child.log"
                    ).read_text(encoding="utf-8", errors="replace")
                    await asyncio.sleep(0.05)
                try:
                    answer = await (probe_domain(inbound_port, destination_port)
                                    if domain else probe(inbound_port, destination_port))
                except (TimeoutError, asyncio.IncompleteReadError):
                    assert not succeeds, "expected an outbound connection"
                    answer = b""
                assert (answer == b"\0\0" + PAYLOAD) == succeeds, (
                    f"addresses={addresses}, strategy={strategy}, answer={answer!r}"
                )
                assert received == (["127.0.0.1"] if succeeds else []), received
            finally:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
    finally:
        server.close()
        await server.wait_closed()
        if refused_v6:
            refused_v6.close()
        if dns_socket:
            dns_socket.close()


async def probe_user(port, destination_port, user_uuid, proxy_header=b""):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(
            proxy_header +
            b"\0" + user_uuid.bytes + b"\0\1" + struct.pack("!H", destination_port) +
            b"\1\x7f\0\0\1" + PAYLOAD
        )
        await writer.drain()
        return await asyncio.wait_for(reader.readexactly(2 + len(PAYLOAD)), 12)
    finally:
        writer.close()
        await writer.wait_closed()


async def run_chained_passthrough_case(binary, root):
    import uuid
    entry_port = free_port()
    entry_b_port = free_port()
    us_port = free_port()
    jp_port = free_port()
    user_a = uuid.UUID("11111111-1111-4111-8111-111111111111")
    user_b = uuid.UUID("22222222-2222-4222-8222-222222222222")
    relay_user = uuid.UUID("99999999-9999-4999-8999-999999999999")
    values = {
        "config.json": {
            "workers": 1,
            "log": {"enable": True, "rotateDaily": False, "access": str(root / "access.log")},
        },
        "inbounds.json": [
            {
                "tag": "entry-in-a", "protocol": "vless", "listen": "127.0.0.1",
                "port": entry_port, "proxyProtocol": "auto", "outboundTag": "entry-to-us-anytls",
                "settings": {
                    "clients": [
                        {"id": str(user_a), "email": "1001"},
                        {"id": str(user_b), "email": "1002"},
                    ]
                },
            },
            {
                "tag": "entry-in-b", "protocol": "vless", "listen": "127.0.0.1",
                "port": entry_b_port, "proxyProtocol": "auto", "outboundTag": "entry-to-us-anytls",
                "settings": {
                    "clients": [
                        {"id": str(user_a), "email": "1001"},
                    ]
                },
            },
            {
                "tag": "us-anytls-in", "protocol": "anytls", "listen": "127.0.0.1",
                "port": us_port, "outboundTag": "us-to-jp",
                "settings": {
                    "clients": [{"password": "us-anytls-password", "email": "hop1@us.example"}]
                },
                "streamSettings": {
                    "network": "tcp", "security": "tls",
                    "tlsSettings": {"serverName": "us.example.com"},
                },
            },
            {
                "tag": "jp-in", "protocol": "vless", "listen": "127.0.0.1",
                "port": jp_port, "outboundTag": "jp-out-user",
                "settings": {
                    "clients": [{"id": str(relay_user), "email": "relay@jp.example"}]
                },
            },
        ],
        "outbounds.json": [
            {
                "tag": "entry-to-us-anytls", "protocol": "anytls", "passthrough": True,
                "settings": {
                    "address": "127.0.0.1", "port": us_port,
                    "password": "us-anytls-password", "minIdleSession": 1,
                },
                "streamSettings": {
                    "network": "tcp", "security": "tls",
                    "tlsSettings": {"serverName": "us.example.com", "allowInsecure": True},
                },
            },
            {
                "tag": "us-to-jp", "protocol": "vless", "passthrough": True,
                "settings": {
                    "address": "127.0.0.1", "port": jp_port, "id": str(relay_user),
                },
            },
            {
                "tag": "jp-out-user", "protocol": "freedom",
                "sendThrough": ["127.0.0.0/24"], "sendThroughStrategy": "user_hash",
            },
        ],
    }
    write_configs(root, values)
    received = []

    async def echo(reader, writer):
        received.append(writer.get_extra_info("peername")[0])
        try:
            data = await reader.readexactly(len(PAYLOAD))
            writer.write(data)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    destination_port = server.sockets[0].getsockname()[1]
    try:
        with (root / "child.log").open("w", encoding="utf-8") as log:
            child = subprocess.Popen(
                [str(binary), "--config-dir", str(root)], stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 10
                while "server started" not in (root / "child.log").read_text(
                    encoding="utf-8", errors="replace"
                ):
                    assert child.poll() is None and time.monotonic() < deadline
                    await asyncio.sleep(0.05)
                ans1 = await probe_user(entry_port, destination_port, user_a)
                ans2 = await probe_user(entry_port, destination_port, user_a)
                ans3 = await probe_user(entry_port, destination_port, user_b)
                ans4 = await probe_user(entry_b_port, destination_port, user_a)
                assert ans1 == b"\0\0" + PAYLOAD and ans2 == b"\0\0" + PAYLOAD
                assert ans3 == b"\0\0" + PAYLOAD and ans4 == b"\0\0" + PAYLOAD
                assert len(received) == 4, received
                assert received[0] == received[1], f"user_hash unstable: {received}"
                assert received[0] != received[2], f"user_hash did not isolate users: {received}"
                assert received[0] != received[3], f"user_hash did not isolate same user ID across different origin tags: {received}"
            finally:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
        access_text = (root / "access.log").read_text(encoding="utf-8", errors="replace")
        assert "|entry-in-a|" in access_text and "|entry-in-b|" in access_text, access_text
    finally:
        server.close()
        await server.wait_closed()

    # Verify ip_hash passthrough with PROXY protocol client IPs and varying ports
    received.clear()
    values["inbounds.json"][3]["outboundTag"] = "jp-out-ip"
    values["outbounds.json"][2] = {
        "tag": "jp-out-ip", "protocol": "freedom",
        "sendThrough": ["127.0.0.0/24"], "sendThroughStrategy": "ip_hash",
    }
    ip_root = root / "ip-hash-chain"
    write_configs(ip_root, values)
    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    destination_port = server.sockets[0].getsockname()[1]
    try:
        with (ip_root / "child.log").open("w", encoding="utf-8") as log:
            child = subprocess.Popen(
                [str(binary), "--config-dir", str(ip_root)], stdout=log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 10
                while "server started" not in (ip_root / "child.log").read_text(
                    encoding="utf-8", errors="replace"
                ):
                    assert child.poll() is None and time.monotonic() < deadline
                    await asyncio.sleep(0.05)
                pp1 = b"PROXY TCP4 203.0.113.10 127.0.0.1 40001 443\r\n"
                pp2 = b"PROXY TCP4 203.0.113.10 127.0.0.1 59999 443\r\n"
                pp3 = b"PROXY TCP4 203.0.113.25 127.0.0.1 40001 443\r\n"
                assert await probe_user(entry_port, destination_port, user_a, pp1) == b"\0\0" + PAYLOAD
                assert await probe_user(entry_port, destination_port, user_b, pp2) == b"\0\0" + PAYLOAD
                assert await probe_user(entry_port, destination_port, user_a, pp3) == b"\0\0" + PAYLOAD
                assert len(received) == 3, received
                assert received[0] == received[1], f"ip_hash varied across source ports: {received}"
                assert received[0] != received[2], f"ip_hash did not distinguish client IPs: {received}"
            finally:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
    finally:
        server.close()
        await server.wait_closed()

async def main(binary, root):
    binary, root = binary.resolve(), root.resolve()
    await run_case(binary, root / "ordered-ip-hash", ["127.0.0.1/32", "192.0.2.3"], "ip_hash", True)
    await run_case(binary, root / "ordered-user-hash", ["127.0.0.1/32", "192.0.2.3"], "user_hash", True)
    await run_case(binary, root / "ordered-random", ["127.0.0.1/32"], "random", True)
    await run_case(binary, root / "strict-first-ip", ["192.0.2.3", "127.0.0.1/32"], "ip_hash", False)
    await run_case(binary, root / "no-same-family", ["2001:db8:ffff::/64"], "ip_hash", True)
    await run_case(binary, root / "dns-v6-bind-failed-v4-default",
                   ["2001:db8:ffff::/64"], "ip_hash", True, domain=True)
    await run_case(binary, root / "dns-v6-refused-v4-default",
                   ["::1"], "ip_hash", True, domain=True)
    await run_chained_passthrough_case(binary, root / "chained-passthrough")

    for index, (addresses, strategy) in enumerate((
        (["2001:db8::/129"], "ip_hash"),
        (["127.0.0.1/33"], "ip_hash"),
        (["127.0.0.1"], "round-robin"),
        (["127.0.0.1"], "hash"),
        ([42], "ip_hash"),
        ([], "ip_hash"),
    )):
        case = root / f"rejected-{index}"
        write_configs(case, make_configs(free_port(), addresses, strategy))
        process = subprocess.run(
            [str(binary), "--config-dir", str(case)],
            capture_output=True, text=True, timeout=5,
        )
        assert process.returncode != 0 and "sendThrough" in process.stdout + process.stderr
    print("ordered sendThrough: same-family selection, strict failure, passthrough hash, and system fallback passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

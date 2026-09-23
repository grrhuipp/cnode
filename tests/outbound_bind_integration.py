"""Real VLESS -> freedom TCP dials verify ordered source binding and fallback."""
import argparse
import asyncio
import os
from pathlib import Path
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

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    destination_port = server.sockets[0].getsockname()[1]
    try:
        with (root / "child.log").open("w", encoding="utf-8") as log:
            child = subprocess.Popen(
                [str(binary), "--config-dir", str(root)], stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
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
        if dns_socket:
            dns_socket.close()


async def main(binary, root):
    binary, root = binary.resolve(), root.resolve()
    await run_case(binary, root / "ordered-hash", ["127.0.0.1/32", "192.0.2.3"], "hash", True)
    await run_case(binary, root / "ordered-random", ["127.0.0.1/32"], "random", True)
    await run_case(binary, root / "strict-first-ip", ["192.0.2.3", "127.0.0.1/32"], "hash", False)
    await run_case(binary, root / "no-same-family", ["2001:db8:ffff::/64"], "hash", True)
    await run_case(binary, root / "dns-v6-bind-failed-v4-default",
                   ["2001:db8:ffff::/64"], "hash", True, domain=True)
    await run_case(binary, root / "dns-v6-refused-v4-default",
                   ["::1"], "hash", True, domain=True)

    for index, (addresses, strategy) in enumerate((
        (["2001:db8::/129"], "hash"),
        (["127.0.0.1/33"], "hash"),
        (["127.0.0.1"], "round-robin"),
        ([42], "hash"),
        ([], "hash"),
    )):
        case = root / f"rejected-{index}"
        write_configs(case, make_configs(free_port(), addresses, strategy))
        process = subprocess.run(
            [str(binary), "--config-dir", str(case)],
            capture_output=True, text=True, timeout=5,
        )
        assert process.returncode != 0 and "sendThrough" in process.stdout + process.stderr
    print("ordered sendThrough: same-family selection, strict failure, and system fallback passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

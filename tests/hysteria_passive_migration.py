#!/usr/bin/env python3
"""Real Hysteria v1/v2 passive-migration acceptance (no protocol mocks).

Start cnode with >=2 Workers, debug logging and one fixed Hysteria UDP port.
Run once per protocol and outbound (direct, TCP tunnel, AnyTLS), for example:
  python3 tests/hysteria_passive_migration.py --version 2 \
    --client build/hysteria-smoke/hysteria --server-port 38443 \
    --server-log build/server.log --auth smoke-secret --output build/hy2-migration

The independent client process, SOCKS TCP connection and SOCKS UDP association
are never restarted. A NAT relay changes only its upstream source port and
then returns to the same previously validated socket (A -> B -> A). Success
requires actual cross-Worker commits, including ngtcp2's historical-path reuse,
uninterrupted TCP sequence numbers, and stable TCP/UDP egress tuples. Forged
CID packets must leave both business exchanges responsive within 1.5 seconds,
not merely avoid a commit. The server destination UDP port never changes.
Results and generated client configuration/logs remain under --output. This
script deliberately does not start or reconfigure cnode.

A second independent client continuously exercises an unrelated TCP request.
For an AnyTLS/TCP upstream, run a second real cnode and configure the tested
server's outbound to dial a local tap port; pass, for example,
  --upstream-target 127.0.0.1:44443 --upstream-proxy-port 44444
The transparent tap verifies that established upstream connections are not
redialed during migration. Neither endpoint is mocked.

Optional Linux lifecycle regression: --stop-server-pid PID first proves the
normal migration assertions, then selects a fresh foreign-Worker source using
an actual forged-CID rejection. It withholds the real client's PATH_RESPONSE
by dropping server replies on that path and sends SIGTERM after the first
server packet arrives. It requires target-listener cancellation, fail-closed
rollback of the selected path, and process exit within ten seconds. Use only
with a disposable cnode process; the PID is deliberately terminated.
"""
import argparse
import asyncio
import errno
import json
import os
from pathlib import Path
import re
import socket
import signal
import struct
import time


def udp_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    return sock


def tcp_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class NatRelay:
    def __init__(self, server):
        self.loop = asyncio.get_running_loop()
        self.server = server
        self.front = udp_socket()
        self.upstream = udp_socket()
        self.sockets = [self.upstream]
        self.client = None
        self.tasks = []
        self.trace = []
        self.cid = None
        self.blocked_upstream = None
        self.blocked_response = asyncio.Event()

    def start(self):
        self.tasks.append(asyncio.create_task(self.receive_client()))
        self.tasks.append(asyncio.create_task(self.receive_server(self.upstream)))

    async def receive_client(self):
        while True:
            packet, peer = await self.loop.sock_recvfrom(self.front, 65536)
            self.client = peer
            if packet and not packet[0] & 0x80 and len(packet) >= 19:
                self.cid = packet[1:19]
            await self.loop.sock_sendto(self.upstream, packet, self.server)

    async def receive_server(self, sock):
        while True:
            packet, peer = await self.loop.sock_recvfrom(sock, 65536)
            if peer == self.server and self.client:
                if sock is self.blocked_upstream:
                    self.blocked_response.set()
                    continue
                await self.loop.sock_sendto(self.front, packet, self.client)

    def switch(self, previous=None):
        old = self.upstream.getsockname()
        if previous is None:
            self.upstream = udp_socket()
            self.sockets.append(self.upstream)
            self.tasks.append(asyncio.create_task(self.receive_server(self.upstream)))
        else:
            assert previous in self.sockets, "return path must reuse an existing NAT socket"
            self.upstream = previous
        self.trace.append({"time": time.time(), "old_source": old,
                           "new_source": self.upstream.getsockname(),
                           "fixed_destination": self.server, "reused": previous is not None})
        return self.upstream.getsockname()[1]

    async def close(self):
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for sock in [self.front, *self.sockets]:
            sock.close()


async def socks_reply(reader):
    head = await reader.readexactly(4)
    if head[:2] != b"\x05\x00":
        raise AssertionError(f"SOCKS request rejected: {head.hex()}")
    if head[3] == 1:
        address = socket.inet_ntoa(await reader.readexactly(4))
    elif head[3] == 3:
        size = (await reader.readexactly(1))[0]
        address = (await reader.readexactly(size)).decode()
    elif head[3] == 4:
        address = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        raise AssertionError("bad SOCKS address type")
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return address, port


async def socks_open(port, command, target_port):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    assert await reader.readexactly(2) == b"\x05\x00", "SOCKS authentication failed"
    writer.write(b"\x05" + bytes([command]) + b"\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", target_port))
    await writer.drain()
    bound = await socks_reply(reader)
    return reader, writer, bound


async def run(args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    server_log = Path(args.server_log)
    log_offset = server_log.stat().st_size
    loop = asyncio.get_running_loop()
    udp_echo = udp_socket()
    udp_client = udp_socket()
    tcp_peers = []
    udp_peers = set()
    backend_writers = []
    upstream_accepts = []
    upstream_tasks = set()
    upstream_server = None
    upstream_baseline = None
    control_task = None

    async def tap_upstream(reader, writer):
        task = asyncio.current_task()
        upstream_tasks.add(task)
        upstream_accepts.append({"time": time.time(), "peer": writer.get_extra_info("peername")})
        remote_writer = None
        try:
            host, port = args.upstream_target.rsplit(":", 1)
            remote_reader, remote_writer = await asyncio.open_connection(host, int(port))

            async def pipe(source, destination):
                while data := await source.read(65536):
                    destination.write(data)
                    await destination.drain()
                if not destination.is_closing():
                    try:
                        destination.write_eof()
                    except OSError as error:
                        # A fully disconnected peer has no write half left.
                        if error.errno != errno.ENOTCONN:
                            raise

            await asyncio.gather(pipe(reader, remote_writer), pipe(remote_reader, writer))
        finally:
            writer.close()
            if remote_writer:
                remote_writer.close()
            upstream_tasks.discard(task)

    if args.upstream_target:
        upstream_server = await asyncio.start_server(
            tap_upstream, "127.0.0.1", args.upstream_proxy_port)
    result = {"version": args.version, "fixed_server_port": args.server_port,
              "success": False, "commits": [], "rounds": 0}

    async def echo_tcp(reader, writer):
        tcp_peers.append(writer.get_extra_info("peername"))
        backend_writers.append(writer)
        try:
            while payload := await reader.read(65536):
                writer.write(payload)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def echo_udp():
        while True:
            payload, peer = await loop.sock_recvfrom(udp_echo, 65536)
            udp_peers.add(peer)
            # Independently observed egress tuple, not an inferred connection ID.
            encoded_peer = socket.inet_aton(peer[0]) + struct.pack("!H", peer[1])
            await loop.sock_sendto(udp_echo, payload + encoded_peer, peer)

    tcp_server = await asyncio.start_server(echo_tcp, "127.0.0.1", 0)
    echo_port = tcp_server.sockets[0].getsockname()[1]
    udp_task = asyncio.create_task(echo_udp())
    relay = NatRelay(("127.0.0.1", args.server_port))
    relay.start()
    socks_port = tcp_port()
    relay_port = relay.front.getsockname()[1]
    def client_config(name, server_port, local_socks):
        if args.version == 2:
            config = out / f"{name}.yaml"
            config.write_text(f"server: 127.0.0.1:{server_port}\nauth: {json.dumps(args.auth)}\n"
                              f"tls:\n  sni: localhost\n  insecure: true\n"
                              f"socks5:\n  listen: 127.0.0.1:{local_socks}\n")
        else:
            config = out / f"{name}.json"
            config.write_text(json.dumps({"server": f"127.0.0.1:{server_port}", "protocol": "udp",
                "up_mbps": 100, "down_mbps": 100, "auth_str": args.auth,
                "server_name": "localhost", "insecure": True,
                "socks5": {"listen": f"127.0.0.1:{local_socks}"}}, indent=2))
        return config

    control_port = tcp_port()
    while control_port == socks_port:
        control_port = tcp_port()
    config = client_config("client", relay_port, socks_port)
    control_config = client_config("control-client", args.server_port, control_port)
    client_log = (out / "client.log").open("wb")
    control_log = (out / "control-client.log").open("wb")
    processes = []
    process = None
    writers = []
    try:
        process = await asyncio.create_subprocess_exec(str(Path(args.client).resolve()),
            "client", "-c", str(config.resolve()), stdout=client_log, stderr=client_log)
        processes.append(process)
        control_process = await asyncio.create_subprocess_exec(str(Path(args.client).resolve()),
            "client", "-c", str(control_config.resolve()), stdout=control_log, stderr=control_log)
        processes.append(control_process)
        # Readiness probes are only to the local SOCKS listener, before a
        # protocol session or test stream is established.
        for ready_process, ready_port in [(process, socks_port), (control_process, control_port)]:
            deadline = loop.time() + 15
            while True:
                if ready_process.returncode is not None:
                    raise AssertionError("real Hysteria client exited before readiness")
                try:
                    _, probe = await asyncio.open_connection("127.0.0.1", ready_port)
                    probe.close()
                    await probe.wait_closed()
                    break
                except OSError:
                    if loop.time() >= deadline:
                        raise TimeoutError("Hysteria SOCKS listener did not start")
                    await asyncio.sleep(0.05)
        tcp_reader, tcp_writer, _ = await asyncio.wait_for(socks_open(socks_port, 1, echo_port), 15)
        writers.append(tcp_writer)
        _, association, udp_bound = await asyncio.wait_for(socks_open(socks_port, 3, 0), 15)
        writers.append(association)
        control_reader, control_writer, _ = await asyncio.wait_for(
            socks_open(control_port, 1, echo_port), 15)
        writers.append(control_writer)
        result["control_rounds"] = 0
        result["control_max_latency_seconds"] = 0
        control_first_echo = asyncio.Event()

        async def control_loop():
            while True:
                data = b"independent-session:" + struct.pack("!Q", result["control_rounds"]) + os.urandom(1024)
                started = loop.time()
                control_writer.write(data)
                await control_writer.drain()
                reply = await asyncio.wait_for(control_reader.readexactly(len(data)), 2)
                assert reply == data, "unrelated request was corrupted"
                result["control_max_latency_seconds"] = max(
                    result["control_max_latency_seconds"], loop.time() - started)
                control_first_echo.set()
                result["control_rounds"] += 1
                await asyncio.sleep(0.01)

        control_task = asyncio.create_task(control_loop())
        ready = asyncio.create_task(control_first_echo.wait())
        try:
            done, _ = await asyncio.wait(
                {ready, control_task}, timeout=15, return_when=asyncio.FIRST_COMPLETED)
            if not done:
                raise TimeoutError("independent control request produced no first echo")
            if control_task in done:
                await control_task
                raise AssertionError("independent control request ended before readiness")
        finally:
            ready.cancel()
            await asyncio.gather(ready, return_exceptions=True)
        if udp_bound[0] == "0.0.0.0":
            udp_bound = ("127.0.0.1", udp_bound[1])
        udp_header = b"\x00\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", udp_echo.getsockname()[1])
        nonce = os.urandom(16)
        first_udp_peer = None

        async def exchange():
            nonlocal first_udp_peer
            sequence = result["rounds"]

            async def tcp_round():
                payload = nonce + struct.pack("!Q", sequence) + os.urandom(4096)
                tcp_writer.write(payload)
                await tcp_writer.drain()
                assert await asyncio.wait_for(tcp_reader.readexactly(len(payload)), 12) == payload

            async def udp_round():
                nonlocal first_udp_peer
                udp_payload = nonce + struct.pack("!Q", sequence)
                end = loop.time() + 12
                while loop.time() < end:
                    await loop.sock_sendto(udp_client, udp_header + udp_payload, udp_bound)
                    try:
                        reply, _ = await asyncio.wait_for(loop.sock_recvfrom(udp_client, 65536), 0.5)
                    except TimeoutError:
                        continue
                    if len(reply) < 10 or reply[:4] != b"\x00\x00\x00\x01":
                        raise AssertionError("unexpected SOCKS UDP response framing")
                    body = reply[10:]
                    if body[:-6] != udp_payload:
                        continue
                    observed_peer = (socket.inet_ntoa(body[-6:-2]), struct.unpack("!H", body[-2:])[0])
                    first_udp_peer = first_udp_peer or observed_peer
                    assert observed_peer == first_udp_peer, "UDP egress source tuple changed (redial)"
                    return
                raise AssertionError(f"UDP session stopped at sequence {sequence}")

            await asyncio.gather(tcp_round(), udp_round())
            if control_task.done():
                await control_task
                raise AssertionError("independent control request ended")
            assert len(tcp_peers) == 2, "TCP egress was reconnected"
            assert len(udp_peers) == 1, "UDP egress association was recreated"
            if upstream_baseline is not None:
                assert len(upstream_accepts) == upstream_baseline, "active upstream tunnel was redialed"
            result["rounds"] += 1

        def server_events():
            with server_log.open("rb") as handle:
                handle.seek(log_offset)
                return handle.read().decode(errors="replace")

        def commits():
            pattern = (r"QUIC passive handoff committed old_owner=(\d+) receiving_worker=(\d+) "
                       r"remote=[^\n]*?:(\d+) path_evidence=(challenge|reused)")
            return [{"old_owner": int(old), "receiving_worker": int(new), "source_port": int(port),
                     "path_evidence": evidence}
                    for old, new, port, evidence in re.findall(pattern, server_events())]

        for _ in range(4):
            await exchange()
        upstream_baseline = len(upstream_accepts)
        if args.upstream_target:
            assert upstream_baseline > 0, "server outbound did not use the configured upstream tap"
        control_before_migration = result["control_rounds"]
        # Exercise actual foreign-Worker claims, not only randomly selected
        # SO_REUSEPORT sockets that might belong to the current owner. Each
        # attempt measures the existing TCP stream AND UDP association while
        # the forged packet is being handled; the old 3-second freeze fails.
        forged_sockets = []
        result["forged_max_latency_seconds"] = 0
        result["forged_claim_rejections"] = []
        try:
            if relay.cid is None:
                raise AssertionError("client never sent a short-header QUIC packet")
            for _ in range(args.max_switches):
                forged = udp_socket()
                forged_sockets.append(forged)
                forged_port = forged.getsockname()[1]
                await loop.sock_sendto(forged, b"\x40" + relay.cid + os.urandom(80), relay.server)
                # Let the server receive the invalid packet before the next
                # exchange; this is not a wait for the 3-second claim timeout.
                await asyncio.sleep(0.02)
                started = loop.time()
                await asyncio.wait_for(exchange(), 1.5)
                result["forged_max_latency_seconds"] = max(
                    result["forged_max_latency_seconds"], loop.time() - started)
                assert all(item["source_port"] != forged_port for item in commits()), \
                    "unauthenticated CID committed migration"
                rejected = re.findall(
                    rf"QUIC passive claim rejected receiving_worker=(\d+) remote=[^\n]*?:{forged_port} "
                    r"reason=no-path-evidence", server_events())
                if rejected:
                    result["forged_claim_rejections"] = [
                        {"source_port": forged_port, "receiving_worker": int(worker)}
                        for worker in rejected]
                    break
            # Debug records are flushed asynchronously (up to five seconds).
            # Wait for evidence while continuing the same bounded exchanges;
            # log visibility must not weaken the business-latency assertion.
            evidence_deadline = loop.time() + 7
            forged_ports = {sock.getsockname()[1] for sock in forged_sockets}
            while not result["forged_claim_rejections"] and loop.time() < evidence_deadline:
                rejected = re.findall(
                    r"QUIC passive claim rejected receiving_worker=(\d+) remote=[^\n]*?:(\d+) "
                    r"reason=no-path-evidence", server_events())
                result["forged_claim_rejections"] = [
                    {"source_port": int(port), "receiving_worker": int(worker)}
                    for worker, port in rejected if int(port) in forged_ports]
                assert all(item["source_port"] not in forged_ports for item in commits()), \
                    "unauthenticated CID committed migration"
                await asyncio.wait_for(exchange(), 1.5)
                await asyncio.sleep(0.05)
            assert result["forged_claim_rejections"], \
                "no log-proven foreign-Worker forged-CID rejection"
        finally:
            for forged in forged_sockets:
                forged.close()
        result["return_commits"] = []
        for _ in range(args.max_switches):
            previous = relay.upstream
            source_port = relay.switch()
            for _ in range(6):
                await asyncio.wait_for(exchange(), 1.5)
            # Return before ngtcp2's historical-path validity expires, without
            # waiting for the asynchronous debug sink to expose the first commit.
            return_port = relay.switch(previous)
            for _ in range(6):
                await asyncio.wait_for(exchange(), 1.5)
            evidence_deadline = loop.time() + 7
            while loop.time() < evidence_deadline:
                observed = commits()
                confirmed = [item for item in observed if item["source_port"] == source_port
                             and item["old_owner"] != item["receiving_worker"]]
                returned = [item for item in observed
                            if item["source_port"] == return_port
                            and item["path_evidence"] == "reused"
                            and any(item["old_owner"] == outward["receiving_worker"]
                                    and item["receiving_worker"] == outward["old_owner"]
                                    for outward in confirmed)]
                if confirmed and returned:
                    result["commits"].extend(confirmed)
                    result["return_commits"].extend(returned)
                    break
                await asyncio.wait_for(exchange(), 1.5)
                await asyncio.sleep(0.05)
            if result["return_commits"]:
                break
        assert result["commits"], \
            "no log-proven cross-Worker handoff (same-Worker NAT rebinding is insufficient)"
        assert result["return_commits"], "no safe cross-Worker return to the validated historical path"
        for _ in range(20):
            await exchange()
        assert result["control_rounds"] > control_before_migration, "independent request made no progress"
        if control_task.done():
            await control_task
        if args.stop_server_pid:
            # A previously validated B path can commit without a new challenge.
            # Find a genuinely fresh foreign path instead, without ever moving
            # a client packet until its receiving Worker has been observed.
            candidates = {}
            for _ in range(args.max_switches):
                candidate = udp_socket()
                relay.sockets.append(candidate)
                relay.tasks.append(asyncio.create_task(relay.receive_server(candidate)))
                port = candidate.getsockname()[1]
                candidates[port] = candidate
                await loop.sock_sendto(candidate, b"\x40" + relay.cid + os.urandom(80), relay.server)
                await asyncio.wait_for(exchange(), 1.5)
            chosen = None
            deadline = loop.time() + 7
            while chosen is None and loop.time() < deadline:
                rejected = re.findall(
                    r"QUIC passive claim rejected receiving_worker=(\d+) remote=[^\n]*?:(\d+) "
                    r"reason=no-path-evidence", server_events())
                for worker, port in rejected:
                    if int(port) in candidates:
                        chosen = candidates[int(port)]
                        result["shutdown_claim"] = {
                            "receiving_worker": int(worker), "source_port": int(port)}
                        break
                await asyncio.wait_for(exchange(), 1.5)
                await asyncio.sleep(0.02)
            assert chosen is not None, "no fresh foreign-Worker path for shutdown regression"
            relay.blocked_upstream = chosen
            relay.switch(chosen)
            interrupted = asyncio.create_task(exchange())
            try:
                await asyncio.wait_for(relay.blocked_response.wait(), 1.5)
                # The independent session has remained live until the deliberate
                # whole-server stop. Its termination is not a migration failure.
                if control_task.done():
                    await control_task
                control_task.cancel()
                await asyncio.gather(control_task, return_exceptions=True)
                control_task = None
                os.kill(args.stop_server_pid, signal.SIGTERM)
                deadline = loop.time() + 10
                while True:
                    try:
                        os.kill(args.stop_server_pid, 0)
                        stat = Path(f"/proc/{args.stop_server_pid}/stat").read_text().rsplit(")", 1)[1].split()
                        if stat[0] == "Z":
                            # stat field 52 is waitpid's encoded exit status;
                            # fields here begin at field 3 after the comm name.
                            status = int(stat[49])
                            assert status == 0, f"cnode exited abnormally: wait status {status}"
                            result["shutdown_claim"]["exit_status"] = status
                            break
                    except (ProcessLookupError, FileNotFoundError):
                        break
                    if loop.time() >= deadline:
                        raise AssertionError("cnode did not join the interrupted claim during shutdown")
                    await asyncio.sleep(0.02)
                events = server_events()
                assert (f"QUIC passive claim abandoned receiving_worker="
                        f"{result['shutdown_claim']['receiving_worker']} reason=listener-stopped") in events, \
                    "target listener did not stop during the authenticated claim"
                assert re.search(
                    r"QUIC passive rollback closed connection worker=\d+ reason=selected-path-changed", events), \
                    "shutdown did not exercise fail-closed rollback of a changed selected path"
                result["shutdown_claim"]["joined"] = True
            finally:
                interrupted.cancel()
                await asyncio.gather(interrupted, return_exceptions=True)
        result.update(success=True, client_pid=process.pid, control_client_pid=control_process.pid,
                      tcp_egress=tcp_peers, udp_egress=sorted(udp_peers), relay=relay.trace,
                      upstream_accepts=upstream_accepts, upstream_baseline=upstream_baseline)
    except Exception as error:
        result.update(error=f"{type(error).__name__}: {error}", tcp_egress=tcp_peers,
                      udp_egress=sorted(udp_peers), relay=relay.trace)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(result, indent=2))
        if control_task:
            control_task.cancel()
            await asyncio.gather(control_task, return_exceptions=True)
        for writer in writers + backend_writers:
            writer.close()
        for child in processes:
            if child.returncode is None:
                child.terminate()
                try:
                    await asyncio.wait_for(child.wait(), 5)
                except TimeoutError:
                    child.kill()
                    await child.wait()
        control_log.close()
        if upstream_server:
            upstream_server.close()
            await upstream_server.wait_closed()
        for task in list(upstream_tasks):
            task.cancel()
        await asyncio.gather(*list(upstream_tasks), return_exceptions=True)
        client_log.close()
        await relay.close()
        udp_task.cancel()
        await asyncio.gather(udp_task, return_exceptions=True)
        udp_client.close()
        udp_echo.close()
        tcp_server.close()
        await tcp_server.wait_closed()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", type=int, choices=(1, 2), required=True)
    parser.add_argument("--client", required=True)
    parser.add_argument("--server-port", type=int, required=True)
    parser.add_argument("--server-log", required=True)
    parser.add_argument("--auth", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-switches", type=int, default=32)
    parser.add_argument("--stop-server-pid", type=int,
                        help="Linux only: terminate this disposable cnode PID during authenticated path validation")
    parser.add_argument("--upstream-target", help="Real AnyTLS/TCP upstream host:port; cnode outbound must dial --upstream-proxy-port")
    parser.add_argument("--upstream-proxy-port", type=int, default=0,
                        help="Fixed listening port for transparent upstream accept-count tap")
    args = parser.parse_args()
    if bool(args.upstream_target) != bool(args.upstream_proxy_port):
        parser.error("--upstream-target and --upstream-proxy-port must be specified together")
    if args.stop_server_pid is not None and (args.stop_server_pid <= 1 or args.stop_server_pid == os.getpid()):
        parser.error("--stop-server-pid must name a separate disposable cnode process")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()

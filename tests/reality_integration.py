"""End-to-end integration test for REALITY:
1. Unauthenticated dest fallback + PROXY protocol (xver 0, 1, 2)
2. ML-DSA-65 post-quantum certificate signing & verification (mldsa65Seed / mldsa65Verify)
3. Client TLS fingerprint simulation (chrome, firefox, random)
4. Client spiderX fallback HTTP crawling on unauthenticated fallback
5. V2Board panel REALITY (tls=2) node auto-sync
"""

import argparse
import asyncio
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import threading
import time
import uuid

USER = uuid.UUID("11111111-1111-4111-8111-111111111111")
PAYLOAD = b"reality-end-to-end-verification-payload"

# X25519 keypair (32-byte raw keys, Base64URL without padding)
SERVER_PRIV_KEY = "6Epi9xRmv1RL-Kiqrj6Fl523a9eagFMTc-oyzGC5IU8"
SERVER_PUB_KEY = "VPI8d_RKeP4K4eF69AY-QjrV325NaSe03p-a0zkcH3Q"
SHORT_ID = "0123456789abcdef"
WRONG_SHORT_ID = "fedcba9876543210"

MLDSA65_SEED_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
MLDSA65_SEED_B = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def derive_mldsa65_pub(binary: Path, seed: str) -> str:
    helper = binary.parent / "cnode_reality_key_test"
    out = subprocess.check_output(
        [str(helper), "--derive-mldsa65", seed], text=True, timeout=5
    ).strip()
    assert len(out) == 2603, f"unexpected ML-DSA-65 public key length: {len(out)}"
    return out


def make_self_signed_cert(cert_path: Path, key_path: Path):
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=example.com",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def build_vless_request(target_port: int, payload: bytes) -> bytes:
    return (
        b"\x00"
        + USER.bytes
        + b"\x00\x01"
        + struct.pack("!H", target_port)
        + b"\x01\x7f\x00\x00\x01"
        + payload
    )


async def send_vless_probe(entry_port: int, target_port: int, payload: bytes = PAYLOAD) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", entry_port)
    try:
        writer.write(build_vless_request(target_port, payload))
        await writer.drain()
        return await asyncio.wait_for(reader.readexactly(2 + len(payload)), 5.0)
    finally:
        writer.close()
        await writer.wait_closed()


def write_config_dir(root: Path, config_dict: dict):
    root.mkdir(parents=True, exist_ok=True)
    config_dict["config.json"].setdefault("log", {})["logDir"] = str(root / "logs")
    for name, content in config_dict.items():
        (root / name).write_text(json.dumps(content), encoding="utf-8")


def start_cnode(binary: Path, config_dir: Path) -> subprocess.Popen:
    log_path = config_dir / "child.log"
    logfile = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [str(binary), "--config-dir", str(config_dir)],
        stdout=logfile,
        stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 10.0
    while True:
        text = log_path.read_text(encoding="utf-8", errors="replace")
        if "server started" in text:
            return proc
        assert proc.poll() is None and time.monotonic() < deadline, (
            f"cnode failed to start in {config_dir}:\n{text}"
        )
        time.sleep(0.05)


def stop_cnode(proc: subprocess.Popen):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


class MockPanelServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, node_port: int, dest_port: int):
        super().__init__(("127.0.0.1", 0), MockPanelHandler)
        self.node_port = node_port
        self.dest_port = dest_port
        self.config_fetches = 0
        self.user_fetches = 0


class MockPanelHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        srv = self.server
        if "/config?" in self.path:
            srv.config_fetches += 1
            body = {
                "server_port": srv.node_port,
                "network": "tcp",
                "tls": 2,
                "flow": "",
                "server_name": "example.com",
                "tls_settings": {
                    "private_key": SERVER_PRIV_KEY,
                    "short_id": [SHORT_ID],
                    "dest": f"127.0.0.1:{srv.dest_port}",
                    "xver": 1,
                    "mldsa65_seed": MLDSA65_SEED_A,
                },
                "base_config": {"pull_interval": 1, "push_interval": 60},
            }
        elif "/user?" in self.path:
            srv.user_fetches += 1
            body = {
                "users": [
                    {
                        "id": 42,
                        "uuid": str(USER),
                        "speed_limit": 0,
                        "device_limit": 0,
                    }
                ]
            }
        else:
            body = {}
        raw = json.dumps(body).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        raw = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)


async def main(binary: Path, root: Path):
    binary = binary.resolve()
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)

    mldsa_pub_a = derive_mldsa65_pub(binary, MLDSA65_SEED_A)
    mldsa_pub_b = derive_mldsa65_pub(binary, MLDSA65_SEED_B)

    cert_path = root / "dest_cert.pem"
    key_path = root / "dest_key.pem"
    make_self_signed_cert(cert_path, key_path)

    # 1. Start target TCP echo server (for authenticated VLESS traffic)
    async def echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            data = await asyncio.wait_for(reader.read(4096), 5.0)
            if data:
                writer.write(data)
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    echo_server = await asyncio.start_server(echo_handler, "127.0.0.1", 0)
    echo_port = echo_server.sockets[0].getsockname()[1]

    # 2. Start fallback receivers for xver=0 (TLS HTTP server for spiderX + plain check),
    #    xver=1 (PROXY v1 inspector), and xver=2 (PROXY v2 inspector).
    spider_requests: list[str] = []
    dest_tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    dest_tls_ctx.load_cert_chain(str(cert_path), str(key_path))

    async def dest_tls_http_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            req = await asyncio.wait_for(reader.read(4096), 5.0)
            req_line = req.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
            spider_requests.append(req_line)
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 13\r\n"
                b"Connection: close\r\n\r\n"
                b"fallback-body"
            )
            writer.write(resp)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    dest_tls_server = await asyncio.start_server(
        dest_tls_http_handler, "127.0.0.1", 0, ssl=dest_tls_ctx
    )
    dest_tls_port = dest_tls_server.sockets[0].getsockname()[1]

    proxy_v1_records: list[bytes] = []

    async def dest_xver1_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            line = await asyncio.wait_for(reader.readuntil(b"\r\n"), 5.0)
            rest = await asyncio.wait_for(reader.read(1024), 5.0)
            proxy_v1_records.append(line + rest)
            writer.write(b"XVER1-OK")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    dest_xver1_server = await asyncio.start_server(dest_xver1_handler, "127.0.0.1", 0)
    dest_xver1_port = dest_xver1_server.sockets[0].getsockname()[1]

    proxy_v2_records: list[bytes] = []

    async def dest_xver2_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            hdr = await asyncio.wait_for(reader.readexactly(28), 5.0)
            rest = await asyncio.wait_for(reader.read(1024), 5.0)
            proxy_v2_records.append(hdr + rest)
            writer.write(b"XVER2-OK")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    dest_xver2_server = await asyncio.start_server(dest_xver2_handler, "127.0.0.1", 0)
    dest_xver2_port = dest_xver2_server.sockets[0].getsockname()[1]

    # 3. Configure and start cnode server with 3 REALITY inbounds:
    #    - reality_xver0 (dest -> dest_tls_port, xver=0, mldsa65Seed=MLDSA65_SEED_A)
    #    - reality_xver1 (dest -> dest_xver1_port, xver=1, mldsa65Seed=MLDSA65_SEED_A)
    #    - reality_xver2 (dest -> dest_xver2_port, xver=2, mldsa65Seed=MLDSA65_SEED_A)
    port_xver0 = free_port()
    port_xver1 = free_port()
    port_xver2 = free_port()

    server_cfg = {
        "config.json": {"workers": 1, "log": {"level": "debug"}},
        "inbounds.json": [
            {
                "tag": "reality-xver0",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": port_xver0,
                "outboundTag": "direct",
                "settings": {
                    "decryption": "none",
                    "clients": [{"id": str(USER)}],
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": f"127.0.0.1:{dest_tls_port}",
                        "xver": 0,
                        "serverNames": ["example.com"],
                        "privateKey": SERVER_PRIV_KEY,
                        "shortIds": [SHORT_ID],
                        "mldsa65Seed": MLDSA65_SEED_A,
                    },
                },
            },
            {
                "tag": "reality-xver1",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": port_xver1,
                "outboundTag": "direct",
                "settings": {
                    "decryption": "none",
                    "clients": [{"id": str(USER)}],
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": f"127.0.0.1:{dest_xver1_port}",
                        "xver": 1,
                        "serverNames": ["example.com"],
                        "privateKey": SERVER_PRIV_KEY,
                        "shortIds": [SHORT_ID],
                        "mldsa65Seed": MLDSA65_SEED_A,
                    },
                },
            },
            {
                "tag": "reality-xver2",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": port_xver2,
                "outboundTag": "direct",
                "settings": {
                    "decryption": "none",
                    "clients": [{"id": str(USER)}],
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "dest": f"127.0.0.1:{dest_xver2_port}",
                        "xver": 2,
                        "serverNames": ["example.com"],
                        "privateKey": SERVER_PRIV_KEY,
                        "shortIds": [SHORT_ID],
                        "mldsa65Seed": MLDSA65_SEED_A,
                    },
                },
            },
        ],
        "outbounds.json": [{"tag": "direct", "protocol": "freedom"}],
    }
    write_config_dir(root / "server", server_cfg)

    # 4. Configure and start cnode client with 4 VLESS entry inbounds mapped to 4 REALITY outbounds:
    #    - entry_chrome: valid shortId + mldsa65Verify=mldsa_pub_a + fingerprint="chrome"
    #    - entry_firefox: valid shortId + mldsa65Verify=mldsa_pub_a + fingerprint="firefox"
    #    - entry_bad_mldsa: valid shortId + mldsa65Verify=mldsa_pub_b (wrong key!)
    #    - entry_spider: wrong shortId + spiderX="/spider-probe?ok=1" -> hits reality-xver0 fallback!
    entry_chrome = free_port()
    entry_firefox = free_port()
    entry_bad_mldsa = free_port()
    entry_spider = free_port()

    client_cfg = {
        "config.json": {"workers": 1, "log": {"level": "debug"}},
        "inbounds.json": [
            {
                "tag": "in-chrome",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": entry_chrome,
                "outboundTag": "out-chrome",
                "settings": {"decryption": "none", "clients": [{"id": str(USER)}]},
            },
            {
                "tag": "in-firefox",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": entry_firefox,
                "outboundTag": "out-firefox",
                "settings": {"decryption": "none", "clients": [{"id": str(USER)}]},
            },
            {
                "tag": "in-bad-mldsa",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": entry_bad_mldsa,
                "outboundTag": "out-bad-mldsa",
                "settings": {"decryption": "none", "clients": [{"id": str(USER)}]},
            },
            {
                "tag": "in-spider",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": entry_spider,
                "outboundTag": "out-spider",
                "settings": {"decryption": "none", "clients": [{"id": str(USER)}]},
            },
        ],
        "outbounds.json": [
            {
                "tag": "out-chrome",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": port_xver0,
                    "id": str(USER),
                    "encryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.com",
                        "publicKey": SERVER_PUB_KEY,
                        "shortId": SHORT_ID,
                        "fingerprint": "chrome",
                        "mldsa65Verify": mldsa_pub_a,
                    },
                },
            },
            {
                "tag": "out-firefox",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": port_xver1,
                    "id": str(USER),
                    "encryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.com",
                        "publicKey": SERVER_PUB_KEY,
                        "shortId": SHORT_ID,
                        "fingerprint": "firefox",
                        "mldsa65Verify": mldsa_pub_a,
                    },
                },
            },
            {
                "tag": "out-bad-mldsa",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": port_xver0,
                    "id": str(USER),
                    "encryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.com",
                        "publicKey": SERVER_PUB_KEY,
                        "shortId": SHORT_ID,
                        "fingerprint": "random",
                        "mldsa65Verify": mldsa_pub_b,
                    },
                },
            },
            {
                "tag": "out-spider",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": port_xver0,
                    "id": str(USER),
                    "encryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.com",
                        "publicKey": SERVER_PUB_KEY,
                        "shortId": WRONG_SHORT_ID,
                        "fingerprint": "safari",
                        "spiderX": "/spider-probe?ok=1",
                    },
                },
            },
        ],
    }
    write_config_dir(root / "client", client_cfg)

    server_proc = start_cnode(binary, root / "server")
    client_proc = start_cnode(binary, root / "client")
    try:
        # Test A: Authenticated REALITY + ML-DSA-65 + Chrome & Firefox fingerprints
        resp_chrome = await send_vless_probe(entry_chrome, echo_port)
        assert resp_chrome == b"\x00\x00" + PAYLOAD, f"chrome REALITY failed: {resp_chrome!r}"

        resp_firefox = await send_vless_probe(entry_firefox, echo_port)
        assert resp_firefox == b"\x00\x00" + PAYLOAD, f"firefox REALITY failed: {resp_firefox!r}"

        # Test B: Wrong mldsa65Verify public key must fail handshake
        try:
            resp_bad = await send_vless_probe(entry_bad_mldsa, echo_port)
            assert resp_bad != b"\x00\x00" + PAYLOAD, "wrong mldsa65Verify unexpectedly succeeded"
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass

        # Test C: Unauthenticated dest fallback with xver=1 (PROXY v1) and xver=2 (PROXY v2)
        r1, w1 = await asyncio.open_connection("127.0.0.1", port_xver1)
        try:
            w1.write(b"GET /plain-http HTTP/1.1\r\nHost: example.com\r\n\r\n")
            await w1.drain()
            reply1 = await asyncio.wait_for(r1.read(64), 5.0)
            assert reply1 == b"XVER1-OK", f"unexpected xver=1 fallback reply: {reply1!r}"
        finally:
            w1.close()
            await w1.wait_closed()

        assert len(proxy_v1_records) == 1
        assert proxy_v1_records[0].startswith(b"PROXY TCP4 127.0.0.1 127.0.0.1 "), proxy_v1_records[0]
        assert b"GET /plain-http HTTP/1.1\r\n" in proxy_v1_records[0]

        r2, w2 = await asyncio.open_connection("127.0.0.1", port_xver2)
        try:
            w2.write(b"\x16\x03\x01\x00\x05hello")
            await w2.drain()
            reply2 = await asyncio.wait_for(r2.read(64), 5.0)
            assert reply2 == b"XVER2-OK", f"unexpected xver=2 fallback reply: {reply2!r}"
        finally:
            w2.close()
            await w2.wait_closed()

        assert len(proxy_v2_records) == 1
        v2_sig = b"\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\x7f\x00\x00\x01\x7f\x00\x00\x01"
        assert proxy_v2_records[0].startswith(v2_sig), proxy_v2_records[0][:28]
        assert proxy_v2_records[0][28:] == b"\x16\x03\x01\x00\x05hello"

        # Test D: Client spiderX fallback crawl on unauthenticated fallback to TLS HTTP dest
        spider_requests.clear()
        try:
            await send_vless_probe(entry_spider, echo_port)
        except (TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            pass

        deadline = time.monotonic() + 5.0
        while not spider_requests and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        assert any("GET /spider-probe?ok=1 HTTP/1.1" in req for req in spider_requests), (
            f"spiderX request was not observed by fallback TLS server: {spider_requests}"
        )
    finally:
        stop_cnode(client_proc)
        stop_cnode(server_proc)

    # Test E: V2Board panel REALITY (tls=2) node sync + client connection
    panel_node_port = free_port()
    panel_entry_port = free_port()
    panel_server = MockPanelServer(panel_node_port, dest_xver1_port)
    panel_thread = threading.Thread(target=panel_server.serve_forever, daemon=True)
    panel_thread.start()
    panel_port = panel_server.server_address[1]

    panel_cnode_cfg = {
        "config.json": {
            "workers": 1,
            "log": {"level": "debug"},
            "panels": [
                {
                    "Name": "v2b",
                    "Type": "V2board",
                    "APIHost": f"http://127.0.0.1:{panel_port}",
                    "Key": "test-token",
                    "NodeIDs": [1],
                    "NodeType": "vless",
                    "ListenIP": "127.0.0.1",
                    "RequestTimeout": 1,
                }
            ],
        },
        "inbounds.json": [
            {
                "tag": "panel-client-in",
                "protocol": "vless",
                "listen": "127.0.0.1",
                "port": panel_entry_port,
                "outboundTag": "panel-reality-out",
                "settings": {"decryption": "none", "clients": [{"id": str(USER)}]},
            }
        ],
        "outbounds.json": [
            {"tag": "direct", "protocol": "freedom"},
            {
                "tag": "panel-reality-out",
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": panel_node_port,
                    "id": str(USER),
                    "encryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "example.com",
                        "publicKey": SERVER_PUB_KEY,
                        "shortId": SHORT_ID,
                        "fingerprint": "chrome",
                        "mldsa65Verify": mldsa_pub_a,
                    },
                },
            },
        ],
    }
    write_config_dir(root / "panel_node", panel_cnode_cfg)
    panel_proc = start_cnode(binary, root / "panel_node")
    try:
        deadline = time.monotonic() + 10.0
        while panel_server.user_fetches < 1 and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.2)
        resp_panel = await send_vless_probe(panel_entry_port, echo_port)
        assert resp_panel == b"\x00\x00" + PAYLOAD, f"panel REALITY failed: {resp_panel!r}"
    finally:
        stop_cnode(panel_proc)
        panel_server.shutdown()
        panel_server.server_close()
        dest_tls_server.close()
        dest_xver1_server.close()
        dest_xver2_server.close()
        echo_server.close()
        await dest_tls_server.wait_closed()
        await dest_xver1_server.wait_closed()
        await dest_xver2_server.wait_closed()
        await echo_server.wait_closed()

    print("REALITY end-to-end integration test passed (dest/xver, mldsa65, fingerprint, spiderX, V2Board tls=2)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(main(args.binary, args.output))

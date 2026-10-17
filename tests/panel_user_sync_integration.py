"""Exercise panel failures, committed ETags and user revocation via real VLESS."""

import argparse
import contextlib
import http.server
import json
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
import time
import uuid


USER_A = uuid.UUID("11111111-1111-4111-8111-111111111111")
USER_B = uuid.UUID("22222222-2222-4222-8222-222222222222")
PAYLOAD = b"panel-user-sync-regression"


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            while data := self.request.recv(4096):
                self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


class Panel(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, node_port, blocked_port):
        super().__init__(("127.0.0.1", 0), PanelHandler)
        self.node_port = node_port
        self.blocked_port = blocked_port
        self.condition = threading.Condition()
        self.phase = "ready"
        self.pull_phase = self.phase
        self.requests = []

    def enter(self, phase):
        with self.condition:
            self.phase = phase

    def wait_cycles(self, child):
        # Starting the third config request proves two previous iterations have
        # finished, including any failed request and runtime compensation.
        with self.condition:
            phase = self.phase
            deadline = time.monotonic() + 12
            while sum(p == phase and kind == "config" for p, kind, _ in self.requests) < 3:
                assert child.poll() is None, "cnode exited during panel sync"
                remaining = deadline - time.monotonic()
                assert remaining > 0, f"panel sync stopped retrying in {phase}: {self.requests}"
                self.condition.wait(min(remaining, 0.1))

    def user_headers(self, phase):
        with self.condition:
            return [etag for p, kind, etag in self.requests if p == phase and kind == "user"]


class PanelHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body, etag=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if etag is not None:
            self.send_header("ETag", etag)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass  # The timeout case intentionally outlives the request deadline.

    def do_GET(self):
        kind = "config" if "/config?" in self.path else "user"
        requested_etag = self.headers.get("If-None-Match")
        panel = self.server
        with panel.condition:
            # Keep config and users from the same pull consistent even when
            # the test advances while the controller is between HTTP requests.
            if kind == "config":
                panel.pull_phase = panel.phase
            phase = panel.pull_phase
            panel.requests.append((phase, kind, requested_etag))
            panel.condition.notify_all()

        if kind == "config":
            if phase in ("config404", "config503"):
                self.reply(int(phase[-3:]), {"message": "panel unavailable"})
                return
            if phase == "config-invalid":
                self.reply(200, {"message": "not a node configuration"}, '"invalid-config"')
                return
            port = panel.blocked_port if phase == "rejected-update" else panel.node_port
            etag = f"config-{port}"
            if requested_etag == etag:
                self.reply(304, b"")
            else:
                self.reply(200, {
                    "server_port": port, "network": "tcp", "tls": 0,
                    "base_config": {"pull_interval": 1, "push_interval": 3600},
                }, f'"{etag}"')
            return

        if phase in ("user404", "user500"):
            self.reply(int(phase[-3:]), {"message": "panel unavailable"})
            return
        if phase == "user-timeout":
            time.sleep(1.3)
            self.reply(200, {"users": []}, '"invalid-timeout"')
            return
        if phase == "user-json":
            self.reply(200, b'{"users":', '"invalid-json"')
            return
        if phase == "user-schema":
            self.reply(200, {"message": "not a user list"}, '"invalid-schema"')
            return
        if phase == "user-credentials":
            self.reply(200, {"users": [{"id": 1, "uuid": "invalid-uuid-" * 8}]},
                       '"invalid-credentials"')
            return
        if phase == "unexpected304":
            self.reply(304, b"")
            return

        version = "v1"
        user = USER_A
        if phase in ("rejected-update", "recovered"):
            version, user = "v2", USER_B
        elif phase == "restored":
            version, user = "v4", USER_B
        elif phase == "empty":
            version = "empty"
        etag = None if phase == "no-etag" else f"users-{version}"
        if etag and requested_etag == etag:
            self.reply(304, b"")
        else:
            users = [] if phase == "empty" else [{"id": 1, "uuid": str(user)}]
            self.reply(200, {"users": users}, f'"{etag}"' if etag else None)


def receives_echo(node_port, echo_port, user):
    try:
        with socket.create_connection(("127.0.0.1", node_port), timeout=1) as stream:
            stream.settimeout(1)
            stream.sendall(b"\0" + user.bytes + b"\0\1" + struct.pack("!H", echo_port)
                           + b"\1\x7f\0\0\1" + PAYLOAD)
            expected = b"\0\0" + PAYLOAD
            received = b""
            while len(received) < len(expected):
                data = stream.recv(len(expected) - len(received))
                if not data:
                    break
                received += data
            return received == expected
    except (OSError, TimeoutError):
        return False


def check_users(panel, echo_port, accepted, rejected):
    for _ in range(4):  # Exercise both SO_REUSEPORT Workers with fresh sessions.
        for user in accepted:
            assert receives_echo(panel.node_port, echo_port, user), f"{panel.phase}: existing user rejected"
        for user in rejected:
            assert not receives_echo(panel.node_port, echo_port, user), f"{panel.phase}: revoked user accepted"


def main(binary, root):
    binary, root = binary.resolve(), root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    with contextlib.ExitStack() as stack:
        # Keep the conflicting endpoint occupied throughout the failed candidate.
        blocked = stack.enter_context(socket.socket())
        blocked.bind(("127.0.0.1", 0))
        blocked.listen()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            node_port = reservation.getsockname()[1]
        echo = stack.enter_context(EchoServer(("127.0.0.1", 0), Echo))
        panel = stack.enter_context(Panel(node_port, blocked.getsockname()[1]))
        threads = []
        for server in (echo, panel):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        config = {
            "workers": 2, "log": {"enable": False, "logDir": str(root / "logs")},
            "panels": [{"Name": "user-sync", "Type": "V2board",
                        "APIHost": f"http://127.0.0.1:{panel.server_port}",
                        "Key": "fixture-key", "NodeIDs": [1], "NodeType": "vless",
                        "ListenIP": "127.0.0.1", "RequestTimeout": 1}],
        }
        (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
        output = stack.enter_context((root / "child.log").open("w", encoding="utf-8"))
        child = subprocess.Popen([str(binary), "--config-dir", str(root)],
                                 stdout=output, stderr=subprocess.STDOUT)
        try:
            panel.wait_cycles(child)
            check_users(panel, echo.server_address[1], [USER_A], [USER_B])
            assert panel.user_headers("ready")[0] is None
            assert panel.user_headers("ready")[1] == "users-v1"
            for phase in ("config404", "config503", "config-invalid", "user404",
                          "user500", "user-timeout", "user-json", "user-schema",
                          "user-credentials", "unchanged", "rejected-update"):
                panel.enter(phase)
                panel.wait_cycles(child)
                check_users(panel, echo.server_address[1], [USER_A], [USER_B])
                headers = panel.user_headers(phase)
                if not phase.startswith("config"):
                    assert headers and all(value == "users-v1" for value in headers), (
                        f"{phase}: uncommitted user ETag acknowledged: {headers}")

            for phase, accepted, rejected, previous_etag in (
                ("recovered", [USER_B], [USER_A], "users-v1"),
                ("no-etag", [USER_A], [USER_B], "users-v2"),
                ("unexpected304", [USER_A], [USER_B], None),
                ("empty", [], [USER_A, USER_B], None),
                ("restored", [USER_B], [USER_A], "users-empty"),
            ):
                panel.enter(phase)
                panel.wait_cycles(child)
                check_users(panel, echo.server_address[1], accepted, rejected)
                assert panel.user_headers(phase)[0] == previous_etag, (
                    f"{phase}: request validator disagrees with committed users")
        except BaseException:
            output.flush()
            print((root / "child.log").read_text(encoding="utf-8", errors="replace"))
            raise
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
            for server in (echo, panel):
                server.shutdown()
            for thread in threads:
                thread.join(timeout=2)
    print("panel errors preserve authentication; committed ETags retry; valid empty lists revoke and recover")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    main(args.binary, args.output)

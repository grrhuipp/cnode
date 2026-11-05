"""Real TCP panel faults, durable accounting lifecycle, and atomic rule updates."""
import argparse
import contextlib
import http.server
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

from panel_user_sync_integration import EchoServer, Echo, USER_A, PAYLOAD


class Panel(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, node_port):
        super().__init__(("127.0.0.1", 0), Handler)
        self.node_port = node_port
        self.condition = threading.Condition()
        self.mode = "ok"
        self.rule_phase = "none"
        self.push_interval = 1
        self.posts = []
        self.gets = []


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body, etag=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        if etag:
            self.send_header("ETag", etag)
        self.end_headers()
        with contextlib.suppress(OSError):
            self.wfile.write(raw)

    def do_GET(self):
        panel = self.server
        if "/config?" not in self.path:
            self.reply(200, {"users": [{"id": 1, "uuid": str(USER_A)}]}, '"users"')
            return
        with panel.condition:
            phase = panel.rule_phase
            panel.gets.append((phase, self.headers.get("If-None-Match")))
            panel.condition.notify_all()
        routes = []
        if phase == "blocked":
            routes = [{"action": "block", "match": [r"127\.0\.0\.1"]}]
        elif phase == "invalid":
            routes = [{"action": "block", "match": [r"127\.0\.0\.2"]},
                      {"action": "block", "match": ["["]}]
        self.reply(200, {"server_port": panel.node_port, "network": "tcp", "tls": 0,
                         "routes": routes, "base_config": {"pull_interval": 1,
                         "push_interval": panel.push_interval}}, f'"rules-{phase}"')

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if "/push?" not in self.path:
            self.reply(200, {"data": True})
            return
        data = json.loads(body)
        panel = self.server
        with panel.condition:
            mode = panel.mode
            panel.posts.append((mode, data))
            panel.condition.notify_all()
        if not data or mode == "ok":
            self.reply(200, {"data": True})
        elif mode == "non2xx":
            # A server can already have queued some users when a later action
            # fails. The client cannot infer 'not billed' from this status.
            self.reply(503, {"message": "partial application is possible"})
        elif mode == "truncated":
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{")
            self.close_connection = True
        elif mode == "lost":
            # Full request was accepted, but absolutely no response is delivered.
            self.close_connection = True
        elif mode == "kill":
            time.sleep(4)
            self.close_connection = True


def wait_for(predicate, child=None, timeout=12):
    deadline = time.monotonic() + timeout
    while not predicate():
        if child:
            assert child.poll() is None, "cnode exited unexpectedly"
        assert time.monotonic() < deadline, "timed out waiting for fixture state"
        time.sleep(0.03)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def echo(node_port, target_port, target="127.0.0.1"):
    try:
        with socket.create_connection(("127.0.0.1", node_port), timeout=0.5) as sock:
            sock.settimeout(1)
            sock.sendall(b"\0" + USER_A.bytes + b"\0\1" + struct.pack("!H", target_port)
                         + b"\1" + socket.inet_aton(target) + PAYLOAD)
            result = b""
            while len(result) < len(PAYLOAD) + 2:
                chunk = sock.recv(len(PAYLOAD) + 2 - len(result))
                if not chunk:
                    break
                result += chunk
            return result == b"\0\0" + PAYLOAD
    except OSError:
        return False


def start(binary, root, panel):
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.json").write_text(json.dumps({
        "workers": 2, "log": {"loglevel": "debug", "logDir": str(root / "logs")},
        "panels": [{"name": "integrity", "apiHost": f"http://127.0.0.1:{panel.server_port}",
                    "key": "fixture-secret-must-not-persist", "nodeType": "vless", "nodeIDs": [1],
                    "listenIP": "127.0.0.1", "requestTimeout": 1}]}))
    output = (root / "child.log").open("ab")
    child = subprocess.Popen([str(binary), "--config-dir", str(root)], stdout=output, stderr=output)
    output.close()
    return child


def stop(child, killed=False):
    if child.poll() is None:
        child.send_signal(signal.SIGKILL if killed else signal.SIGTERM)
        try:
            code = child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
            raise AssertionError("graceful shutdown did not join")
        assert killed or code == 0, f"graceful shutdown failed: {code}"


def records(root, state):
    return sorted((root / "traffic-journal").glob(f"*/*.{state}"))


def nonempty(panel):
    with panel.condition:
        return [data for _, data in panel.posts if data]


def wait_new_empty_cycles(panel, child):
    with panel.condition:
        baseline = len(panel.posts)
    wait_for(lambda: len(panel.posts) >= baseline + 2, child)


def fault_case(binary, root, mode, echo_port):
    panel = Panel(free_port())
    panel.mode = mode
    thread = threading.Thread(target=panel.serve_forever, daemon=True)
    thread.start()
    child = start(binary, root, panel)
    try:
        wait_for(lambda: echo(panel.node_port, echo_port), child)
        wait_for(lambda: bool(nonempty(panel)), child)
        wait_for(lambda: bool(records(root, "unknown")), child)
        if mode == "kill":
            stop(child, killed=True)
        else:
            count = len(nonempty(panel))
            wait_new_empty_cycles(panel, child)
            assert len(nonempty(panel)) == count, "ambiguous additive request was retried"
            stop(child)
        unknown = [(p.name, p.read_bytes()) for p in records(root, "unknown")]
        assert unknown, "unknown traffic disappeared"
        for path in records(root, "unknown"):
            assert path.stat().st_mode & 0o777 == 0o600
            assert path.parent.stat().st_mode & 0o777 == 0o700
            assert b"fixture-secret" not in path.read_bytes()
        panel.mode = "ok"
        count = len(nonempty(panel))
        child = start(binary, root, panel)
        wait_new_empty_cycles(panel, child)
        assert len(nonempty(panel)) == count, "restart retransmitted unknown traffic"
        assert [(p.name, p.read_bytes()) for p in records(root, "unknown")] == unknown
        stop(child)
        tool = Path(__file__).resolve().parents[1] / "scripts" / "traffic_journal.py"
        path = records(root, "unknown")[0]
        subprocess.run(["python3", str(tool), str(path.parent), "list"], check=True)
        decision = "confirmed-not-applied" if mode == "non2xx" else "confirmed-applied"
        subprocess.run(["python3", str(tool), str(path.parent), "resolve", path.name,
                        "--decision", decision, "--evidence", "fixture operator ledger check"], check=True)
        assert not path.exists(), "explicit reconciliation did not transition the unknown record"
        if decision == "confirmed-not-applied":
            assert path.with_suffix(".ready").exists(), "unapplied delta was not made ready"
            count = len(nonempty(panel))
            child = start(binary, root, panel)
            wait_for(lambda: len(nonempty(panel)) == count + 1, child)
            wait_new_empty_cycles(panel, child)
            assert len(nonempty(panel)) == count + 1, "explicit replay was repeated"
            assert not path.with_suffix(".ready").exists() and not path.exists()
    finally:
        stop(child)
        panel.shutdown()
        panel.server_close()
        thread.join()


def graceful_ready_case(binary, root, echo_port):
    panel = Panel(free_port())
    panel.push_interval = 3600
    thread = threading.Thread(target=panel.serve_forever, daemon=True)
    thread.start()
    child = start(binary, root, panel)
    try:
        wait_for(lambda: echo(panel.node_port, echo_port), child)
        stop(child)
        assert records(root, "ready"), "graceful shutdown lost unsampled final counters"
        assert not nonempty(panel), "long interval unexpectedly transmitted traffic"
        panel.push_interval = 1
        child = start(binary, root, panel)
        wait_for(lambda: bool(nonempty(panel)), child)
        wait_for(lambda: not records(root, "ready") and not records(root, "unknown"), child)
        count = len(nonempty(panel))
        wait_new_empty_cycles(panel, child)
        assert len(nonempty(panel)) == count, "accepted ready batch was sent twice"
    finally:
        stop(child)
        panel.shutdown()
        panel.server_close()
        thread.join()


def rule_case(binary, root, echo_port):
    panel = Panel(free_port())
    panel.rule_phase = "invalid"
    thread = threading.Thread(target=panel.serve_forever, daemon=True)
    thread.start()
    child = start(binary, root, panel)
    try:
        wait_for(lambda: bool(panel.gets), child)
        time.sleep(0.3)
        assert not echo(panel.node_port, echo_port, "127.0.0.1"), "invalid first config admitted listener"
        stop(child)
        panel.rule_phase = "blocked"
        child = start(binary, root, panel)
        wait_for(lambda: echo(panel.node_port, echo_port, "127.0.0.2"), child)
        assert not echo(panel.node_port, echo_port), "initial blocking policy was not installed"
        panel.rule_phase = "invalid"
        baseline = len(panel.gets)
        wait_for(lambda: len(panel.gets) >= baseline + 3, child)
        assert not echo(panel.node_port, echo_port), "bad candidate removed the committed blocking rule"
        assert echo(panel.node_port, echo_port, "127.0.0.2"), "bad candidate partially installed a valid prefix"
        invalid_headers = [etag for phase, etag in panel.gets[baseline:] if phase == "invalid"]
        assert invalid_headers and all(etag == "rules-blocked" for etag in invalid_headers), invalid_headers
    finally:
        stop(child)
        panel.shutdown()
        panel.server_close()
        thread.join()


def main(binary, root):
    binary, root = binary.resolve(), root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix="run-", dir=root))
    print(f"panel integrity artifacts: {root}", flush=True)
    with EchoServer(("0.0.0.0", 0), Echo) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for mode in ("non2xx", "truncated", "lost", "kill"):
                fault_case(binary, root / mode, mode, server.server_address[1])
            graceful_ready_case(binary, root / "graceful-ready", server.server_address[1])
            rule_case(binary, root / "rules", server.server_address[1])
        finally:
            server.shutdown()
            thread.join()
    print("panel integrity: HTTP ambiguity quarantined; ready replay; graceful flush; atomic rules")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    main(args.binary, args.root)

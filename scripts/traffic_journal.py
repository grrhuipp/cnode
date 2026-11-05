#!/usr/bin/env python3
"""Inspect and reconcile UniProxy traffic journals; never infer a billing outcome.

Run with cnode stopped. 'confirmed-applied' removes a reconciled unknown batch;
'confirmed-not-applied' makes it eligible for one new transmission on restart.
The latter MUST be based on panel-side evidence, not on an HTTP failure alone.
"""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 64 * 1024 * 1024
MAX_AUDIT_BYTES = 1024 * 1024
NAME = re.compile(r"batch-[A-Za-z0-9]{6}\.(ready|unknown)\Z")


def read_record(directory_fd, name):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("invalid record type or size")
        raw = source.read(MAX_BYTES + 1)
    rows = json.loads(raw)
    if not isinstance(rows, list):
        raise ValueError("record must contain a row array")
    for row in rows:
        if (not isinstance(row, list) or len(row) != 3 or
                any(type(value) is not int for value in row) or
                row[0] <= 0 or min(row[1:]) < 0 or max(row) > 2**63 - 1):
            raise ValueError("invalid record counters")
    return raw, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="one hashed panel/node journal directory")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    resolve = commands.add_parser("resolve")
    resolve.add_argument("record", help="exact batch-XXXXXX.unknown filename")
    resolve.add_argument("--decision", required=True,
                         choices=("confirmed-applied", "confirmed-not-applied"))
    resolve.add_argument("--evidence", required=True,
                         help="panel-side reconciliation reference (no API keys; at most 512 characters)")
    args = parser.parse_args()
    directory_fd = os.open(args.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    lock_fd = -1
    try:
        lock_fd = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                          0o600, dir_fd=directory_fd)
        # Reconciliation must never race the daemon, even for distinct records.
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "list":
            for name in sorted(os.listdir(directory_fd)):
                if not NAME.fullmatch(name):
                    continue
                _, rows = read_record(directory_fd, name)
                print(json.dumps({"record": name, "state": name.rsplit(".", 1)[1],
                                  "users": len(rows), "upload": sum(r[1] for r in rows),
                                  "download": sum(r[2] for r in rows)}))
            return
        if not NAME.fullmatch(args.record) or not args.record.endswith(".unknown"):
            parser.error("resolve requires one exact unknown record filename")
        if not args.evidence.strip() or len(args.evidence) > 512:
            parser.error("evidence must contain 1..512 characters")
        raw, rows = read_record(directory_fd, args.record)
        ready = args.record.removesuffix(".unknown") + ".ready"
        if args.decision == "confirmed-not-applied":
            try:
                os.stat(ready, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("ready destination already exists")
        # A durable intent is an audit trail, NOT a claim of atomic billing or
        # completion. The record's suffix/existence remains the recovery truth.
        entry = (json.dumps({"event": "reconciliation-intent", "record": args.record,
                             "sha256": hashlib.sha256(raw).hexdigest(),
                             "decision": args.decision, "evidence": args.evidence,
                             "time": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                            ensure_ascii=True) + "\n").encode()
        audit_fd = os.open(".reconciliation.jsonl", os.O_CREAT | os.O_WRONLY | os.O_APPEND |
                           os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(audit_fd, "ab", buffering=0) as audit:
            info = os.fstat(audit.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size + len(entry) > MAX_AUDIT_BYTES:
                raise ValueError("audit limit reached; archive .reconciliation.jsonl while stopped first")
            view = memoryview(entry)
            while view:
                count = audit.write(view)
                if not count:
                    raise OSError("short audit write")
                view = view[count:]
            os.fsync(audit.fileno())
        os.fsync(directory_fd)
        if args.decision == "confirmed-applied":
            os.unlink(args.record, dir_fd=directory_fd)
        else:
            os.rename(args.record, ready, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
        print(json.dumps({"event": "reconciled", "record": args.record,
                          "decision": args.decision, "users": len(rows)}))
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        os.close(directory_fd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"traffic journal: {error}") from error

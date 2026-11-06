"""Owned loopback VLESS/native Shadowsocks UDP integration tests.

Requires Python and cryptography for independent AES-GCM peers and authenticated
QUIC Initial generation. native_ss2022_isolation runs four Workers with both
SIP022 AES and XChaCha20-Poly1305 (blake3 and libsodium required), repeatedly
changes real UDP source ports, and requires logged passive owner changes. It
checks delayed old-path rejection, current-path reordering, reply endpoint and
outbound tuple/session continuity, replay, and second-credential isolation.
DNS timeout cases use an owned silent UDP listener on a dynamically assigned
loopback port. No external server or credentials are involved.
"""
import argparse
import asyncio
import base64
from contextlib import ExitStack, contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import time
import uuid

import ctypes
import ctypes.util
import hmac

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ModuleNotFoundError:
    hashes = None
    HKDF = None
    _libcrypto = ctypes.CDLL('libcrypto.so.3')
    _libcrypto.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    _libcrypto.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    _libcrypto.EVP_aes_128_gcm.restype = ctypes.c_void_p
    _libcrypto.EVP_CipherInit_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    _libcrypto.EVP_CIPHER_CTX_ctrl.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    _libcrypto.EVP_CipherUpdate.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
        ctypes.c_char_p, ctypes.c_int]
    _libcrypto.EVP_CipherFinal_ex.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]

    class AESGCM:
        def __init__(self, key: bytes):
            self._key = key

        def encrypt(self, nonce: bytes, data: bytes, aad):
            ctx = _libcrypto.EVP_CIPHER_CTX_new()
            try:
                assert _libcrypto.EVP_CipherInit_ex(ctx, _libcrypto.EVP_aes_128_gcm(), None, None, None, 1) == 1
                assert _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), None) == 1
                assert _libcrypto.EVP_CipherInit_ex(ctx, None, None, self._key, nonce, 1) == 1
                out = ctypes.create_string_buffer(len(data))
                out_len = ctypes.c_int(0)
                assert _libcrypto.EVP_CipherUpdate(ctx, out, ctypes.byref(out_len), data, len(data)) == 1
                final_len = ctypes.c_int(0)
                assert _libcrypto.EVP_CipherFinal_ex(ctx, ctypes.byref(out, out_len.value), ctypes.byref(final_len)) == 1
                tag = ctypes.create_string_buffer(16)
                assert _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, tag) == 1
                return out.raw[:out_len.value + final_len.value] + tag.raw
            finally:
                _libcrypto.EVP_CIPHER_CTX_free(ctx)

        def decrypt(self, nonce: bytes, data: bytes, aad):
            if len(data) < 16:
                raise ValueError('ciphertext too short')
            body, tag = data[:-16], data[-16:]
            ctx = _libcrypto.EVP_CIPHER_CTX_new()
            try:
                assert _libcrypto.EVP_CipherInit_ex(ctx, _libcrypto.EVP_aes_128_gcm(), None, None, None, 0) == 1
                assert _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x9, len(nonce), None) == 1
                assert _libcrypto.EVP_CipherInit_ex(ctx, None, None, self._key, nonce, 0) == 1
                out = ctypes.create_string_buffer(len(body))
                out_len = ctypes.c_int(0)
                assert _libcrypto.EVP_CipherUpdate(ctx, out, ctypes.byref(out_len), body, len(body)) == 1
                tag_buf = ctypes.create_string_buffer(tag, 16)
                assert _libcrypto.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, tag_buf) == 1
                final_len = ctypes.c_int(0)
                if _libcrypto.EVP_CipherFinal_ex(ctx, ctypes.byref(out, out_len.value), ctypes.byref(final_len)) != 1:
                    raise ValueError('GCM tag mismatch')
                return out.raw[:out_len.value + final_len.value]
            finally:
                _libcrypto.EVP_CIPHER_CTX_free(ctx)
USER = uuid.UUID('b831381d-6324-4d53-ad4f-8cda48b30811')
SECOND_USER = uuid.UUID('c942492e-7435-5e64-be5f-9ddb59c41922')
QUIC_SNI = 'fragmented-quic.test'
QUIC_MODES = ('quic_fragmented', 'quic_missing', 'quic_interrupted', 'quic_invalid',
              'native_quic_fragmented', 'native_quic_missing',
              'native_quic_interrupted', 'native_quic_invalid')


def quic_varint(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return struct.pack('!H', value | 0x4000)
    raise ValueError('test QUIC varint is too large')


def fragmented_quic_initials():
    """Two independently authenticated RFC 9001 v1 Initials, one ClientHello."""
    if HKDF is None:
        raise RuntimeError('fragmented QUIC integration cases require cryptography')

    def extension(kind, data):
        return struct.pack('!HH', kind, len(data)) + data

    name = QUIC_SNI.encode('ascii')
    server_name = b'\0' + struct.pack('!H', len(name)) + name
    extensions = (
        extension(43, b'\2\3\4') +
        extension(10, b'\0\2\0\x1d') +
        extension(13, b'\0\4\x08\x04\x04\x03') +
        extension(51, b'\0\x24\0\x1d\0\x20' + bytes(range(32))) +
        extension(16, b'\0\3\2h3') +
        extension(57, b'\x0f\0') +  # initial_source_connection_id matches empty SCID
        # Put SNI beyond the first CRYPTO frame: neither packet alone contains
        # a complete ClientHello, and sniffing only packet one cannot route.
        extension(21, b'\0' * 1700) +
        extension(0, struct.pack('!H', len(server_name)) + server_name))
    hello = (b'\3\3' + bytes(range(32)) + b'\0\0\2\x13\1\1\0' +
             struct.pack('!H', len(extensions)) + extensions)
    hello = b'\1' + len(hello).to_bytes(3, 'big') + hello
    dcid = bytes.fromhex('8394c8f03e515708')
    initial_secret = hmac.new(
        bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a'), dcid,
        hashlib.sha256).digest()

    def expand(secret, label, length):
        label = b'tls13 ' + label
        info = struct.pack('!H', length) + bytes([len(label)]) + label + b'\0'
        return hmac.new(secret, info + b'\1', hashlib.sha256).digest()[:length]

    secret = expand(initial_secret, b'client in', 32)
    key = expand(secret, b'quic key', 16)
    iv = expand(secret, b'quic iv', 12)
    hp = expand(secret, b'quic hp', 16)
    packets = []
    for number, (offset, fragment) in enumerate(((0, hello[:1000]), (1000, hello[1000:]))):
        prefix = b'\xc1\0\0\0\1' + bytes([len(dcid)]) + dcid + b'\0\0'
        # The length covers the two-byte packet number, ciphertext and tag.
        header = prefix + quic_varint(1250 - len(prefix) - 2)
        pn_offset = len(header)
        header += struct.pack('!H', number)
        crypto = b'\6' + quic_varint(offset) + quic_varint(len(fragment)) + fragment
        padding_size = 1250 - len(header) - 16 - len(crypto)
        if padding_size < 0:
            raise AssertionError('ClientHello fragment exceeds test Initial size')
        nonce = (int.from_bytes(iv, 'big') ^ number).to_bytes(12, 'big')
        packet = bytearray(header + AESGCM(key).encrypt(
            nonce, crypto + b'\0' * padding_size, header))
        encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = encryptor.update(bytes(packet[pn_offset + 4:pn_offset + 20])) + encryptor.finalize()
        packet[0] ^= mask[0] & 0x0f
        packet[pn_offset] ^= mask[1]
        packet[pn_offset + 1] ^= mask[2]
        packets.append(bytes(packet))
    return packets


class SilentDns(asyncio.DatagramProtocol):
    def __init__(self):
        self.requests = 0

    def datagram_received(self, data, peer):
        self.requests += 1


class GatedReplyPeer(asyncio.DatagramProtocol):
    """Hold replies until the test has observed every request in a round."""
    def __init__(self):
        self.transport = None
        self.requests = asyncio.Queue()
        self.received = []
        self.errors = []
        self.delayed = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, peer):
        self.received.append(len(data))
        self.requests.put_nowait((data, peer))

    async def next_round(self, expected_payloads):
        observed = [await asyncio.wait_for(self.requests.get(), 4)
                    for _ in expected_payloads]
        by_payload = {payload: address for payload, address in observed}
        if len(by_payload) != len(observed) or set(by_payload) != set(expected_payloads):
            raise AssertionError(f'peer round mismatch: {observed!r}')
        return by_payload

    def reply(self, address, payload):
        self.transport.sendto(payload, address)


class EchoPeer(asyncio.DatagramProtocol):
    def __init__(self, protocol, mode):
        self.protocol = protocol
        self.mode = mode
        self.received = []
        self.payloads = []
        self.errors = []
        self.transport = None
        self.delayed = []

    def connection_made(self, transport):
        self.transport = transport

    @staticmethod
    def cipher(salt, password=b'secret'):
        master = hashlib.md5(password).digest()
        if HKDF is not None:
            key = HKDF(algorithm=hashes.SHA1(), length=16, salt=salt, info=b'ss-subkey').derive(master)
        else:
            prk = hmac.new(salt, master, hashlib.sha1).digest()
            key = hmac.new(prk, b'ss-subkey\x01', hashlib.sha1).digest()[:16]
        return AESGCM(key)
    def datagram_received(self, data, peer):
        try:
            if self.protocol == 'shadowsocks':
                plain = self.cipher(data[:16]).decrypt(b'\0' * 12, data[16:], None)
                if plain[:7] != b'\1\x7f\0\0\1\0\x35':
                    raise AssertionError('Shadowsocks embedded target changed')
                self.received.append(len(plain) - 7)
                self.payloads.append(plain[7:])
                # An unauthenticated packet must not prevent the valid reply.
                self.transport.sendto(b'invalid encrypted datagram', peer)
                salt = os.urandom(16)
                reply = salt + self.cipher(salt).encrypt(b'\0' * 12, plain, None)
            else:
                self.received.append(len(data))
                self.payloads.append(data)
                reply = data
            if self.mode == 'late_reply':
                self.delayed.append(asyncio.get_running_loop().call_later(0.2, self.transport.sendto, reply, peer))
            else:
                self.transport.sendto(reply, peer)
        except Exception as error:
            self.errors.append(repr(error))


async def close_writer(writer):
    if writer is None:
        return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (ConnectionError, TimeoutError):
        writer.transport.abort()


class Client:
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.response_header = False

    @classmethod
    async def connect(cls, port, target_host, target_port, user=USER):
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        if target_host == '127.0.0.1':
            address = b'\1\x7f\0\0\1'
        else:
            name = target_host.encode('ascii')
            address = b'\2' + bytes([len(name)]) + name
        writer.write(b'\0' + user.bytes + b'\0\2' + struct.pack('!H', target_port) + address)
        await writer.drain()
        return cls(reader, writer)

    async def send(self, payload):
        self.writer.write(struct.pack('!H', len(payload)) + payload)
        await self.writer.drain()

    async def receive(self, expected):
        if not self.response_header:
            if await asyncio.wait_for(self.reader.readexactly(2), 4) != b'\0\0':
                raise AssertionError('VLESS response header changed')
            self.response_header = True
        size = struct.unpack('!H', await asyncio.wait_for(self.reader.readexactly(2), 4))[0]
        packet = await asyncio.wait_for(self.reader.readexactly(size), 4)
        if packet != expected:
            raise AssertionError(f'UDP datagram changed: expected {len(expected)}, received {size}')


class NativeClient:
    def __init__(self, sock, target_port, password=b'secret'):
        self.sock = sock
        self.password = password
        self.target = b'\1\x7f\0\0\1' + struct.pack('!H', target_port)
        self.writer = None

    @classmethod
    async def connect(cls, port, target_host, target_port, user=USER):
        assert target_host == '127.0.0.1'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.connect(('127.0.0.1', port))
        return cls(sock, target_port, b'secret' if user == USER else b'second-secret')

    async def send(self, payload):
        salt = os.urandom(16)
        packet = salt + EchoPeer.cipher(salt, self.password).encrypt(b'\0' * 12, self.target + payload, None)
        await asyncio.get_running_loop().sock_sendall(self.sock, packet)

    async def receive(self, expected):
        packet = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(self.sock, 65536), 4)
        plain = EchoPeer.cipher(packet[:16], self.password).decrypt(b'\0' * 12, packet[16:], None)
        if plain != self.target + expected:
            raise AssertionError('native UDP target or datagram boundary changed')


class Native2022Client(NativeClient):
    """Independent SIP022 AES/XChaCha peer; session IDs deliberately cross users."""
    def __init__(self, sock, target_port, password=b'secret', cipher='aes'):
        super().__init__(sock, target_port, password)
        if HKDF is None:
            raise RuntimeError('SS2022 integration requires Python cryptography and blake3')
        from blake3 import blake3
        self.blake3 = blake3
        self.cipher = cipher
        key_size = 16 if cipher == 'aes' else 32
        start = 0 if password == b'secret' else key_size
        self.key = bytes(range(start, start + key_size))
        if cipher == 'chacha':
            library = ctypes.util.find_library('sodium')
            if library is None:
                raise RuntimeError('SS2022 ChaCha integration requires libsodium')
            self.sodium = ctypes.CDLL(library)
            self.sodium.sodium_init.restype = ctypes.c_int
            if self.sodium.sodium_init() < 0:
                raise RuntimeError('libsodium initialization failed')
            self.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong),
                ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p,
                ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
            self.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulonglong), ctypes.c_void_p,
                ctypes.c_char_p, ctypes.c_ulonglong, ctypes.c_char_p,
                ctypes.c_ulonglong, ctypes.c_char_p, ctypes.c_char_p]
        self.session_id = bytes.fromhex('00123456789abcde')
        self.packet_id = 0
        self.server_session_id = None
        self.server_packet_id = None
        self.server_packet_ids = []

    @classmethod
    async def connect(cls, port, target_host, target_port, user=USER, cipher='aes'):
        assert target_host == '127.0.0.1'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            sock.connect(('127.0.0.1', port))
            return cls(sock, target_port,
                       b'secret' if user == USER else b'second-secret', cipher)
        except Exception:
            sock.close()
            raise

    def xchacha(self, nonce, data, encrypt):
        output = ctypes.create_string_buffer(len(data) + 16)
        size = ctypes.c_ulonglong()
        if encrypt:
            status = self.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
                output, ctypes.byref(size), data, len(data), None, 0, None,
                nonce, self.key)
        else:
            status = self.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                output, ctypes.byref(size), None, data, len(data), None, 0,
                nonce, self.key)
        if status != 0:
            raise ValueError('XChaCha20-Poly1305 authentication failed')
        return output.raw[:size.value]

    def subkey(self, session_id):
        return self.blake3(self.key + session_id,
                           derive_key_context='shadowsocks 2022 session subkey').digest(16)

    def header(self, header, encrypt):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB())
        operation = cipher.encryptor() if encrypt else cipher.decryptor()
        return operation.update(header) + operation.finalize()

    def encode(self, payload):
        header = self.session_id + struct.pack('!Q', self.packet_id)
        self.packet_id += 1
        body = b'\0' + struct.pack('!QH', int(time.time()), 0) + self.target + payload
        if self.cipher == 'aes':
            packet = self.header(header, True) + AESGCM(self.subkey(self.session_id)).encrypt(
                header[4:], body, None)
        else:
            nonce = os.urandom(24)
            packet = nonce + self.xchacha(nonce, header + body, True)
        return packet

    async def send(self, payload):
        packet = self.encode(payload)
        await asyncio.get_running_loop().sock_sendall(self.sock, packet)
        return packet

    async def receive(self, expected):
        packet = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(self.sock, 65536), 4)
        if self.cipher == 'aes':
            header = self.header(packet[:16], False)
            plain = AESGCM(self.subkey(header[:8])).decrypt(header[4:], packet[16:], None)
        else:
            decoded = self.xchacha(packet[:24], packet[24:], False)
            header, plain = decoded[:16], decoded[16:]
        if (len(plain) < 19 or plain[0] != 1 or plain[9:17] != self.session_id or
                abs(int(time.time()) - int.from_bytes(plain[1:9], 'big')) > 30):
            raise AssertionError('invalid SS2022 response session header')
        padding = int.from_bytes(plain[17:19], 'big')
        if plain[19 + padding:] != self.target + expected:
            raise AssertionError('SS2022 response crossed an owner or datagram boundary')
        server_session_id = header[:8]
        server_packet_id = int.from_bytes(header[8:], 'big')
        if self.server_session_id is not None:
            if server_session_id != self.server_session_id:
                raise AssertionError('SS2022 response session changed within a live association')
            if server_packet_id <= self.server_packet_id:
                raise AssertionError('SS2022 response packet ID did not advance')
        self.server_session_id = server_session_id
        self.server_packet_id = server_packet_id
        self.server_packet_ids.append(server_packet_id)


def passive_handoffs(output):
    """Only committed owner-change records count; never infer workers from IDs."""
    records = []
    for path in (output / 'child.log', output / 'handoff.log'):
        if not path.exists():
            continue
        text = path.read_text(encoding='utf-8', errors='replace')
        path_records = []
        for worker, previous_worker, session in re.findall(
                r'UDP passive handoff worker=(\d+) previous_worker=(\d+) session=(\d+)\b', text):
            path_records.append({'worker': int(worker), 'previous_worker': int(previous_worker),
                                 'session': int(session)})
        # Console/file sinks can mirror the same event. Count one complete sink,
        # not both copies, when requiring repeated owner changes.
        if len(path_records) > len(records):
            records = path_records
    return records


async def assert_datagram_rejected(packet, source, sockets, peer, reason):
    """Rejected ciphertext must reach neither the target nor any client."""
    loop = asyncio.get_running_loop()
    await loop.sock_sendall(source, packet)
    pending = [asyncio.create_task(peer.requests.get())]
    pending.extend(asyncio.create_task(loop.sock_recv(sock, 65536)) for sock in sockets)
    try:
        ready, _ = await asyncio.wait(pending, timeout=0.3,
                                      return_when=asyncio.FIRST_COMPLETED)
        if ready:
            if pending[0] in ready:
                raise AssertionError(f'{reason} reached direct outbound: {pending[0].result()!r}')
            raise AssertionError(f'{reason} delivered an unexpected client echo')
    finally:
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


async def exercise_native_handoff(inbound_port, peer_port, peer, clients, output,
                                  result, cipher, rebind_attempts):
    first = await Native2022Client.connect(inbound_port, '127.0.0.1', peer_port, cipher=cipher)
    clients.append(first)
    second = await Native2022Client.connect(inbound_port, '127.0.0.1', peer_port,
                                            SECOND_USER, cipher=cipher)
    clients.append(second)
    # Same source tuple and session ID; only the authenticated key distinguishes users.
    second.sock.close()
    second.sock = first.sock
    first_payload, second_payload = b'client-one-round-one', b'client-two-round-one'
    retained_packet = await first.send(first_payload)
    await second.send(second_payload)
    initial = await peer.next_round((first_payload, second_payload))
    first_address, second_address = initial[first_payload], initial[second_payload]
    if first_address[1] == second_address[1]:
        raise AssertionError('isolated Freedom sessions shared an outbound source port')
    peer.reply(second_address, second_payload)
    await second.receive(second_payload)
    peer.reply(first_address, first_payload)
    await first.receive(first_payload)
    sockets = [second.sock]
    source_ports = [first.sock.getsockname()[1]]
    result['client_session_id'] = int.from_bytes(first.session_id, 'big')
    result['workers'] = 4
    result['peer_source_ports'] = [first_address[1], second_address[1]]
    result['rebind_source_ports'] = source_ports
    result['replay_probes'] = 0
    result['stale_path_probes'] = 0
    result['reordered_current_path_packets'] = 0
    expected_lengths = [len(first_payload), len(second_payload)]
    with ExitStack() as cleanup:
        for attempt in range(rebind_attempts):
            old_path = first.sock
            delayed_payload = f'client-one-delayed-{attempt}'.encode()
            # Reserve N without sending it. N+1 must establish the new path
            # before this unseen, authenticated N arrives on the previous path.
            delayed_packet = first.encode(delayed_payload)
            # Keep every previous socket bound: retries must use genuinely fresh
            # source ports, not close/reopen an existing path or simulate a Worker.
            moved = cleanup.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            moved.setblocking(False)
            moved.connect(('127.0.0.1', inbound_port))
            first.sock = moved
            sockets.append(moved)
            source_port = moved.getsockname()[1]
            if source_port in source_ports:
                raise AssertionError('rebinding reused an earlier source port')
            source_ports.append(source_port)
            # Probe before admission on the new path, then again after its valid
            # packet. Replays must neither create an association nor steal ownership.
            await assert_datagram_rejected(
                retained_packet, moved, sockets, peer, 'replayed ciphertext')
            result['replay_probes'] += 1
            first_payload = f'client-one-rebind-{attempt}'.encode()
            second_payload = f'client-two-rebind-{attempt}'.encode()
            await first.send(first_payload)
            await second.send(second_payload)
            observed = await peer.next_round((first_payload, second_payload))
            if observed[first_payload] != first_address or observed[second_payload] != second_address:
                raise AssertionError('UDP association outbound tuple changed after source rebinding')
            expected_lengths.extend((len(first_payload), len(second_payload)))
            # Reverse replies expose cross-credential socket/session contamination.
            peer.reply(second_address, second_payload)
            await second.receive(second_payload)
            peer.reply(first_address, first_payload)
            await first.receive(first_payload)
            await assert_datagram_rejected(
                retained_packet, moved, sockets, peer, 'replayed ciphertext')
            result['replay_probes'] += 1
            await assert_datagram_rejected(
                delayed_packet, old_path, sockets, peer, 'delayed old-path ciphertext')
            result['stale_path_probes'] += 1
            # No current-path uplink may repair a stolen reply route before this
            # reply: it must still reach the last committed source address.
            reply_payload = f'reply-after-stale-path-{attempt}'.encode()
            peer.reply(first_address, reply_payload)
            await first.receive(reply_payload)
            # Rejecting stale path metadata must not consume the replay slot or
            # impose global receive ordering: the same unseen N is valid here.
            await asyncio.get_running_loop().sock_sendall(moved, delayed_packet)
            reordered = await peer.next_round((delayed_payload,))
            if reordered[delayed_payload] != first_address:
                raise AssertionError('current-path reordering changed the outbound tuple')
            expected_lengths.append(len(delayed_payload))
            peer.reply(first_address, delayed_payload)
            await first.receive(delayed_payload)
            result['reordered_current_path_packets'] += 1
            await assert_datagram_rejected(
                delayed_packet, moved, sockets, peer, 'reordered packet replay')
            result['replay_probes'] += 1
        # Exercise both credentials once more after the final handoff/replay probe.
        for client, address, payload in (
                (first, first_address, b'client-one-after-handoff'),
                (second, second_address, b'client-two-after-handoff')):
            await client.send(payload)
            observed = await peer.next_round((payload,))
            if observed[payload] != address:
                raise AssertionError('post-handoff outbound tuple changed')
            expected_lengths.append(len(payload))
            peer.reply(address, payload)
            await client.receive(payload)
        result['server_session_ids'] = [first.server_session_id.hex(), second.server_session_id.hex()]
        result['server_packet_ids'] = [first.server_packet_ids, second.server_packet_ids]
        if peer.received != expected_lengths or not peer.requests.empty():
            raise AssertionError('unexpected direct outbound packet count or replay delivery')


async def exercise_quic(client, mode, result):
    first, second = fragmented_quic_initials()
    expected = [first]
    started = time.monotonic()
    await client.send(first)
    if mode.endswith('_missing'):
        # No second packet and no EOF: sniff timeout, not connection closure,
        # must release the first datagram and leave the association usable.
        await asyncio.wait_for(client.receive(first), 1)
        elapsed = time.monotonic() - started
        result['fallback_seconds'] = round(elapsed, 3)
    else:
        await asyncio.sleep(0.02)
        if mode.endswith('_fragmented'):
            next_packet = second
        elif mode.endswith('_invalid'):
            # Preserve the header-protection sample; corrupt only the GCM tag.
            next_packet = second[:-1] + bytes([second[-1] ^ 1])
        else:
            next_packet = b'non-QUIC-between-CRYPTO-fragments'
        expected.append(next_packet)
        terminal_started = time.monotonic()
        await client.send(next_packet)
        # Completion must release both original packets to the selected peer;
        # parser unit coverage distinguishes terminal errors from need-more.
        await asyncio.wait_for(client.receive(first), 1)
        result['terminal_reply_seconds'] = round(time.monotonic() - terminal_started, 3)
        await asyncio.wait_for(client.receive(next_packet), 1)
    if not mode.endswith('_fragmented'):
        # A final valid fragment arriving after fallback must not re-route or
        # disappear into an abandoned sniff read.
        expected.append(second)
        await client.send(second)
        await asyncio.wait_for(client.receive(second), 1)
    # Exercise ordinary relay after the replay batch, including scattered data.
    for packet in (bytes(range(256)) * 80, b'after-QUIC-sniff'):
        expected.append(packet)
        await client.send(packet)
        await asyncio.wait_for(client.receive(packet), 1)
    if client.writer is not None:
        client.writer.write_eof()
    return expected


@contextmanager
def reserve_inbound_port(native):
    # Native Shadowsocks starts TCP and UDP on the same port. A UDP-only
    # reservation can select a port already used by another test's TCP socket.
    for _ in range(64):
        with ExitStack() as sockets:
            tcp = sockets.enter_context(socket.socket())
            tcp.bind(('127.0.0.1', 0))
            address = tcp.getsockname()
            if native:
                udp = sockets.enter_context(socket.socket(type=socket.SOCK_DGRAM))
                try:
                    udp.bind(address)
                except OSError as error:
                    if error.errno != errno.EADDRINUSE:
                        raise
                    continue
            yield address[1]
            return
    raise RuntimeError('no free TCP/UDP inbound port after 64 candidates')


async def run_case(binary, output, protocol, mode, ss2022_cipher='aes', rebind_attempts=16):
    output.mkdir(parents=True, exist_ok=True)
    quic_case = mode in QUIC_MODES
    handoff_case = mode == 'native_ss2022_isolation'
    dns = SilentDns()
    loop = asyncio.get_running_loop()
    dns_transport = None
    if mode in ('dns_timeout', 'shared_cancel') or quic_case:
        dns_transport, _ = await loop.create_datagram_endpoint(
            lambda: dns, local_addr=('127.0.0.1' if quic_case else '127.77.0.2', 0))
    dns_address = dns_transport.get_extra_info('sockname') if dns_transport else None
    dns_server = f'{dns_address[0]}:{dns_address[1]}' if dns_address else '127.77.0.2'
    isolated = mode in ('isolation', 'isolation_cancel', 'native_isolation',
                        'native_ss2022_isolation')
    peer = GatedReplyPeer() if isolated else EchoPeer(protocol, mode)
    peer_transport, _ = await loop.create_datagram_endpoint(lambda: peer, local_addr=('127.0.0.1', 0))
    peer_port = peer_transport.get_extra_info('sockname')[1]
    fallback_peer = None
    fallback_transport = None
    if quic_case:
        fallback_peer = EchoPeer(protocol, mode)
        fallback_transport, _ = await loop.create_datagram_endpoint(
            lambda: fallback_peer, local_addr=('127.0.0.1', 0))
    with reserve_inbound_port(mode.startswith('native_')) as inbound_port:
        outbound = {'tag': 'udp-out', 'protocol': protocol, 'settings': {}}
        if protocol == 'shadowsocks':
            outbound['settings'] = {'servers': [{
                'address': 'udp-sink.test' if mode == 'dns_timeout' else '127.0.0.1',
                'port': peer_port, 'method': 'aes-128-gcm', 'password': 'secret'}]}
        configs = {
            'config.json': {'workers': 1, 'timeouts': {'write': 1, 'connIdle': 30, 'downlinkOnly': 1},
                            'dns': {'servers': [dns_server], 'timeout': 10},
                            'log': {'enable': False, 'logDir': (output / 'logs').as_posix()}},
            'inbounds.json': [{'tag': 'udp-probe', 'protocol': 'vless', 'listen': '127.0.0.1',
                               'port': inbound_port, 'routingEnabled': True,
                               'settings': {'clients': [{'id': str(USER)},
                                                         {'id': str(SECOND_USER)}] if isolated else
                                                        [{'id': str(USER)}]}}],
            'outbounds.json': [outbound],
            'routing.json': {'rules': [{'type': 'field', 'inboundTag': ['udp-probe'], 'outboundTag': 'udp-out'}]},
        }
        sniffing = quic_case or mode in ('sniff_echo', 'native_sniff_echo', 'sniff_burst', 'native_sniff_burst')
        configs['inbounds.json'][0]['sniffing'] = {'enabled': sniffing}
        if quic_case:
            configs['inbounds.json'][0]['sniffing']['routeOnly'] = True
            configs['inbounds.json'][0]['sniffing']['destOverride'] = ['quic']
            configs['outbounds.json'].append({
                'tag': 'fallback-out', 'protocol': 'shadowsocks',
                'settings': {'servers': [{
                    'address': '127.0.0.1',
                    'port': fallback_transport.get_extra_info('sockname')[1],
                    'method': 'aes-128-gcm', 'password': 'secret'}]}})
            configs['routing.json'] = {'domainStrategy': 'AsIs', 'rules': [
                {'type': 'field', 'domain': ['full:' + QUIC_SNI], 'outboundTag': 'udp-out'},
                {'type': 'field', 'inboundTag': ['udp-probe'], 'outboundTag': 'fallback-out'}]}
        if mode.startswith('native_'):
            configs['inbounds.json'][0]['protocol'] = 'shadowsocks'
            configs['inbounds.json'][0]['settings'] = {
                'method': 'aes-128-gcm', 'clients': [{'password': 'secret'}]}
            if isolated:
                configs['inbounds.json'][0]['settings']['clients'].append(
                    {'password': 'second-secret'})
            if handoff_case:
                key_size = 16 if ss2022_cipher == 'aes' else 32
                configs['inbounds.json'][0]['settings'] = {
                    'method': ('2022-blake3-aes-128-gcm' if ss2022_cipher == 'aes'
                               else '2022-blake3-chacha20-poly1305'),
                    'clients': [{'password': base64.b64encode(bytes(range(start, start + key_size))).decode()}
                                for start in (0, key_size)]}
                configs['config.json']['workers'] = 4
                configs['config.json']['log'] = {
                    'loglevel': 'debug', 'logDir': output.as_posix(),
                    'error': 'handoff.log', 'access': 'access.log',
                    'rotateDaily': False, 'gzip': False}
                # A reused output directory must not satisfy this run's assertion.
                (output / 'handoff.log').write_text('', encoding='utf-8')
        for name, config in configs.items():
            (output / name).write_text(json.dumps(config), encoding='utf-8')
    clients = []
    result = {'protocol': protocol, 'mode': mode}
    if handoff_case:
        result['cipher'] = ss2022_cipher
    with (output / 'child.log').open('w', encoding='utf-8') as logfile:
        child = subprocess.Popen([str(binary), '--config-dir', str(output)], stdout=logfile,
                                 stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 8
            while 'server started' not in (output / 'child.log').read_text(encoding='utf-8', errors='replace'):
                if child.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError('cnode did not start')
                await asyncio.sleep(0.05)
            if mode in ('dns_timeout', 'shared_cancel'):
                blocked = await Client.connect(inbound_port,
                                               'udp-sink.test' if protocol == 'freedom' else '127.0.0.1', 53)
                clients.append(blocked)
                started = time.monotonic()
                await blocked.send(b'waiting-for-dns')
                if mode == 'shared_cancel':
                    survivor = await Client.connect(inbound_port, '127.0.0.1', peer_port)
                    clients.append(survivor)
                    await survivor.send(b'before-cancel')
                    await survivor.receive(b'before-cancel')
                reply = await asyncio.wait_for(blocked.reader.read(), 4)
                if reply:
                    raise AssertionError('silent DNS unexpectedly produced application data')
                result['request_seconds'] = round(time.monotonic() - started, 3)
                if not (0.5 <= result['request_seconds'] < 3 and dns.requests > 0):
                    raise AssertionError('UDP send did not honor its write budget during DNS')
                if mode == 'shared_cancel':
                    payload = bytes(range(256)) * 80
                    await survivor.send(payload)
                    await survivor.receive(payload)
                    result['survivor_after_cancel'] = len(payload)
            elif handoff_case:
                await exercise_native_handoff(inbound_port, peer_port, peer, clients,
                                              output, result, ss2022_cipher, rebind_attempts)
            elif isolated:
                client_type = NativeClient if mode == 'native_isolation' else Client
                first = await client_type.connect(inbound_port, '127.0.0.1', peer_port)
                second = await client_type.connect(inbound_port, '127.0.0.1', peer_port, SECOND_USER)
                if mode.startswith('native_'):
                    # Identical endpoint leaves only authenticated owner identity
                    # to distinguish the two associations.
                    second.sock.close()
                    second.sock = first.sock
                clients.extend((first, second))
                first_payload, second_payload = b'client-one-round-one', b'client-two-round-one'
                await asyncio.gather(first.send(first_payload), second.send(second_payload))
                first_round = await peer.next_round((first_payload, second_payload))
                first_port = first_round[first_payload][1]
                second_port = first_round[second_payload][1]
                if first_port == second_port:
                    raise AssertionError(f'isolated Freedom sessions shared peer source port {first_port}')
                # Replies are intentionally sent in reverse request order. The peer
                # waits for both flows, so timing cannot hide a shared-socket broadcast.
                peer.reply(first_round[second_payload], b'reply-for-client-two')
                await second.receive(b'reply-for-client-two')
                peer.reply(first_round[first_payload], b'reply-for-client-one')
                await first.receive(b'reply-for-client-one')
                # Interleave a second round while both associations are alive;
                # each must retain its own source port and have no stale packet.
                next_first = b'client-one-round-two'
                next_second = b'client-two-round-two'
                await second.send(next_second)
                await first.send(next_first)
                second_round = await peer.next_round((next_first, next_second))
                if (second_round[next_first][1] != first_port or
                        second_round[next_second][1] != second_port):
                    raise AssertionError('UDP association source port changed between rounds')
                peer.reply(second_round[next_first], b'round-two-for-client-one')
                await first.receive(b'round-two-for-client-one')
                peer.reply(second_round[next_second], b'round-two-for-client-two')
                await second.receive(b'round-two-for-client-two')
                if mode == 'isolation_cancel':
                    await close_writer(first.writer)
                    first.writer = None
                    next_payload = b'client-two-after-cancel'
                    await second.send(next_payload)
                    next_round = await peer.next_round((next_payload,))
                    if next_round[next_payload][1] != second_port:
                        raise AssertionError('surviving request changed its peer source port')
                    peer.reply(next_round[next_payload], b'survivor-after-cancel')
                    await second.receive(b'survivor-after-cancel')
                result['peer_source_ports'] = [first_port, second_port]
            else:
                client_type = NativeClient if mode.startswith('native_') else Client
                client = await client_type.connect(inbound_port, '127.0.0.1',
                                              53 if protocol == 'shadowsocks' else peer_port)
                clients.append(client)
                if quic_case:
                    expected_payloads = await exercise_quic(client, mode, result)
                    selected = peer if mode.endswith('_fragmented') else fallback_peer
                    rejected = fallback_peer if mode.endswith('_fragmented') else peer
                    if selected.payloads != expected_payloads or rejected.payloads:
                        raise AssertionError('QUIC route, datagram bytes, order or boundaries changed')
                    if selected.errors or rejected.errors or dns.requests:
                        raise AssertionError('QUIC relay peer error or unexpected DNS request')
                    result['selected_route'] = 'sni' if selected is peer else 'fallback'
                elif sniffing:
                    # The first packet must arrive without waiting for another.
                    await client.send(b'first-datagram')
                    burst = mode.endswith('_burst')
                    if not burst:
                        await client.receive(b'first-datagram')
                    # Queued packets must retain boundaries, including >8KB data.
                    payloads = (bytes(range(256)) * 80, b'third-datagram')
                    for payload in payloads:
                        await client.send(payload)
                    if burst:
                        await client.receive(b'first-datagram')
                    for payload in payloads:
                        await client.receive(payload)
                    if client.writer is not None:
                        client.writer.write_eof()
                elif mode == 'late_reply':
                    await client.send(b'late')
                    client.writer.write_eof()
                    await client.receive(b'late')
                else:
                    for payload in (b'first-datagram', bytes(range(256)) * 80):
                        await client.send(payload)
                        await client.receive(payload)
                    client.writer.write_eof()
                if client.writer is not None and await asyncio.wait_for(client.reader.read(), 2):
                    raise AssertionError('unexpected data after both datagrams')
            result['dns_requests'] = dns.requests
            result['peer_packets'] = peer.received
            result['peer_errors'] = peer.errors
            expected = ([] if mode == 'dns_timeout' else
                        [20, 20, 20, 20, 23] if mode == 'isolation_cancel' else
                        [20, 20, 20, 20] if isolated else [4] if mode == 'late_reply'
                        else [13, 20480] if mode == 'shared_cancel'
                        else [14, 20480, 14] if sniffing else [14, 20480])
            result['passed'] = (not peer.errors if handoff_case else True if quic_case else
                                not peer.errors and peer.received == expected)
        except Exception as error:
            result['error'] = repr(error)
            result['dns_requests'] = dns.requests
            result['peer_packets'] = peer.received
            result['peer_errors'] = peer.errors
            result['passed'] = False
        finally:
            for client in clients:
                await close_writer(client.writer)
                if isinstance(client, NativeClient):
                    client.sock.close()
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            for timer in peer.delayed:
                timer.cancel()
            if dns_transport:
                dns_transport.close()
            peer_transport.close()
            if fallback_transport:
                fallback_transport.close()
            await asyncio.sleep(0)
    if handoff_case:
        # LOG_NET_DEBUG files may buffer until shutdown. Require actual committed
        # ownership changes, not source-port changes or a guessed SO_REUSEPORT hash.
        handoffs = passive_handoffs(output)
        result['passive_handoffs'] = handoffs
        if result['passed'] and (
                len(handoffs) < 2 or any(
                    event['worker'] == event['previous_worker'] or
                    not (0 <= event['worker'] < 4 and 0 <= event['previous_worker'] < 4) or
                    event['session'] != result['client_session_id']
                    for event in handoffs)):
            result['passed'] = False
            result['error'] = 'missing repeated valid four-Worker passive owner changes for the live session'
    if fallback_peer is not None:
        result['fallback_packets'] = fallback_peer.received
        result['fallback_errors'] = fallback_peer.errors
    (output / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result), flush=True)
    return result


async def main(args):
    results = []
    cases = [('shadowsocks', 'dns_timeout'), ('freedom', 'dns_timeout'),
             ('freedom', 'shared_cancel'), ('freedom', 'isolation'),
             ('freedom', 'isolation_cancel'), ('freedom', 'echo'), ('shadowsocks', 'echo'),
             ('freedom', 'late_reply'), ('shadowsocks', 'late_reply'),
             ('freedom', 'sniff_echo'), ('shadowsocks', 'sniff_echo'),
             ('freedom', 'native_sniff_echo'), ('shadowsocks', 'native_sniff_echo'),
             ('freedom', 'sniff_burst'), ('shadowsocks', 'sniff_burst'),
             ('freedom', 'native_sniff_burst'), ('shadowsocks', 'native_sniff_burst')]
    cases.extend(('freedom', mode) for mode in ('native_isolation', 'native_ss2022_isolation'))
    cases.extend(('shadowsocks', mode) for mode in QUIC_MODES)
    if args.case:
        selected = set(args.case)
        assert selected <= {f'{protocol}-{mode}' for protocol, mode in cases}
        cases = [(protocol, mode) for protocol, mode in cases if f'{protocol}-{mode}' in selected]
    for protocol, mode in cases:
        case_output = args.output.resolve() / f'{protocol}-{mode}'
        if mode == 'native_ss2022_isolation':
            for cipher in dict.fromkeys(args.ss2022_cipher or ('aes', 'chacha')):
                results.append(await run_case(args.binary.resolve(), case_output / cipher,
                                              protocol, mode, cipher, args.ss2022_rebind_attempts))
        else:
            results.append(await run_case(args.binary.resolve(), case_output, protocol, mode))
    (args.output / 'results.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return 0 if all(result['passed'] for result in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append')
    parser.add_argument('--ss2022-cipher', action='append', choices=('aes', 'chacha'),
                        help='SS2022 cipher(s) to exercise; defaults to both')
    parser.add_argument('--ss2022-rebind-attempts', type=int, default=16,
                        help='fresh UDP source paths to exercise for repeated owner changes')
    args = parser.parse_args()
    if args.ss2022_rebind_attempts < 2:
        parser.error('--ss2022-rebind-attempts must be at least two')
    raise SystemExit(asyncio.run(main(args)))

"""Real TLS: fragmented ClientHello, long configured SAN, fixed certificate under arbitrary SNI."""
import argparse
import asyncio
import json
from pathlib import Path
import ssl

from reality_integration import (USER, PAYLOAD, build_vless_request, free_port,
                                 start_cnode, stop_cnode, write_config_dir)
from tls_fragmentation import FragmentingProxy


async def main(args):
    args.output.mkdir(parents=True, exist_ok=True)
    identity = "a" * 63 + "." + "b" * 63 + ".example.com"
    port = free_port()
    write_config_dir(args.output, {
        "config.json": {"workers": 2, "log": {"level": "debug"}},
        "inbounds.json": [{
            "tag": "autosign", "protocol": "vless", "listen": "127.0.0.1", "port": port,
            "outboundTag": "direct", "settings": {"decryption": "none", "clients": [{"id": str(USER)}]},
            "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {"serverName": identity}},
        }],
        "outbounds.json": [{"tag": "direct", "protocol": "freedom"}],
    })
    peer_errors = []

    async def echo(reader, writer):
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except ConnectionError as error:
            peer_errors.append(repr(error))
        finally:
            writer.close()
            await writer.wait_closed()

    echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
    target_port = echo_server.sockets[0].getsockname()[1]
    proxy = await FragmentingProxy(port).start()
    process = None
    result = {"passed": False}
    try:
        process = start_cnode(args.binary, args.output)
        insecure = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE

        async def probe(name, context):
            reader, writer = await asyncio.wait_for(asyncio.open_connection(
                "127.0.0.1", proxy.port, ssl=context, server_hostname=name), 5)
            try:
                certificate = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
                writer.write(build_vless_request(target_port, PAYLOAD))
                await writer.drain()
                response = await asyncio.wait_for(reader.readexactly(2 + len(PAYLOAD)), 5)
                assert response == b"\x00\x00" + PAYLOAD, response
                return certificate
            finally:
                writer.close()
                await writer.wait_closed()

        certificate = await probe(identity, insecure)
        trusted = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        trusted.load_verify_locations(cadata=ssl.DER_cert_to_PEM_cert(certificate))
        assert await probe(identity, trusted) == certificate
        # SNI never causes signing or growth of a name-indexed cache. It is
        # intentionally unrelated to the one configured certificate identity.
        for index in range(16):
            assert await probe(f"arbitrary-{index}.invalid", insecure) == certificate
        try:
            await probe("not-configured.invalid", trusted)
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("unknown SNI must not obtain a matching forged identity")
        assert proxy.fragmented == 19, proxy.fragmented
        assert not proxy.errors and not peer_errors, (proxy.errors, peer_errors)
        result.update(passed=True, fragmented_handshakes=proxy.fragmented,
                      configured_san_length=len(identity), arbitrary_sni_same_certificate=16)
    except Exception as error:
        result["error"] = repr(error)
    finally:
        if process:
            stop_cnode(process)
        await proxy.close()
        echo_server.close()
        await echo_server.wait_closed()
    (args.output / "result.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=lambda value: Path(value).resolve())
    parser.add_argument("--output", required=True, type=lambda value: Path(value).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

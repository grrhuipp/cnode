"""Cold AnyTLS configuration admission must match its update frame byte capacity."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import traceback

from anytls_fin_integration import (
    Resources, Frames, REQUEST, BANNER, available_port, configure, frame,
    target, tls_settings, until,
)


def scheme_bytes(size, unicode):
    prefix = b'stop=8\n0=30-30\n1=64-65\n#'
    unit = '界'.encode('utf-8') if unicode else b'a'
    count, remaining = divmod(size - len(prefix), len(unit))
    return prefix + unit * count + b'x' * remaining


async def scenario(args, size, unicode, array, output, result, resources):
    raw = scheme_bytes(size, unicode)
    assert len(raw) == size
    text = raw.decode('utf-8')
    setting = text.split('\n') if array else text
    requests = []

    async def destination(reader, writer):
        requests.append(await reader.readexactly(len(REQUEST)))
        writer.write(BANNER)
        await writer.drain()

    target_port = await resources.listen(destination)
    port = available_port()
    configure(output, {'protocol': 'anytls', 'listen': '127.0.0.1', 'port': port,
                       'settings': {'clients': [{'password': 'secret'}], 'paddingScheme': setting},
                       'streamSettings': tls_settings(True)}, {'protocol': 'freedom', 'settings': {}})
    child_log = output / 'child.log'
    child = resources.spawn([args.binary, '--config-dir', output], child_log)
    result.update(raw_bytes=size, raw_characters=len(text), input_kind='array' if array else 'text',
                  expected_rejection=size > 65535, raw_md5=hashlib.md5(raw).hexdigest())
    await until(lambda: child.poll() is not None or 'server started' in child_log.read_text(encoding='utf-8'), 6)
    log = child_log.read_text(encoding='utf-8')
    result.update(cold_exit_code=child.poll(), server_started='server started' in log)
    if child.poll() is not None:
        diagnostics = list((output / 'logs').glob('error_*.log'))
        error_log = '\n'.join(path.read_text(encoding='utf-8') for path in diagnostics)
        reason_found = 'padding scheme exceeds 65535 bytes' in error_log
        result.update(passed=size > 65535 and child.returncode != 0 and 'server started' not in log
                      and 'has invalid protocol settings' in log and reason_found,
                      rejection_reason_found=reason_found,
                      diagnostic_files=[path.relative_to(output).as_posix() for path in diagnostics],
                      target_requests=0)
        return
    reader, writer = await resources.connect(port, tls=True)
    received = Frames(resources, reader)
    writer.write(hashlib.sha256(b'secret').digest() + b'\0\0' + frame(4, payload=b'v=2\npadding-md5=outdated')
                 + frame(1, 1) + frame(2, 1, target(target_port) + REQUEST))
    await writer.drain()
    await until(lambda: received.closed or (received.payload(1) == BANNER and received.count(3, 1) == 1))
    updates = [payload for command, _, payload in received.values if command == 6]
    result.update(passed=size <= 65535 and updates == [raw] and received.payload(1) == BANNER and requests == [REQUEST],
                  session_closed=received.closed, update_bytes=[len(value) for value in updates],
                  response_hex=received.payload(1).hex(), target_requests=len(requests))


async def main(args):
    digest = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    results = []
    for size, unicode, array in [
        (31, False, False), (65534, False, False), (65535, False, False),
        (65535, True, False), (65535, True, True),
        (65536, False, False), (65536, True, False), (65536, True, True),
    ]:
        name = f'{size}-' + ('utf8' if unicode else 'ascii') + ('-array' if array else '-text')
        output = args.output / name
        output.mkdir(parents=True, exist_ok=True)
        resources = Resources()
        result = {'case': name, 'passed': False}
        try:
            await asyncio.wait_for(scenario(args, size, unicode, array, output, result, resources), 12)
        except Exception as error:
            result.update(passed=False, error=repr(error), traceback=traceback.format_exc())
        finally:
            result['children_alive_before_cleanup'] = bool(resources.children) and all(c.poll() is None for c in resources.children)
            await resources.close()
        result['peer_errors'] = resources.errors
        result['passed'] &= not resources.errors
        result['passed'] &= (not result['children_alive_before_cleanup'] if result.get('expected_rejection')
                             else result['children_alive_before_cleanup'])
        results.append(result)
        print(json.dumps(result), flush=True)
    assert hashlib.sha256(args.binary.read_bytes()).hexdigest() == digest
    (args.output / 'results.json').write_text(json.dumps({'binary_sha256': digest, 'cases': results}, indent=2))
    return 0 if all(value['passed'] for value in results) else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True, type=lambda x: Path(x).resolve())
    parser.add_argument('--output', required=True, type=lambda x: Path(x).resolve())
    raise SystemExit(asyncio.run(main(parser.parse_args())))

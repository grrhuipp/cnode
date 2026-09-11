"""Compare the compiled TokenBucket with an independent exact integer model."""
import argparse
import json
import os
from pathlib import Path
import random
import subprocess

MAX_U64 = (1 << 64) - 1
MAX_I64 = (1 << 63) - 1


class Model:
    def __init__(self, rate, now):
        self.rate, self.now = rate, now
        self.credit = rate * 1000
        self.capacity = min(2 * rate, MAX_U64) * 1000

    def consume(self, size, now):
        if not self.rate or not size:
            return 0
        if now > self.now:
            self.credit = min(self.capacity, self.credit + self.rate * (now - self.now))
            self.now = now
        self.credit -= size * 1000
        if self.credit < 0:
            wait = (-self.credit + self.rate - 1) // self.rate
            self.credit += self.rate * wait
            if wait > MAX_I64 or self.now + wait > MAX_I64:
                self.now, self.credit = MAX_I64, 0
            else:
                self.now += wait
        return min(MAX_I64, max(0, self.now - now))


def run(args):
    rng = random.Random(320031)
    rates = [0, 1, 2, 3, 999, 1000, 1001, 8192, 10**6, (1 << 32) + 1,
             (1 << 63) - 1, 1 << 63, MAX_U64 - 1, MAX_U64]
    rates += [rng.randrange(1, MAX_U64) for _ in range(24)]
    commands, expected, descriptions = [], [], []
    for rate in rates:
        now = rng.choice([-1000, 0, 100000, 10**12])
        model = Model(rate, now)
        commands.append(f'R {rate} {now}')
        for index in range(600):
            size = rng.choice([0, 1, 8192, MAX_U64, max(1, rate // 1000),
                               rng.randrange(1, 100000), rng.randrange(1, MAX_U64)])
            commands.append(f'C {size} {now}')
            wait = model.consume(size, now)
            expected.append(wait)
            descriptions.append(dict(rate=rate, size=size, now=now, index=index))
            if wait > 100000 or index % 29 == 0:
                now = rng.choice([-1000, 0, 100000, 10**12])
                model = Model(rate, now)
                commands.append(f'R {rate} {now}')
            else:
                now += rng.choice([0, 1, 333, 999, 1000, 2000, wait, wait + 3])
    args.output.mkdir(parents=True, exist_ok=True)
    trace = '\n'.join(commands) + '\n'
    (args.output / 'commands.txt').write_text(trace, encoding='utf-8')
    process = subprocess.run([str(args.binary.resolve()), '--trace'], input=trace,
                             text=True, capture_output=True, timeout=30,
                             creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
    actual = [int(line) for line in process.stdout.splitlines()]
    mismatches = [dict(**descriptions[i], expected=wanted, actual=got)
                  for i, (wanted, got) in enumerate(zip(expected, actual)) if wanted != got]
    result = dict(samples=len(expected), returned=len(actual), mismatches=len(mismatches),
                  first_mismatches=mismatches[:10], exit_code=process.returncode,
                  stderr=process.stderr,
                  passed=not mismatches and len(actual) == len(expected) and process.returncode == 0)
    (args.output / 'results.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    raise SystemExit(run(parser.parse_args()))

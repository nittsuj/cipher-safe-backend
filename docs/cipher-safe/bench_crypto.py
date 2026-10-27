"""Benchmark the Cipher Safe cipher core (core/crypto) without Django.

Measures the two moments a patient waits for:

* upload  - encrypting one item (the app does this once per algorithm), and
* opening - decrypting one stored copy,

for one representative size per data category, with key derivation (KDF),
cipher and MAC timed separately. To make the numbers reliable:

* one untimed warm-up round runs first (first calls pay one-off setup costs);
* every round runs the three algorithms in a rotated order, so slow drift on a
  laptop (thermal throttling, background load) is spread over all of them
  instead of hitting whichever algorithm happens to run last;
* every decryption is checked against the input, so no time is recorded for a
  round trip that did not work;
* the median is reported next to min / max / stdev, because a single slow run
  (scheduler, power management) pulls the mean but not the median.

Usage:  python docs/cipher-safe/bench_crypto.py . --out docs/cipher-safe/bench_results.json
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("backend", help="path to the backend directory")
parser.add_argument("--out", help="write JSON here (UTF-8) instead of stdout")
parser.add_argument("--runs", type=int, default=15, help="timed rounds per case")
ARGS = parser.parse_args()

sys.path.insert(0, str(Path(ARGS.backend).resolve()))

from core.crypto import MODE_FOR, PBKDF2_ROUNDS, SUPPORTED_ALGORITHMS, SUPPORTED_MODES, decrypt, encrypt  # noqa: E402

PASSWORD = "SuperSecret123!"
RUNS = ARGS.runs

# One representative payload per data category in the scenario.
SIZES = [
    ("Patient profile record", 512),
    ("KTP / BPJS card scan", 512 * 1024),
    ("Lab result PDF", 4 * 1024 * 1024),
    ("Ultrasound video", 32 * 1024 * 1024),
]


def payload(size: int) -> bytes:
    # Deterministic, non-repeating bytes: neither compressible nor constant.
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def summarise(samples: list[float]) -> dict[str, float]:
    return {
        "median": statistics.median(samples),
        "mean": statistics.fmean(samples),
        "min": min(samples),
        "max": max(samples),
        "stdev": statistics.stdev(samples) if len(samples) > 1 else 0.0,
    }


def _decrypt(enc):
    return decrypt(enc.ciphertext, PASSWORD, enc.algorithm, enc.salt, enc.iv, enc.mode, enc.tag)


def bench_size(label: str, size: int) -> list[dict]:
    data = payload(size)
    parts = ("kdf_ms", "cipher_ms", "mac_ms", "total_ms")
    samples = {
        alg: {"encrypt": {p: [] for p in parts}, "decrypt": {p: [] for p in parts}}
        for alg in SUPPORTED_ALGORITHMS
    }
    ciphertext_size = {}

    for round_no in range(RUNS + 1):  # round 0 is the untimed warm-up
        shift = round_no % len(SUPPORTED_ALGORITHMS)
        order = SUPPORTED_ALGORITHMS[shift:] + SUPPORTED_ALGORITHMS[:shift]
        for alg in order:
            enc = encrypt(data, PASSWORD, alg)
            dec = _decrypt(enc)
            assert dec.plaintext == data, f"{alg} round trip failed"
            ciphertext_size[alg] = len(enc.ciphertext)
            if round_no == 0:
                continue
            for kind, result in (("encrypt", enc), ("decrypt", dec)):
                bucket = samples[alg][kind]
                bucket["kdf_ms"].append(result.key_derivation_ms)
                bucket["cipher_ms"].append(result.cipher_ms)
                bucket["mac_ms"].append(result.mac_ms)
                bucket["total_ms"].append(result.total_ms)

    rows = []
    for alg in SUPPORTED_ALGORITHMS:
        dec_cipher = statistics.median(samples[alg]["decrypt"]["cipher_ms"])
        rows.append({
            "label": label,
            "plaintext_size": size,
            "algorithm": alg,
            "mode": MODE_FOR[alg] or "-",
            "ciphertext_size": ciphertext_size[alg],
            "runs": RUNS,
            "encrypt": {p: summarise(v) for p, v in samples[alg]["encrypt"].items()},
            "decrypt": {p: summarise(v) for p, v in samples[alg]["decrypt"].items()},
            "decrypt_cipher_mb_per_s": (size / 1_048_576) / (dec_cipher / 1000) if dec_cipher > 0 else None,
        })
    return rows


def bench_modes(size: int = 4 * 1024 * 1024, runs: int = 5) -> list[dict]:
    """Cipher-only decryption time per mode of operation, for the block ciphers."""
    data = payload(size)
    rows = []
    for algorithm in ("AES", "DES"):
        for mode in SUPPORTED_MODES:
            enc = encrypt(data, PASSWORD, algorithm, mode)
            _decrypt(enc)  # warm-up
            cipher = []
            for _ in range(runs):
                result = _decrypt(enc)
                assert result.plaintext == data, f"{algorithm}/{mode} round trip failed"
                cipher.append(result.cipher_ms)
            median = statistics.median(cipher)
            rows.append({
                "algorithm": algorithm,
                "mode": mode,
                "plaintext_size": size,
                "overhead_bytes": len(enc.ciphertext) - size,
                "cipher_ms": summarise(cipher),
                "mb_per_s": (size / 1_048_576) / (median / 1000),
            })
    return rows


def main() -> None:
    out = {
        "host": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "machine": platform.machine(),
        },
        "pbkdf2_rounds": PBKDF2_ROUNDS,
        "runs_per_case": RUNS,
        "warmup_rounds": 1,
        "sizes": [],
        "modes": [],
    }
    for label, size in SIZES:
        print(f"# {label} ({size} B)", file=sys.stderr, flush=True)
        out["sizes"].extend(bench_size(label, size))
    print("# mode comparison", file=sys.stderr, flush=True)
    out["modes"] = bench_modes()

    text = json.dumps(out, indent=2) + "\n"
    if ARGS.out:
        Path(ARGS.out).write_text(text, encoding="utf-8")
        print(f"# written to {ARGS.out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()

"""Benchmark the Cipher Safe cipher core (core/crypto) without Django.

Mirrors what GET /api/files/{id}/benchmark/ does server-side: repeated
decryptions of one ciphertext, reporting the key-derivation and cipher times
separately. Run with the backend directory as the only argument.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
from pathlib import Path

BACKEND = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(BACKEND))

from core.crypto import SUPPORTED_ALGORITHMS, SUPPORTED_MODES, decrypt, encrypt  # noqa: E402
from core.crypto import PBKDF2_ROUNDS  # noqa: E402

PASSWORD = "SuperSecret123!"
RUNS = 10

# One representative payload per file category in the assignment.
SIZES = [
    ("PII field", 64),
    ("ID card image", 512 * 1024),
    ("Document", 4 * 1024 * 1024),
    ("Video", 32 * 1024 * 1024),
]


def payload(size: int) -> bytes:
    # Deterministic, non-repeating bytes: compressible input would be
    # unrepresentative, and a constant pattern would be too.
    return (bytes(range(256)) * (size // 256 + 1))[:size]


def summarise(samples: list[float]) -> dict[str, float]:
    return {
        "mean": statistics.fmean(samples),
        "min": min(samples),
        "max": max(samples),
        "stdev": statistics.stdev(samples) if len(samples) > 1 else 0.0,
    }


def bench(label: str, size: int, mode: str = "CBC") -> list[dict]:
    data = payload(size)
    rows = []
    for algorithm in SUPPORTED_ALGORITHMS:
        enc = encrypt(data, PASSWORD, algorithm=algorithm, mode=mode)
        kdf, cipher = [], []
        for _ in range(RUNS):
            result = decrypt(
                enc.ciphertext,
                PASSWORD,
                algorithm=algorithm,
                salt=enc.salt,
                iv=enc.iv,
                mode=enc.mode,
            )
            assert result.plaintext == data, f"{algorithm}/{mode} round-trip failed"
            kdf.append(result.key_derivation_ms)
            cipher.append(result.cipher_ms)
        rows.append(
            {
                "label": label,
                "plaintext_size": size,
                "algorithm": algorithm,
                "mode": enc.mode or "-",
                "ciphertext_size": len(enc.ciphertext),
                "encrypt_cipher_ms": enc.cipher_ms,
                "runs": RUNS,
                "kdf_ms": summarise(kdf),
                "cipher_ms": summarise(cipher),
                "mb_per_s": (size / 1_048_576) / (statistics.fmean(cipher) / 1000)
                if statistics.fmean(cipher) > 0
                else None,
            }
        )
    return rows


def bench_modes(size: int = 4 * 1024 * 1024) -> list[dict]:
    """Ciphertext size and cipher time per mode, for the block ciphers."""
    data = payload(size)
    rows = []
    for algorithm in ("AES", "DES"):
        for mode in SUPPORTED_MODES:
            enc = encrypt(data, PASSWORD, algorithm=algorithm, mode=mode)
            samples = []
            for _ in range(3):
                result = decrypt(
                    enc.ciphertext,
                    PASSWORD,
                    algorithm=algorithm,
                    salt=enc.salt,
                    iv=enc.iv,
                    mode=mode,
                )
                assert result.plaintext == data, f"{algorithm}/{mode} round-trip failed"
                samples.append(result.cipher_ms)
            rows.append(
                {
                    "algorithm": algorithm,
                    "mode": mode,
                    "plaintext_size": size,
                    "ciphertext_size": len(enc.ciphertext),
                    "overhead": len(enc.ciphertext) - size,
                    "cipher_ms": statistics.fmean(samples),
                }
            )
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
        "sizes": [],
        "modes": [],
    }
    for label, size in SIZES:
        print(f"# {label} ({size} B)", file=sys.stderr, flush=True)
        out["sizes"].extend(bench(label, size))
    print("# mode comparison", file=sys.stderr, flush=True)
    out["modes"] = bench_modes()
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

"""
hashing/sha_hash.py
-------------------
Cryptographic Hash Functions — TP4 Exercices 4.1, 4.3

Covers:
  4.1  MD5  — 5 message sizes, 128-bit output verification, avalanche effect
  4.3  MD5 / SHA-256 / SHA-512 comparison + 100 MB throughput benchmark

Security notes:
  MD5    → 128-bit. Construction Merkle-Damgard. Collisions found (Wang & Yu 2004).
            Broken for security; acceptable for non-security checksums only.
  SHA-1  → 160-bit. Deprecated. SHAttered collision (2017).
  SHA-256 → 256-bit. Merkle-Damgard + Davies-Meyer compression. Widely deployed.
  SHA-512 → 512-bit, 80 rounds, 64-bit words. Faster than SHA-256 on 64-bit CPUs.
  SHA-3  → Keccak sponge construction. Immune to length-extension attacks by design.
"""

import hashlib
import os
import time
import struct

# ─────────────────────────────────────────────────────────────────────────────
# Core hash wrappers (kept from original + extended)
# ─────────────────────────────────────────────────────────────────────────────

def _to_bytes(data: bytes | str) -> bytes:
    return data.encode('utf-8') if isinstance(data, str) else data


def md5(data: bytes | str) -> str:
    return hashlib.md5(_to_bytes(data)).hexdigest()

def sha1(data: bytes | str) -> str:
    return hashlib.sha1(_to_bytes(data)).hexdigest()

def sha256(data: bytes | str) -> str:
    return hashlib.sha256(_to_bytes(data)).hexdigest()

def sha512(data: bytes | str) -> str:
    return hashlib.sha512(_to_bytes(data)).hexdigest()

def sha3_256(data: bytes | str) -> str:
    return hashlib.sha3_256(_to_bytes(data)).hexdigest()

def sha3_512(data: bytes | str) -> str:
    return hashlib.sha3_512(_to_bytes(data)).hexdigest()


def hash_all(data: bytes | str) -> dict[str, str]:
    """Return all digests for a given input."""
    d = _to_bytes(data)
    return {
        "MD5":      md5(d),
        "SHA-1":    sha1(d),
        "SHA-256":  sha256(d),
        "SHA-512":  sha512(d),
        "SHA3-256": sha3_256(d),
        "SHA3-512": sha3_512(d),
    }


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Incrementally hash a file (memory-efficient for large files)."""
    h = hashlib.new(algorithm)
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.1 — MD5 on 5 message sizes + 128-bit output verification
# ─────────────────────────────────────────────────────────────────────────────

def demo_md5_sizes() -> None:
    """
    Compute MD5 on 5 message sizes and verify the output is always 128 bits.

    Messages:
      1. Empty string   (0 bytes)
      2. Single byte    (1 byte)
      3. ~1 KB          (1 024 bytes)
      4. ~1 MB          (1 048 576 bytes)
      5. Pseudo-binary  (256 repeating bytes pattern)
    """
    print("═" * 70)
    print("  4.1.1 — MD5 on 5 message sizes (output always 128 bits = 32 hex chars)")
    print("═" * 70)

    messages = [
        ("empty string",    b""),
        ("single byte",     b"\x42"),
        ("1 KB",            os.urandom(1024)),
        ("1 MB",            os.urandom(1024 * 1024)),
        ("binary pattern",  bytes(range(256)) * 4),      # 1 KB repeating
    ]

    print(f"  {'Message':<18} {'Size':>10}   {'MD5 hex digest':<36}  {'bits':>6}  OK?")
    print(f"  {'-'*18} {'-'*10}   {'-'*36}  {'-'*6}  ---")

    for label, data in messages:
        digest = hashlib.md5(data).hexdigest()
        bits   = len(digest) * 4            # 1 hex char = 4 bits
        ok     = (bits == 128)
        print(f"  {label:<18} {len(data):>10}   {digest}  {bits:>6}  "
              f"{'✓' if ok else '✗'}")

    print(f"\n  → MD5 always produces a 128-bit (32 hex-char) digest,")
    print(f"    regardless of input size (0 bytes to 1 MB tested above).")


# ─────────────────────────────────────────────────────────────────────────────
# 4.1.2 — Avalanche effect (flip 1 bit, compare digests bit by bit)
# ─────────────────────────────────────────────────────────────────────────────

def _flip_bit(data: bytes, bit_pos: int) -> bytes:
    """Return a copy of data with bit bit_pos flipped."""
    ba  = bytearray(data)
    idx = bit_pos // 8
    bit = 7 - (bit_pos % 8)
    ba[idx] ^= (1 << bit)
    return bytes(ba)


def _hamming_distance_hex(h1: str, h2: str) -> int:
    """Count differing bits between two equal-length hex digests."""
    n1 = int(h1, 16)
    n2 = int(h2, 16)
    return bin(n1 ^ n2).count('1')


def avalanche_effect(algo: str = "md5",
                     messages: list[bytes] = None,
                     verbose: bool = True) -> list[float]:
    """
    For each message:
      1. Compute H(m)
      2. Flip bit 0 of m  → m'
      3. Compute H(m')
      4. Count differing bits between H(m) and H(m')
      5. Express as a percentage of total digest bits

    Ideal avalanche: ≈ 50 % of output bits change.

    Returns list of avalanche percentages.
    """
    hasher    = hashlib.new(algo)
    out_bits  = hasher.digest_size * 8

    if messages is None:
        messages = [
            b"",                              # edge case: empty → padded with bit-flip
            b"\x42",
            b"The quick brown fox",
            os.urandom(1024),
            os.urandom(1024 * 1024),
        ]

    if verbose:
        print("\n" + "═" * 70)
        print(f"  4.1.2 — Avalanche Effect ({algo.upper()}, output {out_bits} bits)")
        print("═" * 70)
        print(f"  {'Message':<22} {'Size':>8}   "
              f"{'Differing bits':>15}   {'Rate':>8}   Ideal≈50%?")
        print(f"  {'-'*22} {'-'*8}   {'-'*15}   {'-'*8}   {'-'*10}")

    rates = []
    labels = [
        "empty",
        "1 byte (0x42)",
        "\"The quick brown fox\"",
        "random 1 KB",
        "random 1 MB",
    ]

    for i, msg in enumerate(messages):
        if len(msg) == 0:
            # Flipping a bit in an empty message doesn't make sense;
            # use a 1-byte message for the modified version
            msg_prime = b"\x80"
        else:
            msg_prime = _flip_bit(msg, 0)

        h1 = hashlib.new(algo, msg).hexdigest()
        h2 = hashlib.new(algo, msg_prime).hexdigest()

        diff  = _hamming_distance_hex(h1, h2)
        rate  = diff / out_bits * 100
        close = abs(rate - 50) < 15      # within ±15 pp of 50 %
        rates.append(rate)

        if verbose:
            label = labels[i] if i < len(labels) else f"msg[{i}]"
            print(f"  {label:<22} {len(msg):>8}   "
                  f"{diff:>6}/{out_bits:<8}   {rate:>7.1f} %   "
                  f"{'✓' if close else '~'}")

    if verbose:
        avg = sum(rates) / len(rates)
        print(f"\n  Average avalanche rate: {avg:.1f} %  (ideal ≈ 50 %)")

    return rates


def demo_avalanche_all_algos() -> None:
    """Run avalanche demonstration for MD5, SHA-256, SHA-512."""
    msgs = [
        b"",
        b"\x42",
        b"The quick brown fox",
        os.urandom(1024),
        os.urandom(1024 * 1024),
    ]
    for algo in ("md5", "sha256", "sha512"):
        avalanche_effect(algo=algo, messages=msgs, verbose=True)


# ─────────────────────────────────────────────────────────────────────────────
# 4.3.1 — MD5 / SHA-256 / SHA-512 side-by-side comparison
# ─────────────────────────────────────────────────────────────────────────────

def compare_algorithms(message: bytes | str = None) -> None:
    """
    Compute MD5, SHA-256 and SHA-512 on the same message.
    Show digest size, computation time, and avalanche rate.
    """
    if message is None:
        message = b"TP4 - hash comparison message"
    data = _to_bytes(message)

    print("\n" + "═" * 70)
    print("  4.3.1 — MD5 / SHA-256 / SHA-512 comparison")
    print("═" * 70)
    print(f"  Input : {data[:60]!r}{'…' if len(data) > 60 else ''}")
    print(f"  Size  : {len(data)} bytes\n")

    configs = [
        ("MD5",     "md5",     128),
        ("SHA-256", "sha256",  256),
        ("SHA-512", "sha512",  512),
        ("SHA3-256","sha3_256",256),
        ("SHA3-512","sha3_512",512),
    ]

    print(f"  {'Algorithm':<12} {'Bits':>5}  {'Time (µs)':>10}  "
          f"{'Digest (first 32 hex)…':<36}  {'Avalanche':>10}")
    print(f"  {'-'*12} {'-'*5}  {'-'*10}  {'-'*36}  {'-'*10}")

    for name, algo, bits in configs:
        # Timing (average of 1000 iterations)
        REPS = 1000
        t0 = time.perf_counter()
        for _ in range(REPS):
            hashlib.new(algo, data).hexdigest()
        t_us = (time.perf_counter() - t0) / REPS * 1e6

        digest = hashlib.new(algo, data).hexdigest()

        # Avalanche on a 1-byte input (fast)
        if len(data) >= 1:
            av_rates = avalanche_effect(algo, [data[:max(1,len(data)//4)]], verbose=False)
            av = f"{av_rates[0]:.1f} %"
        else:
            av = "n/a"

        print(f"  {name:<12} {bits:>5}  {t_us:>10.2f}  "
              f"{digest[:36]:<36}  {av:>10}")

    print()
    print("  Notes:")
    print("  • SHA-512 uses 64-bit words → often faster than SHA-256 on 64-bit CPUs")
    print("  • SHA-3 (Keccak) uses a sponge construction → immune to length-extension")
    print("  • MD5 and SHA-1 must NOT be used for security-critical applications")


# ─────────────────────────────────────────────────────────────────────────────
# 4.3.2 — Throughput benchmark on 100 MB
# ─────────────────────────────────────────────────────────────────────────────

def benchmark_throughput(size_mb: float = 100.0) -> dict:
    """
    Hash `size_mb` MB of random data with MD5, SHA-256, SHA-512 and SHA-3.
    Reports throughput in MB/s and ranks algorithms fastest → slowest.
    """
    print("\n" + "═" * 70)
    print(f"  4.3.2 — Throughput benchmark on {size_mb:.0f} MB")
    print("═" * 70)

    size_bytes = int(size_mb * 1024 * 1024)
    print(f"  Generating {size_mb:.0f} MB of random data …")
    data = os.urandom(size_bytes)
    print(f"  Data ready ({len(data):,} bytes). Hashing…\n")

    algos = ["md5", "sha256", "sha512", "sha3_256", "sha3_512"]
    names = {"md5": "MD5", "sha256": "SHA-256", "sha512": "SHA-512",
             "sha3_256": "SHA3-256", "sha3_512": "SHA3-512"}

    results = {}

    # Warm up Python / CPU caches with a small hash
    for algo in algos:
        hashlib.new(algo, b"warmup").hexdigest()

    for algo in algos:
        # Incremental hashing (realistic: avoids 100 MB in-memory copy)
        chunk = 65536
        h  = hashlib.new(algo)
        t0 = time.perf_counter()
        for off in range(0, size_bytes, chunk):
            h.update(data[off:off + chunk])
        _ = h.hexdigest()
        elapsed = time.perf_counter() - t0

        throughput = size_mb / elapsed
        results[algo] = throughput
        print(f"  {names[algo]:<10} : {elapsed:.3f} s  →  {throughput:>7.1f} MB/s")

    # Ranking
    ranked = sorted(results.items(), key=lambda x: -x[1])
    print(f"\n  Ranking (fastest → slowest):")
    for rank, (algo, tp) in enumerate(ranked, 1):
        print(f"    {rank}. {names[algo]:<10} {tp:>7.1f} MB/s")

    fastest = names[ranked[0][0]]
    slowest = names[ranked[-1][0]]
    print(f"\n  Fastest : {fastest}")
    print(f"  Slowest : {slowest}")

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: hash_file (kept from original)
# ─────────────────────────────────────────────────────────────────────────────

def verify_file_sha256(filepath: str, expected_hash: str) -> bool:
    """Return True if SHA-256 of file matches expected_hash (hex string)."""
    got = hash_file(filepath, "sha256")
    return got.lower() == expected_hash.lower().strip()


# ─────────────────────────────────────────────────────────────────────────────
# Self-test / demo
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 4.1.1
    demo_md5_sizes()

    # 4.1.2 + 4.3.1 avalanche for all algos
    demo_avalanche_all_algos()

    # 4.3.1 comparison table
    compare_algorithms()

    # 4.3.2 benchmark (100 MB)
    benchmark_throughput(size_mb=100.0)

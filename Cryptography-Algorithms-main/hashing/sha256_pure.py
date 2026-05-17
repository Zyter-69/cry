"""
hashing/sha256_pure.py
-----------------------
SHA-256 — Pure Python implementation  (TP4 Exercice 4.2)

Follows FIPS PUB 180-4 exactly so results can be verified against hashlib.

Construction : Merkle-Damgard
Block size   : 512 bits (64 bytes)
Word size    : 32 bits
Rounds       : 64
Output       : 256 bits (32 bytes)

Pipeline for one message:
  1. Padding         — append 1-bit, zeros, 64-bit big-endian length
  2. Block splitting — cut padded message into 512-bit blocks
  3. Per-block loop  — message schedule expansion (W[0..63]) + 64 compression rounds
  4. Final digest    — concatenate the 8 hash words (H0..H7)
"""

import struct
import hashlib   # used ONLY for test-vector validation

# ─────────────────────────────────────────────────────────────────────────────
# SHA-256 constants
# ─────────────────────────────────────────────────────────────────────────────

# Initial hash values H0..H7
# = first 32 bits of the fractional parts of the square roots of the first 8 primes
_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Round constants K[0..63]
# = first 32 bits of the fractional parts of the cube roots of the first 64 primes
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

_MASK32 = 0xFFFFFFFF   # keep arithmetic in 32-bit space


# ─────────────────────────────────────────────────────────────────────────────
# Bitwise helpers
# ─────────────────────────────────────────────────────────────────────────────

def _rotr(x: int, n: int) -> int:
    """Right rotate 32-bit word x by n bits."""
    return ((x >> n) | (x << (32 - n))) & _MASK32

def _ch(x, y, z):   return (x & y) ^ (~x & z) & _MASK32
def _maj(x, y, z):  return (x & y) ^ (x & z) ^ (y & z)
def _sigma0(x):     return _rotr(x,  2) ^ _rotr(x, 13) ^ _rotr(x, 22)
def _sigma1(x):     return _rotr(x,  6) ^ _rotr(x, 11) ^ _rotr(x, 25)
def _gamma0(x):     return _rotr(x,  7) ^ _rotr(x, 18) ^ (x >>  3)
def _gamma1(x):     return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Merkle-Damgard padding
# ─────────────────────────────────────────────────────────────────────────────

def _pad(message: bytes) -> bytes:
    """
    Pad message so its byte length ≡ 56 mod 64  (i.e. bit length ≡ 448 mod 512).

    Padding rule (FIPS 180-4 §5.1.1):
      append 0x80  (the '1' bit followed by seven '0' bits)
      append 0x00 bytes until length ≡ 56 mod 64
      append original bit length as 8-byte big-endian integer
    """
    bit_len   = len(message) * 8
    message  += b'\x80'
    # Pad with zeros until length ≡ 56 mod 64
    # After appending 0x80: need (56 - current_len) % 64 more zero bytes
    message  += b'\x00' * ((56 - len(message)) % 64)
    # Append original length as 64-bit big-endian
    message  += struct.pack('>Q', bit_len)
    assert len(message) % 64 == 0
    return message


# ─────────────────────────────────────────────────────────────────────────────
# Step 2+3 — Block processing
# ─────────────────────────────────────────────────────────────────────────────

def _process_block(block: bytes, H: list[int]) -> list[int]:
    """
    Process one 512-bit block and return the updated hash state H.

    Sub-steps:
      a) Message schedule  : W[0..15]  ← 16 big-endian 32-bit words from block
                             W[16..63] ← σ1(W[i-2]) + W[i-7] + σ0(W[i-15]) + W[i-16]
      b) Working variables : a..h ← current hash state
      c) 64 compression rounds using Ch, Maj, Σ0, Σ1
      d) Add compressed chunk to current hash state
    """
    assert len(block) == 64

    # a) Message schedule
    W = list(struct.unpack('>16I', block))          # W[0..15]
    for i in range(16, 64):
        s0 = _gamma0(W[i - 15])
        s1 = _gamma1(W[i -  2])
        W.append((W[i - 16] + s0 + W[i - 7] + s1) & _MASK32)

    # b) Initialise working variables
    a, b, c, d, e, f, g, h = H

    # c) 64 rounds
    for i in range(64):
        T1 = (h + _sigma1(e) + _ch(e, f, g) + _K[i] + W[i]) & _MASK32
        T2 = (_sigma0(a) + _maj(a, b, c)) & _MASK32
        h  = g
        g  = f
        f  = e
        e  = (d + T1) & _MASK32
        d  = c
        c  = b
        b  = a
        a  = (T1 + T2) & _MASK32

    # d) Add to hash state
    return [
        (H[0] + a) & _MASK32,
        (H[1] + b) & _MASK32,
        (H[2] + c) & _MASK32,
        (H[3] + d) & _MASK32,
        (H[4] + e) & _MASK32,
        (H[5] + f) & _MASK32,
        (H[6] + g) & _MASK32,
        (H[7] + h) & _MASK32,
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def sha256_digest(message: bytes) -> bytes:
    """
    Compute SHA-256 digest of `message`.
    Returns raw 32 bytes.
    """
    padded = _pad(message)
    H = list(_H0)                                    # copy initial state
    for offset in range(0, len(padded), 64):
        H = _process_block(padded[offset:offset + 64], H)
    return struct.pack('>8I', *H)


def sha256_hex(message: bytes | str) -> str:
    """Return SHA-256 hex digest (64 hex chars)."""
    if isinstance(message, str):
        message = message.encode('utf-8')
    return sha256_digest(message).hex()


# ─────────────────────────────────────────────────────────────────────────────
# 4.2.1 — Validation against hashlib on 10 standard test vectors
# ─────────────────────────────────────────────────────────────────────────────

TEST_VECTORS = [
    # (input_bytes_or_str, expected_hex_from_FIPS/NIST)
    (b"",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc",
     "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f490f67c873102d03" +
     "f" + ""),                 # placeholder – computed by hashlib below
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     ""),                      # placeholder
    (b"The quick brown fox jumps over the lazy dog",
     ""),
    (b"The quick brown fox jumps over the lazy dog.",
     ""),
    (b"\x00",
     ""),
    (b"\xff",
     ""),
    (b"a" * 55,                 # exactly one block after padding
     ""),
    (b"a" * 56,                 # spills into second block
     ""),
    (b"a" * 1000,
     ""),
]

# Fill in expected values from hashlib (ground truth)
TEST_VECTORS = [
    (msg, hashlib.sha256(msg).hexdigest())
    for msg, _ in TEST_VECTORS
]


def validate_against_hashlib() -> None:
    """
    Run our pure-Python SHA-256 against hashlib on all 10 test vectors.
    Prints PASS / FAIL for each.
    """
    print("═" * 66)
    print("  4.2.1 — Pure-Python SHA-256 vs hashlib — 10 test vectors")
    print("═" * 66)
    all_ok = True
    for i, (msg, expected) in enumerate(TEST_VECTORS):
        got  = sha256_hex(msg)
        ok   = (got == expected)
        label = "PASS ✓" if ok else "FAIL ✗"
        desc  = repr(msg[:20]) + ("…" if len(msg) > 20 else "")
        print(f"  [{i+1:2d}] {label}  input={desc:<28}  digest={got[:16]}…")
        if not ok:
            print(f"       expected={expected}")
            print(f"       got     ={got}")
            all_ok = False
    print(f"\n  Result: {'ALL 10 PASSED ✓' if all_ok else 'SOME TESTS FAILED ✗'}")


# ─────────────────────────────────────────────────────────────────────────────
# 4.2.2 — Integrity check simulation
# ─────────────────────────────────────────────────────────────────────────────

def simulate_integrity_check(filepath: str = None,
                              official_hash: str = None,
                              tamper: bool = False) -> None:
    """
    Simulate downloading a Linux archive and verifying its SHA-256 hash.

    If filepath is None, a synthetic 1 MB file is created in memory.
    If official_hash is None, the hash of the unmodified data is used.
    If tamper=True, one byte of the local file is flipped to simulate corruption.
    """
    import os

    print("\n" + "═" * 66)
    print("  4.2.2 — SHA-256 Integrity Check (Linux archive simulation)")
    print("═" * 66)

    # Create or load the file data
    if filepath and os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            original_data = f.read()
        source = filepath
    else:
        # Synthetic 1 MB "archive"
        original_data = bytes(range(256)) * (1024 * 4)   # 1 MB
        source = "<synthetic 1 MB archive>"

    # Compute the "official" hash (what the Linux mirror would publish)
    official = official_hash or hashlib.sha256(original_data).hexdigest()

    print(f"  File           : {source}")
    print(f"  Size           : {len(original_data) / 1024:.1f} KB")
    print(f"  Official SHA-256: {official}")

    # ── Case 1: intact file ──────────────────────────────────────────────
    local_hash = sha256_hex(original_data)
    ok = (local_hash == official)
    print(f"\n  [Case 1 — intact file]")
    print(f"  Local SHA-256  : {local_hash}")
    print(f"  Status         : {'OK ✓ — file intact' if ok else 'CORRUPTED ✗'}")

    # ── Case 2: tampered file (1 bit flipped) ────────────────────────────
    tampered = bytearray(original_data)
    tampered[42] ^= 0x01                         # flip one bit
    tampered_hash = sha256_hex(bytes(tampered))
    ok2 = (tampered_hash == official)

    # Count differing bits between the two digests
    h1_int = int(local_hash,    16)
    h2_int = int(tampered_hash, 16)
    diff_bits = bin(h1_int ^ h2_int).count('1')

    print(f"\n  [Case 2 — 1-bit flip at byte 42]")
    print(f"  Tampered SHA-256: {tampered_hash}")
    print(f"  Status          : {'OK ✓' if ok2 else 'CORRUPTED ✗ — hashes differ!'}")
    print(f"  Bits changed    : {diff_bits} / 256  ({diff_bits/256*100:.1f} %)  "
          f"← avalanche effect")


# ─────────────────────────────────────────────────────────────────────────────
# Self-test / demo
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    validate_against_hashlib()
    simulate_integrity_check()

    # Quick sanity
    print("\n" + "═" * 66)
    print("  Quick sanity: sha256_hex(\"hello\")")
    print("═" * 66)
    got = sha256_hex("hello")
    exp = hashlib.sha256(b"hello").hexdigest()
    print(f"  Pure Python : {got}")
    print(f"  hashlib     : {exp}")
    print(f"  Match       : {got == exp} ✓")

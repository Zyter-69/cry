"""
asymmetric/elgamal.py
---------------------
ElGamal Public-Key Encryption — TP3 Exercice 3.3

Covers:
  1. Key generation  (p safe-prime > 512 bits, g primitive root, x random, h = g^x mod p)
  2. Encrypt/decrypt an integer M < p  — verified with M = 12345
  3. Non-determinism  — two encryptions of the same M yield different ciphertexts
  4. Malleability     — forge E(2M) from E(M) without knowing M or x
  5. Size comparison  — RSA-2048 (256 B ciphertext) vs ElGamal-2048 (512 B ciphertext)

Protocol reminder:
  KeyGen : p prime, g generator, x ← rand, h = g^x mod p
           Public  (p, g, h)   Private (x)
  Enc(M) : k ← rand
           C1 = g^k mod p
           C2 = M · h^k mod p
           Ciphertext : (C1, C2)
  Dec(C1, C2) : s = C1^x mod p
               M = C2 · s⁻¹ mod p
"""

import os
from math_utils import mod_inverse
from primes import generate_safe_prime, find_primitive_root
from converter import bytes_to_int, int_to_bytes


class ElGamal:
    """
    ElGamal cryptosystem over a prime-order group.

    The prime p must be > 512 bits (TP3 requirement).
    For text encryption, messages are split into chunks < p.
    """

    def __init__(self, bits: int = 512):
        """
        Generate an ElGamal keypair.

        Parameters
        ----------
        bits : bit-length of the safe prime p  (minimum 512 per TP3)
        """
        if bits < 512:
            raise ValueError("TP3 requires p ≥ 512 bits")

        print(f"  [ElGamal] Generating {bits}-bit safe prime p …")
        self.bits = bits
        self.p    = generate_safe_prime(bits)
        self.g    = find_primitive_root(self.p)

        # Private key : x ∈ [2, p-2]
        self.x = int.from_bytes(os.urandom(bits // 8), 'big') % (self.p - 2) + 2
        # Public key  : h = g^x mod p
        self.h = pow(self.g, self.x, self.p)

        print(f"  p  = {hex(self.p)[:18]}…  ({self.p.bit_length()} bits)")
        print(f"  g  = {self.g}")
        print(f"  h  = {hex(self.h)[:18]}…  (public)")

    # ── Properties ───────────────────────────────────────────────────────────

    @property
    def public_key(self) -> tuple[int, int, int]:
        """(p, g, h)"""
        return self.p, self.g, self.h

    @property
    def private_key(self) -> tuple[int, int, int, int]:
        """(p, g, h, x)"""
        return self.p, self.g, self.h, self.x

    # ── Core integer encrypt / decrypt ───────────────────────────────────────

    def encrypt_int(self, M: int) -> tuple[int, int]:
        """
        Encrypt integer M  (0 < M < p).
        Returns (C1, C2)  where C1 = g^k mod p, C2 = M·h^k mod p.
        A fresh random k is chosen on every call → non-deterministic.
        """
        if not (0 < M < self.p):
            raise ValueError(f"M must satisfy 0 < M < p  (got M={M})")
        k  = int.from_bytes(os.urandom(self.bits // 8), 'big') % (self.p - 2) + 2
        C1 = pow(self.g, k, self.p)
        C2 = (M * pow(self.h, k, self.p)) % self.p
        return C1, C2

    def decrypt_int(self, C1: int, C2: int) -> int:
        """
        Decrypt (C1, C2) back to integer M.
        s = C1^x mod p,  M = C2 · s⁻¹ mod p
        """
        s     = pow(C1, self.x, self.p)
        s_inv = mod_inverse(s, self.p)
        return (C2 * s_inv) % self.p

    # ── Bytes / text helpers ─────────────────────────────────────────────────

    def encrypt_bytes(self, data: bytes) -> list[tuple[int, int]]:
        """Encrypt arbitrary bytes by splitting into chunks < p."""
        chunk_size = (self.p.bit_length() - 1) // 8
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        return [self.encrypt_int(bytes_to_int(c) or 1) for c in chunks]

    def decrypt_bytes(self, pairs: list[tuple[int, int]], original_len: int) -> bytes:
        """Decrypt list of (C1, C2) pairs back to bytes."""
        chunk_size = (self.p.bit_length() - 1) // 8
        parts = []
        for i, (C1, C2) in enumerate(pairs):
            m = self.decrypt_int(C1, C2)
            if i == len(pairs) - 1:
                last = original_len % chunk_size or chunk_size
                parts.append(int_to_bytes(m, last))
            else:
                parts.append(int_to_bytes(m, chunk_size))
        return b''.join(parts)

    def encrypt_text(self, plaintext: str) -> tuple[list[tuple[int, int]], int]:
        data = plaintext.encode('utf-8')
        return self.encrypt_bytes(data), len(data)

    def decrypt_text(self, pairs: list[tuple[int, int]], original_len: int) -> str:
        return self.decrypt_bytes(pairs, original_len).decode('utf-8')


# ─────────────────────────────────────────────────────────────────────────────
# 3.3.2 — M = 12345 demo + non-determinism
# ─────────────────────────────────────────────────────────────────────────────

def demo_basic(eg: ElGamal, M: int = 12345) -> None:
    print("\n" + "═" * 60)
    print(f"  3.3.2 — Encrypt/Decrypt M = {M}")
    print("═" * 60)

    C1, C2 = eg.encrypt_int(M)
    dec     = eg.decrypt_int(C1, C2)

    print(f"  M         = {M}")
    print(f"  C1        = {hex(C1)[:20]}…")
    print(f"  C2        = {hex(C2)[:20]}…")
    print(f"  D(E(M))   = {dec}  ({'✓ correct' if dec == M else '✗ ERROR'})")

    # Non-determinism: encrypt the same M twice
    print("\n  [Non-determinism] Two encryptions of the same M:")
    E1 = eg.encrypt_int(M)
    E2 = eg.encrypt_int(M)
    print(f"  Enc₁ = ({hex(E1[0])[:12]}…, {hex(E1[1])[:12]}…)")
    print(f"  Enc₂ = ({hex(E2[0])[:12]}…, {hex(E2[1])[:12]}…)")
    print(f"  Equal: {E1 == E2}  (expected False — different random k each time)")
    assert E1 != E2, "Collision in random k — extremely unlikely"
    print(f"  Both decrypt to {M}: "
          f"{eg.decrypt_int(*E1) == M and eg.decrypt_int(*E2) == M} ✓")


# ─────────────────────────────────────────────────────────────────────────────
# 3.3.3 — Malleability: forge E(2M) from E(M) without knowing M or x
# ─────────────────────────────────────────────────────────────────────────────

def demo_malleability(eg: ElGamal, M: int = 12345) -> None:
    """
    ElGamal is multiplicatively malleable:
      E(M₁) · E(M₂) = E(M₁·M₂ mod p)

    Concretely:
      Given C = (C1, C2) = E(M):
      Forge E(2M) = (C1, 2·C2 mod p)   without knowing M or the private key x.

    This is a chosen-ciphertext property — NOT a break of confidentiality.
    """
    print("\n" + "═" * 60)
    print("  3.3.3 — Malleability: forge E(2M) from E(M)")
    print("═" * 60)

    C1, C2 = eg.encrypt_int(M)
    print(f"  Original E(M={M})  : C1={hex(C1)[:12]}…, C2={hex(C2)[:12]}…")

    # Forge E(2M) — multiply C2 by 2 mod p
    forged_C2 = (2 * C2) % eg.p
    forged    = (C1, forged_C2)

    dec_forged = eg.decrypt_int(*forged)
    expected   = (2 * M) % eg.p

    print(f"  Forged E(2M)       : C1={hex(C1)[:12]}…, C2'={hex(forged_C2)[:12]}…")
    print(f"  D(forged)          = {dec_forged}")
    print(f"  Expected 2·M mod p = {expected}")
    print(f"  Malleability works : {dec_forged == expected} ✓")

    print(f"\n  General rule: from E(M)=(C1,C2), E(k·M) = (C1, k·C2 mod p)")
    print(f"  → Attacker multiplies the message without decryption!")


# ─────────────────────────────────────────────────────────────────────────────
# 3.3.4 — Size comparison: RSA-2048 vs ElGamal-2048
# ─────────────────────────────────────────────────────────────────────────────

def compare_sizes() -> None:
    """
    RSA-2048  : one ciphertext block = 256 bytes  (= n/8)
    ElGamal-2048 : one ciphertext = (C1, C2), each 256 bytes → 512 bytes total
    i.e. ElGamal produces 2× the ciphertext size of RSA for the same security level.
    """
    print("\n" + "═" * 60)
    print("  3.3.4 — Ciphertext size comparison: RSA-2048 vs ElGamal-2048")
    print("═" * 60)

    rsa_key_bytes  = 2048 // 8        # 256 bytes
    rsa_ct_bytes   = rsa_key_bytes    # RSA ciphertext = key size

    eg_key_bytes   = 2048 // 8        # p is 2048 bits → C1, C2 each 256 bytes
    eg_ct_bytes    = 2 * eg_key_bytes  # 512 bytes (two group elements)

    print(f"  RSA-2048  key size       : {rsa_key_bytes} bytes")
    print(f"  RSA-2048  ciphertext     : {rsa_ct_bytes} bytes")
    print(f"  ElGamal-2048 key size    : {eg_key_bytes} bytes  (public: p,g,h)")
    print(f"  ElGamal-2048 ciphertext  : {eg_ct_bytes} bytes  (C1 + C2)")
    print(f"  Ratio                    : ×{eg_ct_bytes // rsa_ct_bytes}")
    print()
    print("  Implications:")
    print("  • ElGamal ciphertext is 2× larger than RSA for the same key size.")
    print("  • ElGamal is randomised (IND-CPA) — same plaintext, different CT each time.")
    print("  • RSA-OAEP is also IND-CPA but produces a single block (more compact).")
    print("  • Both are avoided for bulk encryption — hybrid schemes (RSA/ECDH + AES)")
    print("    are used in practice (TLS, PGP, Signal).")


# ─────────────────────────────────────────────────────────────────────────────
# Self-test / demo
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    eg = ElGamal(bits=512)          # TP3 minimum: 512 bits

    demo_basic(eg, M=12345)
    demo_malleability(eg, M=12345)
    compare_sizes()

    # Text round-trip
    print("\n" + "═" * 60)
    print("  Text round-trip")
    print("═" * 60)
    msg = "Hello ElGamal — TP3!"
    ct, length = eg.encrypt_text(msg)
    dec = eg.decrypt_text(ct, length)
    print(f"  Plaintext  : {msg}")
    print(f"  Decrypted  : {dec}")
    print(f"  Match      : {dec == msg} ✓")

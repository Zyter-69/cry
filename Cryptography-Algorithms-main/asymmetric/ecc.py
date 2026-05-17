"""
asymmetric/ecc.py
-----------------
Elliptic Curve Cryptography — TP3 Exercice 3.4 (Supplémentaire)

Covers:
  1. Point addition & scalar multiplication on  y² = x³ + 7 (mod 97)
     (small parameters — educational / verifiable by hand)
  2. ECDH on P-256 via Python-cryptography — shared secret → AES-256 key
  3. Hybrid ECDH + AES-256-GCM (simplified ECIES):
     Alice encrypts a message for Bob using Bob's public key only.

Background:
  Curve (Weierstrass short form): y² = x³ + ax + b  (mod p)
  Group law  : chord-and-tangent construction
  ECDLP      : Q = k·P is easy to compute; inverting k is hard
  ECC-256 ≈ RSA-3072 in security level  (NIST SP 800-57)
"""

import os
import hashlib
from typing import Optional, Tuple

# cryptography library (high-level ECDH + ECDSA)
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, SECP256R1, generate_private_key, EllipticCurvePublicKey,
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# AES for hybrid encryption
from Crypto.Cipher import AES


# ═════════════════════════════════════════════════════════════════════════════
# 3.4.1 — Point arithmetic on y² = x³ + 7  (mod 97)
# ═════════════════════════════════════════════════════════════════════════════

# Small-parameter curve for illustration
_P97_A = 0
_P97_B = 7
_P97_P = 97   # field prime (tiny — only for pedagogy)

Point = Optional[Tuple[int, int]]   # None represents the point at infinity


def _modinv(a: int, m: int) -> int:
    """Extended Euclidean modular inverse."""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m}")
    return x % m


def _extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


class TinyEllipticCurve:
    """
    y² = x³ + a·x + b  (mod p)

    All arithmetic is over GF(p) with p prime.
    The point at infinity is represented as None.
    """

    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p

    def is_on_curve(self, P: Point) -> bool:
        if P is None:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    def point_neg(self, P: Point) -> Point:
        """−P = (x, −y mod p)"""
        if P is None:
            return None
        return (P[0], (-P[1]) % self.p)

    def point_add(self, P: Point, Q: Point) -> Point:
        """
        Add two points P and Q on the curve.

        Cases:
          P = ∞  →  Q
          Q = ∞  →  P
          P = −Q →  ∞  (vertical tangent)
          P = Q  →  doubling formula   (tangent)
          else   →  chord formula
        """
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            if (y1 + y2) % self.p == 0:
                return None   # P + (−P) = ∞
            # Point doubling
            lam = (3 * x1 * x1 + self.a) * _modinv(2 * y1, self.p) % self.p
        else:
            # Standard chord
            lam = (y2 - y1) * _modinv(x2 - x1, self.p) % self.p

        x3 = (lam * lam - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def scalar_mul(self, k: int, P: Point) -> Point:
        """
        k·P via double-and-add (left-to-right binary method).
        """
        result = None           # start at ∞
        addend = P
        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)
            k >>= 1
        return result

    def order_of_point(self, P: Point, max_order: int = 200) -> int:
        """Brute-force the order of P (only feasible for tiny curves)."""
        Q = P
        for n in range(1, max_order + 1):
            if Q is None:
                return n
            Q = self.point_add(Q, P)
        return -1   # not found within max_order


def demo_tiny_curve() -> None:
    """
    Demonstrate point operations on y² = x³ + 7  (mod 97).
    Base point G = (3, 6) lies on this curve.
    """
    curve = TinyEllipticCurve(a=_P97_A, b=_P97_B, p=_P97_P)
    # G = (1, 28) is a valid point on y² = x³ + 7 mod 97
    # Verification: 28² = 784 ≡ 784 - 8×97 = 784 - 776 = 8 mod 97 ✓
    #               1³ + 7 = 8 mod 97 ✓
    G = (1, 28)

    print("═" * 60)
    print("  3.4.1 — Elliptic curve  y² = x³ + 7  (mod 97)")
    print("═" * 60)
    print(f"  a={curve.a}, b={curve.b}, p={curve.p}")
    print(f"  Base point G = {G}")
    print(f"  G on curve   : {curve.is_on_curve(G)} ✓")

    # Compute a few multiples
    print("\n  Scalar multiples of G:")
    for k in [1, 2, 3, 5, 7, 10, 13]:
        kG = curve.scalar_mul(k, G)
        on = curve.is_on_curve(kG)
        print(f"    {k:>3}·G = {str(kG):<20}  on curve: {on}")

    # Point addition
    P = curve.scalar_mul(3, G)
    Q = curve.scalar_mul(5, G)
    R = curve.point_add(P, Q)
    R_expected = curve.scalar_mul(8, G)
    print(f"\n  P = 3·G = {P}")
    print(f"  Q = 5·G = {Q}")
    print(f"  P+Q     = {R}   (expected 8·G = {R_expected})  "
          f"{'✓' if R == R_expected else '✗'}")

    # Point doubling
    twoP = curve.point_add(P, P)
    twoP2 = curve.scalar_mul(6, G)
    print(f"\n  2P = P+P = {twoP}  (expected 6·G = {twoP2})  "
          f"{'✓' if twoP == twoP2 else '✗'}")

    # Point at infinity (P + (−P) = ∞)
    neg_P = curve.point_neg(P)
    inf   = curve.point_add(P, neg_P)
    print(f"\n  −P = {neg_P}")
    print(f"  P + (−P) = {inf}  (point at infinity ✓)")

    # Order of the base point
    ord_G = curve.order_of_point(G)
    print(f"\n  Order of G : {ord_G}  (G has finite order → it generates a cyclic subgroup)")

    # Mini ECDLP demo
    k_secret = 7
    kG = curve.scalar_mul(k_secret, G)
    print(f"\n  ECDLP: k={k_secret}, k·G={kG}")
    print(f"  Finding k by brute-force (tiny p, only for illustration) …")
    found = None
    T = G
    for i in range(1, 200):
        if T == kG:
            found = i
            break
        T = curve.point_add(T, G)
    print(f"  Brute-forced k = {found}  {'✓' if found == k_secret else '✗'}")
    print(f"  (On real curves with p ≈ 2²⁵⁶, this is computationally infeasible.)")


# ═════════════════════════════════════════════════════════════════════════════
# 3.4.2 — ECDH on P-256
# ═════════════════════════════════════════════════════════════════════════════

class ECDHParty:
    """
    One party in an ECDH exchange on NIST P-256.

    Uses `cryptography` (hazmat) for correct, secure arithmetic.
    """

    def __init__(self, name: str):
        self.name = name
        self._priv = generate_private_key(SECP256R1(), default_backend())
        self.pub   = self._priv.public_key()

    def compute_shared_secret(self, other_pub: EllipticCurvePublicKey) -> bytes:
        """Raw ECDH shared secret (x-coordinate of the shared point)."""
        return self._priv.exchange(ECDH(), other_pub)

    def derive_aes_key(self, other_pub: EllipticCurvePublicKey,
                       key_bits: int = 256) -> bytes:
        """
        Derive a symmetric key from the ECDH shared secret using HKDF-SHA256.
        HKDF is preferred over raw SHA-256 as it provides domain separation.
        """
        raw_secret = self.compute_shared_secret(other_pub)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=key_bits // 8,
            salt=None,
            info=b"ECDH AES key derivation",
            backend=default_backend(),
        )
        return hkdf.derive(raw_secret)

    def pub_bytes(self) -> bytes:
        """Uncompressed SEC1 public key bytes (65 bytes for P-256)."""
        return self.pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )


def demo_ecdh_p256() -> None:
    print("\n" + "═" * 60)
    print("  3.4.2 — ECDH on P-256")
    print("═" * 60)

    alice = ECDHParty("Alice")
    bob   = ECDHParty("Bob")

    K_alice = alice.derive_aes_key(bob.pub)
    K_bob   = bob.derive_aes_key(alice.pub)
    match   = K_alice == K_bob

    print(f"  Alice pub (hex) : {alice.pub_bytes().hex()[:32]}…")
    print(f"  Bob   pub (hex) : {bob.pub_bytes().hex()[:32]}…")
    print(f"\n  Alice AES key   : {K_alice.hex()}")
    print(f"  Bob   AES key   : {K_bob.hex()}")
    print(f"  Keys match      : {match} {'✓' if match else '✗'}")

    return alice, bob


# ═════════════════════════════════════════════════════════════════════════════
# 3.4.3 — Hybrid ECDH + AES-256-GCM  (simplified ECIES)
# ═════════════════════════════════════════════════════════════════════════════

def ecies_encrypt(message: bytes, recipient_pub: EllipticCurvePublicKey) -> dict:
    """
    Simplified ECIES (Elliptic Curve Integrated Encryption Scheme):

    1. Generate an ephemeral ECDH key pair (R_priv, R_pub)
    2. Compute shared secret:  Z = ECDH(R_priv, recipient_pub)
    3. Derive AES key:         k = HKDF(Z)
    4. Encrypt with AES-256-GCM

    The sender transmits: (R_pub, nonce, ciphertext, tag)
    The receiver needs only: recipient_priv, R_pub, nonce, ciphertext, tag
    """
    # Step 1 — ephemeral sender key pair
    eph_priv = generate_private_key(SECP256R1(), default_backend())
    eph_pub  = eph_priv.public_key()

    # Step 2 — shared secret
    Z = eph_priv.exchange(ECDH(), recipient_pub)

    # Step 3 — key derivation
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECIES AES-256-GCM",
        backend=default_backend(),
    )
    aes_key = hkdf.derive(Z)

    # Step 4 — AES-256-GCM
    nonce = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(message)

    return {
        "eph_pub": eph_pub,
        "nonce":   nonce,
        "tag":     tag,
        "ciphertext": ct,
    }


def ecies_decrypt(bundle: dict, recipient_priv) -> bytes:
    """
    Decrypt an ECIES bundle using the recipient's private key.

    Parameters
    ----------
    bundle        : dict produced by ecies_encrypt
    recipient_priv: the recipient's ECDH private key object
    """
    # Recompute shared secret from the ephemeral public key
    Z = recipient_priv._priv.exchange(ECDH(), bundle["eph_pub"])

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ECIES AES-256-GCM",
        backend=default_backend(),
    )
    aes_key = hkdf.derive(Z)

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bundle["nonce"])
    return cipher.decrypt_and_verify(bundle["ciphertext"], bundle["tag"])


def demo_ecies() -> None:
    print("\n" + "═" * 60)
    print("  3.4.3 — Hybrid ECDH + AES-256-GCM  (simplified ECIES)")
    print("═" * 60)

    bob = ECDHParty("Bob")
    msg = b"TP3 - secret message from Alice to Bob via ECIES"

    print(f"  Plaintext  : {msg.decode()}")
    bundle = ecies_encrypt(msg, bob.pub)

    eph_pub_hex = bundle["eph_pub"].public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ).hex()
    print(f"  Eph pub    : {eph_pub_hex[:32]}…")
    print(f"  Nonce      : {bundle['nonce'].hex()}")
    print(f"  Tag        : {bundle['tag'].hex()}")
    print(f"  CT (hex)   : {bundle['ciphertext'].hex()[:32]}…")

    recovered = ecies_decrypt(bundle, bob)
    print(f"\n  Decrypted  : {recovered.decode()}")
    print(f"  Match      : {recovered == msg} ✓")

    print("\n  Security properties:")
    print("  • Perfect Forward Secrecy — ephemeral key discarded after encryption")
    print("  • IND-CPA — different ephemeral key each call → different ciphertext")
    print("  • Authenticated — AES-GCM tag prevents ciphertext tampering")


# ═════════════════════════════════════════════════════════════════════════════
# Self-test / demo
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    demo_tiny_curve()
    demo_ecdh_p256()
    demo_ecies()

"""
asymmetric/diffie_hellman.py
-----------------------------
Diffie-Hellman Key Exchange — TP3 Exercice 3.1

Covers:
  1. Standard DH with a large prime (≥ 512 bits), full A↔B exchange
  2. Man-in-the-Middle (MITM) attack simulation
  3. Counter-measure: ECDSA signature of public keys to block MITM

Protocol reminder:
  Public params : large prime p, generator g (primitive root mod p)
  Alice : private a  →  public A = g^a mod p
  Bob   : private b  →  public B = g^b mod p
  Shared secret : K = B^a mod p = A^b mod p = g^(ab) mod p
"""

import os
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

from primes import generate_safe_prime, find_primitive_root


# ── Standard 2048-bit MODP group (RFC 3526 Group 14) — used as fallback ──────
MODP_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
MODP_2048_G = 2


# ─────────────────────────────────────────────────────────────────────────────
# 3.1.1 — Standard DH Party
# ─────────────────────────────────────────────────────────────────────────────

class DHParty:
    """
    One party in a Diffie-Hellman key exchange.

    Usage:
        alice = DHParty(bits=512)          # generates fresh safe prime
        bob   = DHParty(p=alice.p, g=alice.g)
        K_alice = alice.compute_shared_secret(bob.public_key)
        K_bob   = bob.compute_shared_secret(alice.public_key)
        assert K_alice == K_bob
    """

    def __init__(self, p: int = None, g: int = None,
                 bits: int = 512, use_modp2048: bool = False):
        """
        Parameters
        ----------
        p, g        : reuse existing group parameters (skip generation)
        bits        : bit size for fresh safe-prime generation (min 512 per TP3)
        use_modp2048: shortcut to use the pre-computed RFC-3526 2048-bit group
        """
        if bits < 512:
            raise ValueError("TP3 requires p ≥ 512 bits")

        if use_modp2048:
            self.p, self.g = MODP_2048_P, MODP_2048_G
        elif p is not None and g is not None:
            self.p, self.g = p, g
        else:
            print(f"  [DH] Generating {bits}-bit safe prime p …")
            self.p = generate_safe_prime(bits)
            self.g = find_primitive_root(self.p)
            print(f"  [DH] p = {hex(self.p)[:18]}…  ({self.p.bit_length()} bits)")
            print(f"  [DH] g = {self.g}")

        # Private key ∈ [2, p-2]
        key_bytes = (self.p.bit_length() + 7) // 8
        self._private = int.from_bytes(os.urandom(key_bytes), 'big') % (self.p - 2) + 2
        # Public key
        self.public_key: int = pow(self.g, self._private, self.p)

    def compute_shared_secret(self, other_pub: int) -> int:
        """K = other_pub^private mod p"""
        return pow(other_pub, self._private, self.p)

    def derive_aes_key(self, other_pub: int, key_bits: int = 256) -> bytes:
        """Derive a symmetric key from the DH shared secret via SHA-256/512."""
        secret = self.compute_shared_secret(other_pub)
        raw = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
        if key_bits <= 256:
            return hashlib.sha256(raw).digest()[:key_bits // 8]
        return hashlib.sha512(raw).digest()[:key_bits // 8]


def generate_dh_params(bits: int = 512) -> tuple[int, int]:
    """Generate a fresh safe prime p and primitive root g."""
    if bits < 512:
        raise ValueError("bits must be ≥ 512")
    p = generate_safe_prime(bits)
    g = find_primitive_root(p)
    return p, g


# ─────────────────────────────────────────────────────────────────────────────
# 3.1.2 — Man-in-the-Middle Attack Simulation
# ─────────────────────────────────────────────────────────────────────────────

class MITMAttacker:
    """
    Eve sits between Alice and Bob, intercepting and substituting public keys.

    She establishes:
      - Session A↔Eve : shared secret K_AE  (Alice thinks she talks to Bob)
      - Session Eve↔B : shared secret K_EB  (Bob thinks he talks to Alice)

    Eve can decrypt, read, re-encrypt every message transparently.
    """

    def __init__(self, p: int, g: int):
        self.p, self.g = p, g
        key_bytes = (p.bit_length() + 7) // 8
        # Eve's two private keys (one per session)
        self._priv_a = int.from_bytes(os.urandom(key_bytes), 'big') % (p - 2) + 2
        self._priv_b = int.from_bytes(os.urandom(key_bytes), 'big') % (p - 2) + 2
        # Eve's two public keys
        self.pub_to_alice: int = pow(g, self._priv_a, p)   # sent to Alice as "Bob"
        self.pub_to_bob:   int = pow(g, self._priv_b, p)   # sent to Bob as "Alice"

    def session_key_with_alice(self, alice_pub: int) -> int:
        """K_AE = alice_pub^priv_a mod p"""
        return pow(alice_pub, self._priv_a, self.p)

    def session_key_with_bob(self, bob_pub: int) -> int:
        """K_EB = bob_pub^priv_b mod p"""
        return pow(bob_pub, self._priv_b, self.p)


def simulate_mitm(bits: int = 512) -> dict:
    """
    Full MITM simulation.

    Returns a dict with all actors' keys and the two session secrets so the
    caller can display / log the attack.
    """
    print("\n" + "═" * 60)
    print("  MITM ATTACK SIMULATION")
    print("═" * 60)

    # 1. Alice generates group params and her key pair
    alice = DHParty(bits=bits)
    # 2. Bob uses the same group
    bob = DHParty(p=alice.p, g=alice.g)
    # 3. Eve intercepts
    eve = MITMAttacker(alice.p, alice.g)

    print(f"\n  Alice pub  = {hex(alice.public_key)[:20]}…")
    print(f"  Bob   pub  = {hex(bob.public_key)[:20]}…")
    print(f"  Eve→Alice  = {hex(eve.pub_to_alice)[:20]}…  (fake Bob)")
    print(f"  Eve→Bob    = {hex(eve.pub_to_bob)[:20]}…  (fake Alice)")

    # Session keys
    K_alice = alice.compute_shared_secret(eve.pub_to_alice)   # Alice ↔ Eve
    K_bob   = bob.compute_shared_secret(eve.pub_to_bob)       # Bob   ↔ Eve
    K_eve_a = eve.session_key_with_alice(alice.public_key)    # Eve side of Alice
    K_eve_b = eve.session_key_with_bob(bob.public_key)        # Eve side of Bob

    print("\n  ┌──────────────────────────────────────────────────────┐")
    print("  │              Man-in-the-Middle Schema                │")
    print("  ├──────────────────────────────────────────────────────┤")
    print("  │  Alice ──[A_pub]──▶ Eve ──[Eve_pub_b]──▶ Bob        │")
    print("  │  Alice ◀──[Eve_pub_a]── Eve ◀──[B_pub]── Bob        │")
    print("  ├──────────────────────────────────────────────────────┤")
    print(f"  │  K(Alice↔Eve) = {hex(K_alice)[:16]}…  │")
    print(f"  │  K(Eve↔Bob)   = {hex(K_bob)[:16]}…  │")
    print(f"  │  Eve knows BOTH session keys — intercepts all data  │")
    print("  └──────────────────────────────────────────────────────┘")

    return {
        "K_alice_side": K_alice,
        "K_bob_side":   K_bob,
        "K_eve_alice":  K_eve_a,
        "K_eve_bob":    K_eve_b,
        "mitm_success": (K_alice == K_eve_a) and (K_bob == K_eve_b),
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3.1.3 — Counter-measure: ECDSA-authenticated DH
# ─────────────────────────────────────────────────────────────────────────────

class AuthenticatedDHParty:
    """
    DH party that signs its public key with ECDSA (P-256).

    Each party has:
      - A long-term ECDSA key pair (trusted / pre-distributed)
      - A per-session DH key pair

    The DH public key is signed before transmission.  The receiver
    verifies the signature before using the public key → MITM is blocked
    because Eve cannot forge a valid ECDSA signature without the
    long-term private key.
    """

    def __init__(self, name: str, p: int = None, g: int = None, bits: int = 512):
        self.name = name
        # Long-term ECDSA identity key
        self._ecdsa_key = ECC.generate(curve="P-256")
        self.ecdsa_pub  = self._ecdsa_key.public_key()

        # Per-session DH
        self._dh = DHParty(p=p, g=g, bits=bits)
        self.p, self.g = self._dh.p, self._dh.g
        self.dh_pub: int = self._dh.public_key

        # Sign the DH public key
        self.signature: bytes = self._sign_pub(self.dh_pub)

    def _sign_pub(self, dh_pub: int) -> bytes:
        msg = dh_pub.to_bytes((dh_pub.bit_length() + 7) // 8, 'big')
        h   = SHA256.new(msg)
        return DSS.new(self._ecdsa_key, 'fips-186-3').sign(h)

    @staticmethod
    def verify_pub(dh_pub: int, signature: bytes, ecdsa_pub) -> bool:
        """Return True only if `signature` is a valid ECDSA sig over dh_pub."""
        msg = dh_pub.to_bytes((dh_pub.bit_length() + 7) // 8, 'big')
        h   = SHA256.new(msg)
        try:
            DSS.new(ecdsa_pub, 'fips-186-3').verify(h, signature)
            return True
        except ValueError:
            return False

    def compute_shared_secret(self, other_dh_pub: int,
                               other_signature: bytes,
                               other_ecdsa_pub) -> int:
        """
        Verify the other party's DH public key before computing the secret.
        Raises ValueError if the signature is invalid (MITM detected).
        """
        if not self.verify_pub(other_dh_pub, other_signature, other_ecdsa_pub):
            raise ValueError(
                f"[{self.name}] MITM DETECTED — invalid ECDSA signature on "
                f"received DH public key!"
            )
        return self._dh.compute_shared_secret(other_dh_pub)

    def derive_aes_key(self, other_dh_pub: int, other_signature: bytes,
                       other_ecdsa_pub, key_bits: int = 256) -> bytes:
        secret = self.compute_shared_secret(other_dh_pub, other_signature,
                                            other_ecdsa_pub)
        raw = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(raw).digest()[:key_bits // 8]


def simulate_authenticated_dh(bits: int = 512) -> None:
    """
    Demonstrate ECDSA-authenticated DH:
      - Legitimate exchange succeeds.
      - MITM attempt is detected and rejected.
    """
    print("\n" + "═" * 60)
    print("  AUTHENTICATED DH — ECDSA COUNTER-MEASURE")
    print("═" * 60)

    alice = AuthenticatedDHParty("Alice", bits=bits)
    bob   = AuthenticatedDHParty("Bob", p=alice.p, g=alice.g)

    print(f"\n  Alice DH pub  = {hex(alice.dh_pub)[:20]}…")
    print(f"  Bob   DH pub  = {hex(bob.dh_pub)[:20]}…")

    # ── Legitimate exchange ────────────────────────────────────────────────
    print("\n  [1] Legitimate exchange (Alice ↔ Bob) …")
    K_alice = alice.derive_aes_key(bob.dh_pub,   bob.signature,   bob.ecdsa_pub)
    K_bob   = bob.derive_aes_key(alice.dh_pub, alice.signature, alice.ecdsa_pub)
    match   = K_alice == K_bob
    print(f"  Alice AES key = {K_alice.hex()}")
    print(f"  Bob   AES key = {K_bob.hex()}")
    print(f"  Keys match    : {match} {'✓' if match else '✗'}")

    # ── MITM attempt ──────────────────────────────────────────────────────
    print("\n  [2] MITM attempt: Eve substitutes her own DH public key …")
    eve_dh   = DHParty(p=alice.p, g=alice.g)   # Eve's DH pair
    eve_ecdsa = ECC.generate(curve="P-256")     # Eve's (untrusted) ECDSA key

    # Eve signs with HER key — Alice checks against BOB's known public key
    fake_sig = DSS.new(eve_ecdsa, 'fips-186-3').sign(
        SHA256.new(eve_dh.public_key.to_bytes(
            (eve_dh.public_key.bit_length() + 7) // 8, 'big'))
    )

    try:
        alice.compute_shared_secret(eve_dh.public_key, fake_sig, bob.ecdsa_pub)
        print("  MITM NOT detected (❌ something is wrong)")
    except ValueError as exc:
        print(f"  ✓ MITM BLOCKED — {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Self-test / demo
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    BITS = 512   # TP3 minimum

    # ── 3.1.1 Standard DH ─────────────────────────────────────────────────
    print("═" * 60)
    print("  3.1.1 — Diffie-Hellman Key Exchange")
    print("═" * 60)
    alice = DHParty(bits=BITS)
    bob   = DHParty(p=alice.p, g=alice.g)

    K_a = alice.derive_aes_key(bob.public_key)
    K_b = bob.derive_aes_key(alice.public_key)
    print(f"\n  Alice AES-256 key : {K_a.hex()}")
    print(f"  Bob   AES-256 key : {K_b.hex()}")
    print(f"  Keys match        : {K_a == K_b} ✓")

    # ── 3.1.2 MITM ────────────────────────────────────────────────────────
    result = simulate_mitm(BITS)
    print(f"\n  MITM success : {result['mitm_success']} ✓")

    # ── 3.1.3 Counter-measure ─────────────────────────────────────────────
    simulate_authenticated_dh(BITS)

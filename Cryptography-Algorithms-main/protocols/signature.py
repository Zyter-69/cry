"""
protocols/signature.py
-----------------------
TP 5 — Signatures Numériques
  Ex 5.1 — Signature RSA  : PKCS#1 v1.5  et  PSS
  Ex 5.2 — Signature ElGamal (sur groupe multiplicatif mod p)
  Ex 5.3 — DSA  et  ECDSA

Principe général
  Signer  : S = Sign(SK, H(M))   avec la clé privée.
  Vérifier: Verify(PK, M, S) ∈ {Vrai, Faux}  avec la clé publique.
  Garanties : authenticité · intégrité · non-répudiation.

Libs : pycryptodome  (Crypto.*)
       Built-in : hashlib, os, secrets
"""

import os
import hashlib
import secrets

from Crypto.PublicKey  import RSA, DSA, ECC
from Crypto.Signature  import pkcs1_15, pss, DSS
from Crypto.Hash       import SHA256, SHA384, SHA512

from utils.math_utils  import mod_inverse, gcd
from utils.primes      import generate_safe_prime, find_primitive_root


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _hash_obj(data: bytes, algo: str = "SHA256"):
    """Return a PyCryptodome hash object for the given algorithm."""
    _map = {"SHA256": SHA256, "SHA384": SHA384, "SHA512": SHA512}
    if algo not in _map:
        raise ValueError(f"Supported hash algorithms: {list(_map)}")
    return _map[algo].new(data)


def _hash_int(data: bytes, algo: str = "SHA256") -> int:
    """Return the hash of data as an integer (used by ElGamal / DSA math)."""
    h = hashlib.new(algo.lower().replace("-", ""), data)
    return int.from_bytes(h.digest(), "big")


def _to_bytes(msg) -> bytes:
    return msg.encode("utf-8") if isinstance(msg, str) else msg


# ═════════════════════════════════════════════════════════════════════════════
# Ex 5.1 — RSA Signatures : PKCS#1 v1.5  and  PSS
# ═════════════════════════════════════════════════════════════════════════════

class RSASignaturePKCS15:
    """
    RSA-PKCS#1 v1.5 digital signature (legacy, deterministic).

    Sign   : S = RSA_decrypt(SK, PKCS1_pad(H(M)))
    Verify : check RSA_encrypt(PK, S) == PKCS1_pad(H(M))

    ⚠  PKCS#1 v1.5 is still widely deployed (TLS 1.2, old S/MIME) but
       vulnerable to Bleichenbacher-style attacks on padding oracles.
       Prefer PSS for new systems.
    """

    def __init__(self, bits: int = 2048):
        print(f"[RSA-PKCS1v15] Generating {bits}-bit keypair …")
        self._private_key = RSA.generate(bits)
        self._public_key  = self._private_key.publickey()
        print(f"  n = {hex(self._public_key.n)[:22]}…  ({bits} bits)")

    # ── properties ────────────────────────────────────────────────────────────

    @property
    def public_key(self):
        return self._public_key

    @property
    def key_size(self) -> int:
        return self._private_key.size_in_bits()

    # ── core operations ───────────────────────────────────────────────────────

    def sign(self, message, hash_algo: str = "SHA256") -> bytes:
        """Return PKCS#1 v1.5 signature bytes."""
        msg   = _to_bytes(message)
        h     = _hash_obj(msg, hash_algo)
        return pkcs1_15.new(self._private_key).sign(h)

    @staticmethod
    def verify(message, signature: bytes, public_key,
               hash_algo: str = "SHA256") -> bool:
        """Return True if the signature is valid, False otherwise."""
        msg = _to_bytes(message)
        h   = _hash_obj(msg, hash_algo)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    # ── PEM helpers ───────────────────────────────────────────────────────────

    def export_public_pem(self)  -> str: return self._public_key.export_key().decode()
    def export_private_pem(self) -> str: return self._private_key.export_key().decode()


# ─────────────────────────────────────────────────────────────────────────────

class RSASignaturePSS:
    """
    RSA-PSS digital signature (probabilistic, recommended).

    PSS (Probabilistic Signature Scheme) adds a random salt so two
    signatures of the same message differ — removing the determinism
    weakness of PKCS#1 v1.5.

    Sign   : S = RSA_decrypt(SK, PSS_encode(H(M), salt))
    Verify : PSS_verify(RSA_encrypt(PK, S), H(M), salt_len)
    """

    def __init__(self, bits: int = 2048):
        print(f"[RSA-PSS] Generating {bits}-bit keypair …")
        self._private_key = RSA.generate(bits)
        self._public_key  = self._private_key.publickey()
        print(f"  n = {hex(self._public_key.n)[:22]}…  ({bits} bits)")

    @property
    def public_key(self):
        return self._public_key

    @property
    def key_size(self) -> int:
        return self._private_key.size_in_bits()

    def sign(self, message, hash_algo: str = "SHA256") -> bytes:
        """Return RSA-PSS signature bytes."""
        msg = _to_bytes(message)
        h   = _hash_obj(msg, hash_algo)
        return pss.new(self._private_key).sign(h)

    @staticmethod
    def verify(message, signature: bytes, public_key,
               hash_algo: str = "SHA256") -> bool:
        msg = _to_bytes(message)
        h   = _hash_obj(msg, hash_algo)
        try:
            pss.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def export_public_pem(self)  -> str: return self._public_key.export_key().decode()
    def export_private_pem(self) -> str: return self._private_key.export_key().decode()


# ─────────────────────────────────────────────────────────────────────────────
# Backward-compatible alias kept for main.py / hmac_sign.py
# ─────────────────────────────────────────────────────────────────────────────
RSASignature = RSASignaturePSS          # default is the secure variant


# ═════════════════════════════════════════════════════════════════════════════
# Ex 5.2 — ElGamal Signature
# ═════════════════════════════════════════════════════════════════════════════

class ElGamalSignature:
    """
    ElGamal Signature Scheme over Z_p*.

    Key generation:
      p  — large safe prime  (2q+1, q prime)
      g  — primitive root mod p
      x  — private key  (random, 1 < x < p-1)
      y  — public key   y = g^x mod p

    Signing  M  (k must be fresh, random, coprime with p-1):
      r = g^k mod p
      s = (H(M) − x·r) · k⁻¹  mod (p−1)
      Signature = (r, s)

    Verification:
      Valid iff  g^H(M) ≡ y^r · r^s  (mod p)

    Security note:
      Re-using k for two different messages leaks the private key x
      (same weakness as ECDSA nonce reuse — Sony PS3 attack).
    """

    def __init__(self, bits: int = 256):
        print(f"[ElGamal-Sig] Generating {bits}-bit parameters …")
        self.p   = generate_safe_prime(bits)
        self.g   = find_primitive_root(self.p)
        # private key  x ∈ (1, p-2)
        self.x   = secrets.randbelow(self.p - 3) + 2
        # public key   y = g^x mod p
        self.y   = pow(self.g, self.x, self.p)
        self._q  = (self.p - 1)          # order of the group
        print(f"  p = {hex(self.p)[:20]}…  ({bits} bits)")
        print(f"  g = {self.g}")
        print(f"  y = {hex(self.y)[:20]}…  (public)")

    # ── public-key bundle ─────────────────────────────────────────────────────

    @property
    def public_key(self) -> dict:
        """Returns {p, g, y}."""
        return {"p": self.p, "g": self.g, "y": self.y}

    # ── sign ──────────────────────────────────────────────────────────────────

    def sign(self, message, hash_algo: str = "SHA256") -> tuple[int, int]:
        """
        Sign message.  Returns (r, s).

        The ephemeral key k is chosen fresh for every signature.
        gcd(k, p-1) == 1  is enforced.
        """
        msg    = _to_bytes(message)
        hm     = _hash_int(msg, hash_algo) % self._q   # H(M) mod (p-1)
        q      = self._q

        while True:
            k = secrets.randbelow(q - 2) + 2           # k ∈ (1, q-1)
            if gcd(k, q) != 1:
                continue
            r = pow(self.g, k, self.p)                  # r = g^k mod p
            # s = (H(M) - x·r) · k⁻¹ mod (p-1)
            numerator = (hm - self.x * r) % q
            try:
                k_inv = mod_inverse(k, q)
            except ValueError:
                continue
            s = (numerator * k_inv) % q
            if s == 0:
                continue                                # restart if s=0
            return r, s

    # ── verify ────────────────────────────────────────────────────────────────

    @staticmethod
    def verify(message, signature: tuple[int, int], public_key: dict,
               hash_algo: str = "SHA256") -> bool:
        """
        Verify an ElGamal signature.

        g^H(M) ≡ y^r · r^s  (mod p)
        """
        p, g, y = public_key["p"], public_key["g"], public_key["y"]
        r, s    = signature

        # Basic range check
        if not (0 < r < p) or not (0 < s < p - 1):
            return False

        msg = _to_bytes(message)
        hm  = _hash_int(msg, hash_algo) % (p - 1)

        lhs = pow(g, hm, p)                             # g^H(M) mod p
        rhs = (pow(y, r, p) * pow(r, s, p)) % p        # y^r · r^s mod p
        return lhs == rhs

    # ── attack demo ───────────────────────────────────────────────────────────

    @staticmethod
    def demo_nonce_reuse_attack(sig1: tuple, sig2: tuple,
                                hm1: int, hm2: int,
                                p: int, g: int, y: int) -> int | None:
        """
        If the same k was used to sign two different messages M1 and M2,
        recover the private key x.

        From:
          s1 = (hm1 - x·r) · k⁻¹  mod (p-1)
          s2 = (hm2 - x·r) · k⁻¹  mod (p-1)
        →  k·(s1-s2) ≡ hm1-hm2  (mod p-1)
        →  k = (hm1-hm2) · (s1-s2)⁻¹  mod (p-1)
        →  x = (hm1 - k·s1) · r⁻¹  mod (p-1)

        Returns recovered x, or None if recovery fails.
        """
        r1, s1 = sig1
        r2, s2 = sig2
        q = p - 1
        if r1 != r2:
            print("  [!] r values differ — nonces were NOT reused.")
            return None
        try:
            diff_s  = (s1 - s2) % q
            diff_hm = (hm1 - hm2) % q
            k       = (diff_hm * mod_inverse(diff_s, q)) % q
            r_inv   = mod_inverse(r1, q)
            x_rec   = ((hm1 - k * s1) * r_inv) % q
            return x_rec
        except ValueError:
            return None


# ═════════════════════════════════════════════════════════════════════════════
# Ex 5.3 — DSA (Digital Signature Algorithm)
# ═════════════════════════════════════════════════════════════════════════════

class DSASignature:
    """
    DSA — Digital Signature Algorithm  (FIPS 186-4).

    Key generation (via pycryptodome, 2048-bit L / 256-bit N):
      Domain params: large prime p, prime q | (p-1),  generator g of order q
      Private key:   x  ∈ (0, q)
      Public key:    y  = g^x mod p

    Signing M:
      k  ← random ∈ (0, q)   (fresh per signature — MUST NOT be reused)
      r  = (g^k mod p) mod q
      s  = k⁻¹ · (H(M) + x·r)  mod q
      Signature = (r, s)

    Verification:
      w  = s⁻¹ mod q
      u1 = H(M) · w  mod q
      u2 = r · w  mod q
      v  = (g^u1 · y^u2 mod p) mod q
      Valid iff v == r

    Security note:
      DSA shares the nonce-reuse weakness with ElGamal.
      Use deterministic RFC 6979 in production (see below).
    """

    def __init__(self, bits: int = 2048):
        print(f"[DSA] Generating {bits}-bit keypair …")
        self._key        = DSA.generate(bits)
        self._public_key = self._key.publickey()
        print(f"  p = {hex(int(self._key.p))[:22]}…  ({bits} bits)")
        print(f"  q = {hex(int(self._key.q))[:22]}…  ({int(self._key.q).bit_length()} bits)")

    @property
    def public_key(self):
        return self._public_key

    @property
    def key_info(self) -> dict:
        k = self._key
        return {
            "p_bits": k.p.size_in_bits(),
            "q_bits": k.q.size_in_bits(),
            "p":      int(k.p),
            "q":      int(k.q),
            "g":      int(k.g),
            "y":      int(k.y),
        }

    def sign(self, message, hash_algo: str = "SHA256") -> bytes:
        """
        Sign using FIPS 186-4 DSA with a random k.
        Returns DER-encoded (r, s) pair.
        """
        msg    = _to_bytes(message)
        h      = _hash_obj(msg, hash_algo)
        signer = DSS.new(self._key, "fips-186-3")
        return signer.sign(h)

    @staticmethod
    def verify(message, signature: bytes, public_key,
               hash_algo: str = "SHA256") -> bool:
        msg      = _to_bytes(message)
        h        = _hash_obj(msg, hash_algo)
        verifier = DSS.new(public_key, "fips-186-3")
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Ex 5.3b — ECDSA  (Elliptic Curve DSA)
# ─────────────────────────────────────────────────────────────────────────────

class ECDSASignature:
    """
    ECDSA over standard NIST curves.

    Same sign / verify logic as DSA but the group is an elliptic curve
    instead of Z_p*.  Smaller keys, same security level.

    Curve → security (bits) → key size
      P-256  →  128-bit  →  32-byte private key
      P-384  →  192-bit  →  48-byte private key
      P-521  →  260-bit  →  66-byte private key

    Signing M:
      k  ← random scalar  (nonce — MUST be fresh every time)
      R  = k·G  (point multiplication on the curve)
      r  = R.x mod n
      s  = k⁻¹ · (H(M) + d·r) mod n      (d = private key scalar)
      Signature = (r, s)

    Verification:
      w  = s⁻¹ mod n
      u1 = H(M)·w mod n,   u2 = r·w mod n
      P  = u1·G + u2·Q      (Q = public key point)
      Valid iff P.x mod n == r

    Security note:
      Sony PS3 used a fixed k ≡ same for every signature → private key
      was extracted from two signatures of different games.
    """

    CURVES = {"P-256", "P-384", "P-521"}

    def __init__(self, curve: str = "P-256"):
        if curve not in self.CURVES:
            raise ValueError(f"curve must be one of {self.CURVES}")
        print(f"[ECDSA] Generating {curve} keypair …")
        self._private_key = ECC.generate(curve=curve)
        self._public_key  = self._private_key.public_key()
        self.curve        = curve
        print(f"  curve = {curve}  ({self._private_key.pointQ.size_in_bits()}-bit field)")

    @property
    def public_key(self):
        return self._public_key

    def sign(self, message, hash_algo: str = "SHA256") -> bytes:
        """Return DER-encoded ECDSA (r, s) signature."""
        msg    = _to_bytes(message)
        h      = _hash_obj(msg, hash_algo)
        signer = DSS.new(self._private_key, "fips-186-3")
        return signer.sign(h)

    @staticmethod
    def verify(message, signature: bytes, public_key,
               hash_algo: str = "SHA256") -> bool:
        msg      = _to_bytes(message)
        h        = _hash_obj(msg, hash_algo)
        verifier = DSS.new(public_key, "fips-186-3")
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

    def export_public_pem(self)  -> str:
        return self._public_key.export_key(format="PEM")

    def export_private_pem(self) -> str:
        return self._private_key.export_key(format="PEM")


# ─────────────────────────────────────────────────────────────────────────────
# EdDSA — Ed25519  (kept from original, deterministic variant of ECDSA)
# ─────────────────────────────────────────────────────────────────────────────

class EdDSASignature:
    """
    EdDSA over Ed25519 (RFC 8032).

    Deterministic: the nonce k is derived from the private key and the
    message via a hash, so there is no random-k reuse risk.
    """

    def __init__(self):
        print("[EdDSA] Generating Ed25519 keypair …")
        self._private_key = ECC.generate(curve="Ed25519")
        self._public_key  = self._private_key.public_key()

    @property
    def public_key(self):
        return self._public_key

    def sign(self, message) -> bytes:
        msg    = _to_bytes(message)
        signer = DSS.new(self._private_key, "rfc8032")
        h      = SHA512.new(msg)
        return signer.sign(h)

    @staticmethod
    def verify(message, signature: bytes, public_key) -> bool:
        msg      = _to_bytes(message)
        verifier = DSS.new(public_key, "rfc8032")
        h        = SHA512.new(msg)
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False


# ═════════════════════════════════════════════════════════════════════════════
# __main__ — démonstration complète de TP 5
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import hashlib

    MSG      = "Document important — TP Cryptographie 2025"
    MSG_BAD  = MSG + " [falsifié]"

    # ── Ex 5.1 — RSA PKCS#1 v1.5 ─────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("Ex 5.1a — RSA PKCS#1 v1.5  (2048-bit)")
    print("═" * 60)
    rsa_v15 = RSASignaturePKCS15(2048)
    sig_v15 = rsa_v15.sign(MSG)
    print(f"  Signature (hex, 32 premiers octets) : {sig_v15.hex()[:64]}…")
    print(f"  Vérification (message original) : {RSASignaturePKCS15.verify(MSG, sig_v15, rsa_v15.public_key)}")
    print(f"  Vérification (message falsifié) : {RSASignaturePKCS15.verify(MSG_BAD, sig_v15, rsa_v15.public_key)}")

    print("\n" + "─" * 60)
    print("Ex 5.1b — RSA-PSS  (2048-bit)")
    print("─" * 60)
    rsa_pss = RSASignaturePSS(2048)
    sig_pss = rsa_pss.sign(MSG)
    # Two PSS signatures of the same message differ (probabilistic)
    sig_pss2 = rsa_pss.sign(MSG)
    print(f"  Sig1 == Sig2 (PSS est probabiliste) : {sig_pss == sig_pss2}")
    print(f"  Vérification (original) : {RSASignaturePSS.verify(MSG, sig_pss, rsa_pss.public_key)}")
    print(f"  Vérification (falsifié) : {RSASignaturePSS.verify(MSG_BAD, sig_pss, rsa_pss.public_key)}")

    # ── Ex 5.2 — ElGamal Signature ────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("Ex 5.2 — Signature ElGamal  (256-bit safe prime)")
    print("═" * 60)
    eg = ElGamalSignature(bits=256)
    pk = eg.public_key

    sig_eg = eg.sign(MSG)
    print(f"  r = {hex(sig_eg[0])[:22]}…")
    print(f"  s = {hex(sig_eg[1])[:22]}…")
    print(f"  Vérification (original) : {ElGamalSignature.verify(MSG, sig_eg, pk)}")
    print(f"  Vérification (falsifié) : {ElGamalSignature.verify(MSG_BAD, sig_eg, pk)}")

    # Attack demo — deliberately reuse the same k for two messages
    print("\n  ── Attaque par réutilisation du nonce k ──")
    # Sign two messages with the SAME k  (bypassing the normal path for demo)
    p, g_val, y_val, x_val = eg.p, eg.g, eg.y, eg.x
    q   = p - 1
    k_fixed = secrets.randbelow(q - 2) + 2
    while gcd(k_fixed, q) != 1:
        k_fixed = secrets.randbelow(q - 2) + 2

    def _sign_fixed_k(msg_bytes: bytes, k: int, x: int, p: int, g: int) -> tuple:
        q_   = p - 1
        hm   = _hash_int(msg_bytes) % q_
        r    = pow(g, k, p)
        s    = (((hm - x * r) % q_) * mod_inverse(k, q_)) % q_
        return r, s

    m1_bytes = MSG.encode()
    m2_bytes = "Deuxième message signé avec le même k".encode()
    sig_k1   = _sign_fixed_k(m1_bytes, k_fixed, x_val, p, g_val)
    sig_k2   = _sign_fixed_k(m2_bytes, k_fixed, x_val, p, g_val)
    hm1      = _hash_int(m1_bytes) % q
    hm2      = _hash_int(m2_bytes) % q

    x_rec = ElGamalSignature.demo_nonce_reuse_attack(
        sig_k1, sig_k2, hm1, hm2, p, g_val, y_val
    )
    print(f"  Clé privée réelle    x = {hex(x_val)[:22]}…")
    print(f"  Clé privée récupérée x = {hex(x_rec)[:22]}…" if x_rec else "  Récupération échouée.")
    print(f"  Attaque réussie : {x_rec == x_val}")

    # ── Ex 5.3 — DSA ──────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    print("Ex 5.3a — DSA  (2048-bit L / 256-bit N)")
    print("═" * 60)
    dsa = DSASignature(2048)
    sig_dsa = dsa.sign(MSG)
    print(f"  Signature (DER hex, 32 premiers octets) : {sig_dsa.hex()[:64]}…")
    print(f"  Vérification (original) : {DSASignature.verify(MSG, sig_dsa, dsa.public_key)}")
    print(f"  Vérification (falsifié) : {DSASignature.verify(MSG_BAD, sig_dsa, dsa.public_key)}")

    info = dsa.key_info
    print(f"  p ({info['p_bits']} bits), q ({info['q_bits']} bits)")

    # ── Ex 5.3b — ECDSA ───────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("Ex 5.3b — ECDSA  (P-256, P-384)")
    print("─" * 60)
    for curve in ("P-256", "P-384"):
        ec = ECDSASignature(curve)
        sig_ec = ec.sign(MSG)
        ok  = ECDSASignature.verify(MSG, sig_ec, ec.public_key)
        bad = ECDSASignature.verify(MSG_BAD, sig_ec, ec.public_key)
        print(f"  [{curve}]  valid={ok}  tampered={bad}  sig_len={len(sig_ec)} B")

    # ── EdDSA — bonus ─────────────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("Bonus — EdDSA  Ed25519  (déterministe, sans risque de nonce)")
    print("─" * 60)
    ed = EdDSASignature()
    sig_ed = ed.sign(MSG)
    print(f"  Vérification (original) : {EdDSASignature.verify(MSG, sig_ed, ed.public_key)}")
    print(f"  Vérification (falsifié) : {EdDSASignature.verify(MSG_BAD, sig_ed, ed.public_key)}")
    print(f"  Sig1 == Sig2 (EdDSA est déterministe) : {sig_ed == ed.sign(MSG)}")

    print("\n" + "═" * 60)
    print("TP 5 terminé.")
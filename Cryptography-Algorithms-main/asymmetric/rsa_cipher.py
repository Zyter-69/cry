"""
asymmetric/rsa_cipher.py
------------------------
RSA Encryption/Decryption — TP3 Exercice 3.2

Covers:
  1. RSA-512, 1024, 2048 — keygen, encrypt 32-byte string, decrypt, PEM export
  2. Hybrid RSA+AES-256 — encrypt a 1 MB payload, measure timings
  3. OAEP vs textbook RSA (why RSA can't handle arbitrary-length messages)

RSA key generation reminder:
  n = p·q          (p, q large primes)
  λ(n) = lcm(p-1, q-1)
  e = 65537
  d = e⁻¹ mod λ(n)
  Public key  : (e, n)
  Private key : (d, n)
"""

import os
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad


# ─────────────────────────────────────────────────────────────────────────────
# 3.2.1 — Key generation, encrypt/decrypt 32-byte string, PEM export
# ─────────────────────────────────────────────────────────────────────────────

def generate_keypair(bits: int = 2048):
    """
    Generate an RSA key pair.

    TP3 supports 512 / 1024 / 2048 bits.
    512-bit is *only* for educational purposes — it is easily breakable.

    NOTE: PyCryptodome enforces a minimum of 1024 bits.
    For 512-bit (educational only) use generate_keypair_512() below.

    Returns (private_key, public_key) as PyCryptodome RsaKey objects.
    """
    if bits not in (512, 1024, 2048, 4096):
        raise ValueError("Supported key sizes: 512, 1024, 2048, 4096 bits")
    if bits < 1024:
        raise ValueError(
            "PyCryptodome requires RSA key >= 1024 bits. "
            "Use generate_keypair_512() for the 512-bit educational demo."
        )
    key = RSA.generate(bits)
    return key, key.publickey()


def generate_keypair_512() -> dict:
    """
    Educational RSA-512 using textbook (raw) RSA.

    PyCryptodome refuses to generate keys < 1024 bits (correct policy).
    We implement it manually so TP3 can demonstrate the 512-bit case.

    Returns a dict with keys: n, e, d, p, q
    """
    import sympy
    p = sympy.randprime(2**255, 2**256)
    q = sympy.randprime(2**255, 2**256)
    while q == p:
        q = sympy.randprime(2**255, 2**256)
    n = p * q
    from math import lcm
    lam = lcm(p - 1, q - 1)
    e = 65537
    d = pow(e, -1, lam)
    return {"n": n, "e": e, "d": d, "p": p, "q": q, "bits": n.bit_length()}


def export_keys(private_key, public_key) -> tuple[str, str]:
    """Return (private_pem, public_pem) as strings."""
    return private_key.export_key().decode(), public_key.export_key().decode()


def import_private_key(pem: str):
    return RSA.import_key(pem)


def import_public_key(pem: str):
    return RSA.import_key(pem)


# ── OAEP (recommended) ────────────────────────────────────────────────────────

def encrypt_oaep(plaintext: bytes, public_key) -> bytes:
    """
    RSA-OAEP encryption (PKCS#1 v2.1).

    Max plaintext length = key_bytes - 2*hash_len - 2
      For 2048-bit: 256 - 2*32 - 2 = 190 bytes
    """
    return PKCS1_OAEP.new(public_key).encrypt(plaintext)


def decrypt_oaep(ciphertext: bytes, private_key) -> bytes:
    """RSA-OAEP decryption."""
    return PKCS1_OAEP.new(private_key).decrypt(ciphertext)


# ── Textbook RSA (educational only — NO padding) ─────────────────────────────

def textbook_encrypt(m: int, e: int, n: int) -> int:
    """C = m^e mod n   (raw, no padding — do NOT use in production)"""
    return pow(m, e, n)


def textbook_decrypt(c: int, d: int, n: int) -> int:
    """M = c^d mod n"""
    return pow(c, d, n)


# ── RSA-PSS Digital Signature ─────────────────────────────────────────────────

def sign(message: bytes, private_key) -> bytes:
    return pss.new(private_key).sign(SHA256.new(message))


def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    try:
        pss.new(public_key).verify(SHA256.new(message), signature)
        return True
    except (ValueError, TypeError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 3.2.1 — Benchmark: keygen + encrypt + decrypt for 512 / 1024 / 2048
# ─────────────────────────────────────────────────────────────────────────────

def benchmark_rsa_sizes(sample: bytes = None) -> None:
    """
    For each key size (512, 1024, 2048):
      - Measure key-generation time
      - Encrypt and decrypt a 32-byte sample
      - Export keys to PEM
    """
    if sample is None:
        sample = os.urandom(32)          # 32 bytes as required by TP3

    print("\n" + "═" * 60)
    print("  RSA benchmark — 512 / 1024 / 2048 bits")
    print("═" * 60)
    print(f"  Sample (32 bytes, hex) : {sample.hex()}\n")

    results = {}
    for bits in (512, 1024, 2048):
        print(f"  ── RSA-{bits} ──────────────────────────────────────────")

        if bits == 512:
            # Textbook RSA (PyCryptodome minimum is 1024)
            t0 = time.perf_counter()
            key512 = generate_keypair_512()
            t_keygen = time.perf_counter() - t0
            print(f"  KeyGen time : {t_keygen * 1000:.1f} ms  (textbook / educational)")

            # Encrypt with raw textbook RSA
            m_int = int.from_bytes(sample, 'big')
            t0 = time.perf_counter()
            ct_int = textbook_encrypt(m_int, key512["e"], key512["n"])
            t_enc = time.perf_counter() - t0

            t0 = time.perf_counter()
            pt_int = textbook_decrypt(ct_int, key512["d"], key512["n"])
            t_dec = time.perf_counter() - t0

            ok = (pt_int == m_int)
            ct_bytes = ct_int.to_bytes((ct_int.bit_length() + 7) // 8, 'big')
            print(f"  Encrypt time: {t_enc * 1000:.3f} ms")
            print(f"  Decrypt time: {t_dec * 1000:.3f} ms")
            print(f"  CT size     : {len(ct_bytes)} bytes")
            print(f"  Plaintext OK: {ok} {'✓' if ok else '✗'}  "
                  f"(textbook — no OAEP padding)")
            print(f"  n ({key512['bits']} bits): {hex(key512['n'])[:20]}…")
            print()
            continue

        t0 = time.perf_counter()
        priv, pub = generate_keypair(bits)
        t_keygen = time.perf_counter() - t0
        print(f"  KeyGen time : {t_keygen * 1000:.1f} ms")

        t0 = time.perf_counter()
        ct = encrypt_oaep(sample, pub)
        t_enc = time.perf_counter() - t0

        t0 = time.perf_counter()
        pt = decrypt_oaep(ct, priv)
        t_dec = time.perf_counter() - t0

        assert pt == sample, "Decryption mismatch!"
        print(f"  Encrypt time: {t_enc * 1000:.3f} ms")
        print(f"  Decrypt time: {t_dec * 1000:.3f} ms")
        print(f"  CT size     : {len(ct)} bytes")
        print(f"  Plaintext OK: {pt == sample} ✓")

        priv_pem, pub_pem = export_keys(priv, pub)
        print(f"  PEM private : {len(priv_pem)} chars | "
              f"PEM public: {len(pub_pem)} chars")
        print()

        results[bits] = {
            "t_keygen": t_keygen, "t_enc": t_enc, "t_dec": t_dec,
            "ct_len": len(ct),
        }

    return results


# ─────────────────────────────────────────────────────────────────────────────
# 3.2.2 — Hybrid RSA + AES-256 encryption of a 1 MB payload
# ─────────────────────────────────────────────────────────────────────────────

def hybrid_encrypt(plaintext: bytes, rsa_pub) -> dict:
    """
    Hybrid encryption:
      1. Generate a random AES-256 key  (32 bytes)
      2. Encrypt the AES key with RSA-OAEP
      3. Encrypt the plaintext with AES-256-GCM

    Returns a dict with all components needed for decryption.
    """
    # AES key
    aes_key = os.urandom(32)

    # RSA encrypts the AES key
    t0 = time.perf_counter()
    enc_key = encrypt_oaep(aes_key, rsa_pub)
    t_rsa = time.perf_counter() - t0

    # AES-GCM encrypts the bulk data
    t0 = time.perf_counter()
    nonce  = os.urandom(16)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    t_aes = time.perf_counter() - t0

    return {
        "enc_aes_key": enc_key,
        "nonce":       nonce,
        "tag":         tag,
        "ciphertext":  ct,
        "t_rsa_ms":    t_rsa * 1000,
        "t_aes_ms":    t_aes * 1000,
    }


def hybrid_decrypt(bundle: dict, rsa_priv) -> bytes:
    """Decrypt a hybrid bundle produced by hybrid_encrypt."""
    aes_key = decrypt_oaep(bundle["enc_aes_key"], rsa_priv)
    cipher  = AES.new(aes_key, AES.MODE_GCM, nonce=bundle["nonce"])
    return cipher.decrypt_and_verify(bundle["ciphertext"], bundle["tag"])


def benchmark_hybrid(bits: int = 2048, payload_mb: float = 1.0) -> None:
    """
    Encrypt a payload_mb-MB file with hybrid RSA+AES and print timings.
    Compares:
      - Pure AES-256-GCM time (bulk data only)
      - RSA-OAEP time         (32-byte AES key only)
    """
    payload = os.urandom(int(payload_mb * 1024 * 1024))

    print("\n" + "═" * 60)
    print(f"  Hybrid RSA-{bits} + AES-256-GCM — {payload_mb} MB payload")
    print("═" * 60)

    print(f"  Generating RSA-{bits} keypair …")
    priv, pub = generate_keypair(bits)

    bundle = hybrid_encrypt(payload, pub)
    pt     = hybrid_decrypt(bundle, priv)
    ok     = (pt == payload)

    print(f"  RSA-OAEP  (32-byte AES key)  : {bundle['t_rsa_ms']:.3f} ms")
    print(f"  AES-256-GCM ({payload_mb} MB)        : {bundle['t_aes_ms']:.3f} ms")
    print(f"  Total                        : "
          f"{bundle['t_rsa_ms'] + bundle['t_aes_ms']:.3f} ms")
    print(f"  Encrypted AES key size       : {len(bundle['enc_aes_key'])} bytes")
    print(f"  Ciphertext size              : {len(bundle['ciphertext'])} bytes")
    print(f"  Decryption correct           : {ok} ✓")

    # Compare: pure AES on same payload
    t0 = time.perf_counter()
    aes_key = os.urandom(32)
    nonce   = os.urandom(16)
    AES.new(aes_key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(payload)
    t_pure_aes = (time.perf_counter() - t0) * 1000
    print(f"\n  Pure AES-256-GCM (same data) : {t_pure_aes:.3f} ms")
    print(f"  RSA overhead                 : {bundle['t_rsa_ms']:.3f} ms  "
          f"(encrypts only 32 bytes)")


# ─────────────────────────────────────────────────────────────────────────────
# Convenience helpers (kept from original for backward compat)
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_text(plaintext: str, public_key=None, bits: int = 2048) -> dict:
    """Encrypt a text string. Generates keys if none provided."""
    priv, pub = generate_keypair(bits)
    if public_key is None:
        public_key = pub
    ct = encrypt_oaep(plaintext.encode('utf-8'), public_key)
    return {"ciphertext": ct, "private_key": priv, "public_key": pub}


def decrypt_text(ciphertext: bytes, private_key) -> str:
    return decrypt_oaep(ciphertext, private_key).decode('utf-8')


# ─────────────────────────────────────────────────────────────────────────────
# Self-test / demo
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # 3.2.1 — multi-size benchmark
    sample = os.urandom(32)
    benchmark_rsa_sizes(sample)

    # 3.2.2 — hybrid benchmark
    benchmark_hybrid(bits=2048, payload_mb=1.0)

    # Quick smoke-test
    print("\n" + "═" * 60)
    print("  Quick smoke-test — RSA-2048 OAEP + PSS")
    print("═" * 60)
    priv, pub = generate_keypair(2048)
    msg = b"TP3 RSA test message (32 bytes!!!)"
    ct  = encrypt_oaep(msg, pub)
    pt  = decrypt_oaep(ct, priv)
    print(f"  Plaintext    : {msg}")
    print(f"  CT (hex)     : {ct.hex()[:64]}…")
    print(f"  Decrypted    : {pt}")
    print(f"  Signature OK : {verify_signature(msg, sign(msg, priv), pub)} ✓")

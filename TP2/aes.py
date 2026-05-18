"""
modern/aes_cipher.py
---------------------
AES — TP2 Exercice 2.3
  2.3.1  Modes ECB / CBC / CTR (+ visualisation de la fuite ECB sur image)
  2.3.2  Effet avalanche en CBC : modification d'1 bit de l'IV
  2.3.3  Vulnérabilité nonce-reuse CTR : C1 ⊕ C2 = M1 ⊕ M2
  2.3.4  Benchmark AES-128 vs AES-192 vs AES-256 sur 10 Mo

Taille de bloc AES : 128 bits (16 octets) — invariant, quelle que soit la clé.
Tailles de clé    : 128 / 192 / 256 bits → 10 / 12 / 14 tours.
"""

import os
import time
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# ─────────────────────────────────────────────────────────────────────────────
#  Classe principale AESCipher
# ─────────────────────────────────────────────────────────────────────────────

class AESCipher:
    """
    Wrapper AES supportant ECB, CBC, CTR et GCM.

    Utilisation :
        aes = AESCipher(key_size=256)
        key = aes.generate_key()
        ct, iv = aes.encrypt_cbc(b"Hello World", key)
        pt = aes.decrypt_cbc(ct, key, iv)
    """

    BLOCK_SIZE = 16   # AES toujours 128 bits

    def __init__(self, key_size: int = 256):
        if key_size not in (128, 192, 256):
            raise ValueError("Taille de clé AES : 128, 192 ou 256 bits")
        self.key_size  = key_size
        self.key_bytes = key_size // 8

    def generate_key(self) -> bytes:
        return os.urandom(self.key_bytes)

    # ── ECB (non recommandé — fuite de structure) ──────────────────────────

    def encrypt_ecb(self, plaintext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(plaintext, self.BLOCK_SIZE))

    def decrypt_ecb(self, ciphertext: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)

    # ── CBC (recommandé pour blocs) ────────────────────────────────────────

    def encrypt_cbc(self, plaintext: bytes, key: bytes,
                    iv: bytes = None) -> tuple[bytes, bytes]:
        """Retourne (ciphertext, iv)."""
        iv = iv or os.urandom(self.BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(plaintext, self.BLOCK_SIZE)), iv

    def decrypt_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), self.BLOCK_SIZE)

    # ── CTR (chiffrement par flot, parallélisable) ─────────────────────────

    def encrypt_ctr(self, plaintext: bytes, key: bytes,
                    nonce: bytes = None) -> tuple[bytes, bytes]:
        """
        AES-CTR : transforme AES en chiffrement par flot.
        Retourne (ciphertext, nonce).
        ⚠ Ne jamais réutiliser (key, nonce) pour deux messages différents !
        """
        nonce = nonce or os.urandom(8)   # nonce 64 bits, compteur 64 bits
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.encrypt(plaintext), nonce

    def decrypt_ctr(self, ciphertext: bytes, key: bytes,
                    nonce: bytes) -> bytes:
        """CTR : déchiffrement = chiffrement (XOR symétrique)."""
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        return cipher.decrypt(ciphertext)

    # ── GCM (chiffrement authentifié — recommandé pour les communications) ─

    def encrypt_gcm(self, plaintext: bytes, key: bytes,
                    nonce: bytes = None,
                    aad: bytes = None) -> tuple[bytes, bytes, bytes]:
        """
        AES-GCM : chiffrement + authentification.
        Retourne (ciphertext, nonce, auth_tag).
        aad = Additional Authenticated Data (non chiffré, mais authentifié).
        """
        nonce = nonce or os.urandom(16)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        ct, tag = cipher.encrypt_and_digest(plaintext)
        return ct, nonce, tag

    def decrypt_gcm(self, ciphertext: bytes, key: bytes,
                    nonce: bytes, tag: bytes,
                    aad: bytes = None) -> bytes:
        """Lève ValueError si l'authentification échoue."""
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        if aad:
            cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)


# ─────────────────────────────────────────────────────────────────────────────
#  TP2 Ex 2.3.1 — Visualisation ECB sur image
# ─────────────────────────────────────────────────────────────────────────────

def aes_image_mode_comparison(width: int = 128, height: int = 128,
                               output_dir: str = ".") -> dict:
    """
    Génère une image avec motifs répétitifs, puis la chiffre avec :
      • AES-128-ECB → fuite de structure (motifs visibles)
      • AES-256-CBC → image indiscernable
      • AES-256-CTR → image indiscernable

    Sauvegarde les 4 images PNG et retourne leurs chemins.
    """
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        return {"error": "Installer pillow et numpy : pip install pillow numpy"}

    # Image avec damier (blocs très répétitifs pour rendre ECB évident)
    img = np.zeros((height, width), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            img[y, x] = 200 if (x // 16 + y // 16) % 2 == 0 else 30

    # Ajouter un cercle
    cy, cx = height // 2, width // 2
    for y in range(height):
        for x in range(width):
            if (x - cx) ** 2 + (y - cy) ** 2 < (min(width, height) // 4) ** 2:
                img[y, x] = 120

    raw = img.tobytes()
    key128 = os.urandom(16)
    key256 = os.urandom(32)
    aes128 = AESCipher(128)
    aes256 = AESCipher(256)

    paths = {}

    # Original
    orig_path = os.path.join(output_dir, "aes_original.png")
    Image.fromarray(img, 'L').save(orig_path)
    paths["original"] = orig_path

    # ECB
    ecb_ct = aes128.encrypt_ecb(raw, key128)
    ecb_px = np.frombuffer(ecb_ct[:width*height], dtype=np.uint8).reshape(height, width)
    ecb_path = os.path.join(output_dir, "aes_ecb.png")
    Image.fromarray(ecb_px, 'L').save(ecb_path)
    paths["ecb"] = ecb_path

    # CBC
    cbc_ct, _ = aes256.encrypt_cbc(raw, key256)
    cbc_px = np.frombuffer(cbc_ct[:width*height], dtype=np.uint8).reshape(height, width)
    cbc_path = os.path.join(output_dir, "aes_cbc.png")
    Image.fromarray(cbc_px, 'L').save(cbc_path)
    paths["cbc"] = cbc_path

    # CTR
    ctr_ct, _ = aes256.encrypt_ctr(raw, key256)
    ctr_px = np.frombuffer(ctr_ct[:width*height], dtype=np.uint8).reshape(height, width)
    ctr_path = os.path.join(output_dir, "aes_ctr.png")
    Image.fromarray(ctr_px, 'L').save(ctr_path)
    paths["ctr"] = ctr_path

    paths["observation"] = (
        "ECB : motifs du damier encore visibles → fuite de structure.\n"
        "CBC/CTR : image uniforme → aucune information visible."
    )
    return paths


# ─────────────────────────────────────────────────────────────────────────────
#  TP2 Ex 2.3.2 — Effet Avalanche en CBC
# ─────────────────────────────────────────────────────────────────────────────

def avalanche_cbc_demo(plaintext: bytes = None,
                       key: bytes = None) -> dict:
    """
    Modifie 1 bit de l'IV et mesure la propagation des différences
    bloc par bloc dans le ciphertext CBC.

    Retourne :
        {
          "num_blocks"      : int,
          "diff_per_block"  : list[float],   # % de bits différents par bloc
          "avg_diff"        : float,
          "original_iv"     : str (hex),
          "modified_iv"     : str (hex),
        }
    """
    if plaintext is None:
        # 8 blocs de 16 octets
        plaintext = b"A" * 128
    if key is None:
        key = os.urandom(32)

    aes = AESCipher(256)
    iv_orig   = os.urandom(16)
    iv_mod    = bytearray(iv_orig)
    iv_mod[0] ^= 0x01                          # Flip du bit 0 de l'IV
    iv_mod     = bytes(iv_mod)

    ct_orig, _ = aes.encrypt_cbc(plaintext, key, iv=iv_orig)
    ct_mod,  _ = aes.encrypt_cbc(plaintext, key, iv=iv_mod)

    num_blocks = len(ct_orig) // 16
    diff_per_block = []
    for i in range(num_blocks):
        b_orig = ct_orig[i*16:(i+1)*16]
        b_mod  = ct_mod [i*16:(i+1)*16]
        xored  = bytes(a ^ b for a, b in zip(b_orig, b_mod))
        bits_diff = sum(bin(byte).count('1') for byte in xored)
        diff_per_block.append(bits_diff / 128 * 100)   # % sur 128 bits

    return {
        "num_blocks":     num_blocks,
        "diff_per_block": diff_per_block,
        "avg_diff":       sum(diff_per_block) / len(diff_per_block),
        "original_iv":    iv_orig.hex(),
        "modified_iv":    iv_mod.hex(),
        "bit_flipped":    "IV[0] bit 0",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TP2 Ex 2.3.3 — Vulnérabilité nonce-reuse CTR
# ─────────────────────────────────────────────────────────────────────────────

def ctr_nonce_reuse_attack(m1: bytes, m2: bytes,
                            key: bytes = None) -> dict:
    """
    Démontre l'attaque sur CTR quand le même nonce est réutilisé.

    Si C1 = M1 ⊕ KS  et  C2 = M2 ⊕ KS  (même keystream KS),
    alors C1 ⊕ C2 = M1 ⊕ M2.

    Si un attaquant connaît (ou devine) des portions de M1,
    il peut récupérer les portions correspondantes de M2.

    Returns :
        {
          "c1_hex", "c2_hex",
          "xor_ciphertexts_hex"  : C1 ⊕ C2 = M1 ⊕ M2,
          "recovered_m2_partial" : octets récupérés de M2 (si M1 connu),
          "attack_success"       : bool,
        }
    """
    if key is None:
        key = os.urandom(32)

    aes   = AESCipher(256)
    nonce = os.urandom(8)   # MÊME nonce pour M1 et M2 (erreur fatale)

    c1, _ = aes.encrypt_ctr(m1, key, nonce=nonce)
    c2, _ = aes.encrypt_ctr(m2, key, nonce=nonce)

    length = min(len(c1), len(c2))
    xor_ct = bytes(a ^ b for a, b in zip(c1[:length], c2[:length]))

    # Si M1 est connu (scénario chosen-plaintext / known-plaintext partiel) :
    # M2[i] = xor_ct[i] ⊕ M1[i]
    recovered_m2 = bytes(x ^ a for x, a in zip(xor_ct, m1[:length]))

    return {
        "nonce":                   nonce.hex(),
        "c1_hex":                  c1.hex(),
        "c2_hex":                  c2.hex(),
        "xor_ciphertexts_hex":     xor_ct.hex(),
        "recovered_m2_partial":    recovered_m2,
        "recovered_m2_text":       recovered_m2.decode('utf-8', errors='replace'),
        "attack_success":          recovered_m2[:len(m2)] == m2[:length],
        "explanation": (
            "C1 ⊕ C2 = (M1 ⊕ KS) ⊕ (M2 ⊕ KS) = M1 ⊕ M2.\n"
            "Connaître M1 suffit pour retrouver M2 octet par octet."
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TP2 Ex 2.3.4 — Benchmark AES-128 / 192 / 256
# ─────────────────────────────────────────────────────────────────────────────

def benchmark_aes_key_sizes(data_size_mb: float = 10.0,
                             mode: str = "CBC",
                             iterations: int = 3) -> list[dict]:
    """
    Compare les débits AES-128, AES-192 et AES-256 en mode `mode` (CBC/CTR/GCM)
    sur `data_size_mb` Mo.

    Returns:
        Liste de dicts {key_size, rounds, enc_time_s, dec_time_s,
                        enc_throughput_mbs, dec_throughput_mbs}
    """
    data      = os.urandom(int(data_size_mb * 1024 * 1024))
    rounds_map = {128: 10, 192: 12, 256: 14}
    results   = []

    for ks in (128, 192, 256):
        aes = AESCipher(ks)
        key = aes.generate_key()

        # ── Chiffrement ────────────────────────────────────────────────────
        enc_times = []
        ct_store  = None
        iv_store  = None

        for _ in range(iterations):
            t0 = time.perf_counter()
            if mode == "CTR":
                ct, nonce = aes.encrypt_ctr(data, key)
                ct_store  = ct
                iv_store  = nonce
            elif mode == "GCM":
                ct, nonce, tag = aes.encrypt_gcm(data, key)
                ct_store  = ct
                iv_store  = (nonce, tag)
            else:   # CBC
                ct, iv    = aes.encrypt_cbc(data, key)
                ct_store  = ct
                iv_store  = iv
            enc_times.append(time.perf_counter() - t0)

        enc_avg = sum(enc_times) / iterations

        # ── Déchiffrement ──────────────────────────────────────────────────
        dec_times = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            if mode == "CTR":
                aes.decrypt_ctr(ct_store, key, iv_store)
            elif mode == "GCM":
                aes.decrypt_gcm(ct_store, key, iv_store[0], iv_store[1])
            else:
                aes.decrypt_cbc(ct_store, key, iv_store)
            dec_times.append(time.perf_counter() - t0)

        dec_avg = sum(dec_times) / iterations

        results.append({
            "key_size":           ks,
            "rounds":             rounds_map[ks],
            "mode":               mode,
            "enc_time_s":         enc_avg,
            "dec_time_s":         dec_avg,
            "enc_throughput_mbs": data_size_mb / enc_avg if enc_avg > 0 else 0,
            "dec_throughput_mbs": data_size_mb / dec_avg if dec_avg > 0 else 0,
        })

    return results


# ─────────────────────────────────────────────────────────────────────────────
#  Fonctions de commodité
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_text(plaintext: str, key: bytes = None, mode: str = "GCM") -> dict:
    """Chiffre une chaîne de texte avec AES-256. Génère la clé si non fournie."""
    aes  = AESCipher(256)
    key  = key or aes.generate_key()
    data = plaintext.encode('utf-8')

    if mode == "GCM":
        ct, nonce, tag = aes.encrypt_gcm(data, key)
        return {"ciphertext": ct, "key": key, "nonce": nonce,
                "tag": tag, "mode": "GCM"}
    elif mode == "CBC":
        ct, iv = aes.encrypt_cbc(data, key)
        return {"ciphertext": ct, "key": key, "iv": iv, "mode": "CBC"}
    elif mode == "CTR":
        ct, nonce = aes.encrypt_ctr(data, key)
        return {"ciphertext": ct, "key": key, "nonce": nonce, "mode": "CTR"}
    else:
        raise ValueError(f"Mode inconnu : {mode}")


def decrypt_text(params: dict) -> str:
    aes  = AESCipher(256)
    mode = params["mode"]
    if mode == "GCM":
        pt = aes.decrypt_gcm(params["ciphertext"], params["key"],
                              params["nonce"], params["tag"])
    elif mode == "CBC":
        pt = aes.decrypt_cbc(params["ciphertext"], params["key"], params["iv"])
    elif mode == "CTR":
        pt = aes.decrypt_ctr(params["ciphertext"], params["key"], params["nonce"])
    else:
        raise ValueError(f"Mode inconnu : {mode}")
    return pt.decode('utf-8')


# ─────────────────────────────────────────────────────────────────────────────
#  Affichage des démonstrations TP2
# ─────────────────────────────────────────────────────────────────────────────

def print_avalanche_demo() -> None:
    print("\n" + "=" * 56)
    print("  EFFET AVALANCHE AES-CBC (1 bit de l'IV modifié)")
    print("=" * 56)
    result = avalanche_cbc_demo()
    print(f"  IV original : {result['original_iv']}")
    print(f"  IV modifié  : {result['modified_iv']}  (1 bit flippé)")
    print(f"\n  Propagation bloc par bloc :")
    for i, pct in enumerate(result['diff_per_block']):
        bar = "█" * int(pct / 2)
        print(f"    Bloc {i+1:2d} : {pct:5.1f}% de bits différents  {bar}")
    print(f"\n  Moyenne : {result['avg_diff']:.1f}% de bits différents")
    print("  → En CBC, 1 bit de différence dans l'IV se propage à TOUS les blocs.")


def print_nonce_reuse_demo() -> None:
    m1 = b"Message secret numero un"
    m2 = b"Message secret numero deux!"
    print("\n" + "=" * 56)
    print("  VULNÉRABILITÉ NONCE-REUSE AES-CTR")
    print("=" * 56)
    r = ctr_nonce_reuse_attack(m1, m2)
    print(f"  M1       : {m1.decode()}")
    print(f"  M2       : {m2.decode()}")
    print(f"  Nonce    : {r['nonce']}  (réutilisé pour les deux!)")
    print(f"\n  C1 ⊕ C2  : {r['xor_ciphertexts_hex']}")
    print(f"  M2 récupéré : {r['recovered_m2_text']!r}")
    print(f"  Attaque réussie : {r['attack_success']}")
    print(f"\n  → {r['explanation']}")


def print_benchmark_demo(data_mb: float = 1.0) -> None:
    print("\n" + "=" * 56)
    print(f"  BENCHMARK AES-128 / 192 / 256 sur {data_mb} Mo (mode CBC)")
    print("=" * 56)
    print("  Mesure en cours…")
    results = benchmark_aes_key_sizes(data_mb, mode="CBC", iterations=3)
    print(f"\n  {'Clé':<10} {'Tours':<8} {'Chiffr.':<14} {'Déchiffr.'}")
    print("  " + "-" * 44)
    for r in results:
        print(f"  AES-{r['key_size']:<6} {r['rounds']:<8} "
              f"{r['enc_throughput_mbs']:>6.1f} Mo/s    "
              f"{r['dec_throughput_mbs']:>6.1f} Mo/s")
    print("\n  → La différence de performance entre 128 et 256 bits")
    print("    est < 30% — le surcoût en sécurité est minimal.")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    msg = "Message AES confidentiel — clé 256 bits !"
    print("=== AES-256-GCM ===")
    p = encrypt_text(msg, mode="GCM")
    print(f"Clé   : {p['key'].hex()}")
    print(f"CT    : {p['ciphertext'].hex()}")
    print(f"Déch. : {decrypt_text(p)}")

    print("\n=== AES-256-CTR ===")
    p2 = encrypt_text(msg, mode="CTR")
    print(f"Nonce : {p2['nonce'].hex()}")
    print(f"CT    : {p2['ciphertext'].hex()}")
    print(f"Déch. : {decrypt_text(p2)}")

    print_avalanche_demo()
    print_nonce_reuse_demo()
    print_benchmark_demo(data_mb=1.0)
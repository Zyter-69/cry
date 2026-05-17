"""
modern/des_cipher.py
---------------------
DES / Triple-DES — TP2 Exercice 2.2
  2.2.1  DES-ECB vs DES-CBC : comparaison des cryptogrammes
  2.2.2  Visualisation de la faiblesse ECB sur image (pixels → DES-ECB)
  2.2.3  Triple-DES-CBC + benchmark DES vs 3DES sur 1 Mo

Note : DES (56 bits effectifs) est cassé. 3DES est déprécié. → Utiliser AES.
"""

import os
import time
import struct
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 8   # DES : bloc 64 bits = 8 octets


# ─────────────────────────────────────────────────────────────────────────────
#  Génération de clés
# ─────────────────────────────────────────────────────────────────────────────

def des_generate_key() -> bytes:
    return os.urandom(8)

def tdes_generate_key(key_size: int = 24) -> bytes:
    if key_size not in (16, 24):
        raise ValueError("Clé 3DES : 16 ou 24 octets uniquement")
    return os.urandom(key_size)


# ─────────────────────────────────────────────────────────────────────────────
#  TP2 Ex 2.2.1 — DES-ECB et DES-CBC
# ─────────────────────────────────────────────────────────────────────────────

def des_encrypt_ecb(plaintext: bytes, key: bytes) -> bytes:
    """DES-ECB : chiffrement sans IV. Déconseillé (laisse apparaître les motifs)."""
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def des_decrypt_ecb(ciphertext: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)


def des_encrypt_cbc(plaintext: bytes, key: bytes,
                    iv: bytes = None) -> tuple[bytes, bytes]:
    """DES-CBC : chiffrement avec IV aléatoire. Retourne (ciphertext, iv)."""
    iv = iv or os.urandom(BLOCK_SIZE)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE)), iv


def des_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)


def compare_ecb_cbc(plaintext: bytes) -> dict:
    """
    Chiffre le même plaintext en DES-ECB et DES-CBC avec la même clé.
    Montre visuellement que ECB révèle les répétitions.

    Returns:
        {key, iv, ecb_ct, cbc_ct, ecb_hex, cbc_hex,
         ecb_repeated_blocks, cbc_repeated_blocks}
    """
    key = des_generate_key()
    ecb_ct     = des_encrypt_ecb(plaintext, key)
    cbc_ct, iv = des_encrypt_cbc(plaintext, key)

    # Compter les blocs identiques dans le ciphertext
    def count_repeated_blocks(ct: bytes) -> int:
        blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
        return len(blocks) - len(set(blocks))

    return {
        "key":                  key.hex(),
        "iv":                   iv.hex(),
        "ecb_ciphertext":       ecb_ct,
        "cbc_ciphertext":       cbc_ct,
        "ecb_hex":              ecb_ct.hex(),
        "cbc_hex":              cbc_ct.hex(),
        "ecb_repeated_blocks":  count_repeated_blocks(ecb_ct),
        "cbc_repeated_blocks":  count_repeated_blocks(cbc_ct),
        "plaintext_len":        len(plaintext),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TP2 Ex 2.2.2 — Faiblesse ECB visualisée sur image
# ─────────────────────────────────────────────────────────────────────────────

def ecb_image_weakness(width: int = 64, height: int = 64,
                       output_dir: str = ".") -> dict:
    """
    Génère une image de test (dégradé + motif géométrique), la chiffre en
    DES-ECB octet par octet par blocs de 8, puis reconstitue l'image chiffrée.

    Les motifs restent visibles en ECB car les blocs identiques produisent
    des ciphertexts identiques.

    Returns:
        {key, original_path, ecb_path, cbc_path}
    """
    try:
        from PIL import Image
        import numpy as np
    except ImportError:
        return {"error": "Pillow/numpy non installé : pip install pillow numpy"}

    # ── Créer une image avec des motifs répétitifs ────────────────────────────
    img_array = np.zeros((height, width), dtype=np.uint8)
    for y in range(height):
        for x in range(width):
            # Motif géométrique : bandes + cercle
            if (x // 8 + y // 8) % 2 == 0:
                img_array[y, x] = 200   # Blanc
            else:
                img_array[y, x] = 50    # Gris foncé

    original_img = Image.fromarray(img_array, mode='L')
    original_path = os.path.join(output_dir, "des_original.png")
    original_img.save(original_path)

    pixel_bytes = img_array.tobytes()   # width * height octets
    key = des_generate_key()

    # ── Chiffrement ECB : bloc par bloc ───────────────────────────────────────
    ecb_ct = des_encrypt_ecb(pixel_bytes, key)
    # Tronquer/padder pour avoir exactement w*h octets
    ecb_pixels = ecb_ct[:width * height]
    ecb_array  = np.frombuffer(ecb_pixels, dtype=np.uint8).reshape(height, width)
    ecb_img    = Image.fromarray(ecb_array, mode='L')
    ecb_path   = os.path.join(output_dir, "des_ecb_encrypted.png")
    ecb_img.save(ecb_path)

    # ── Chiffrement CBC pour comparaison ──────────────────────────────────────
    cbc_ct, _ = des_encrypt_cbc(pixel_bytes, key)
    cbc_pixels = cbc_ct[:width * height]
    cbc_array  = np.frombuffer(cbc_pixels, dtype=np.uint8).reshape(height, width)
    cbc_img    = Image.fromarray(cbc_array, mode='L')
    cbc_path   = os.path.join(output_dir, "des_cbc_encrypted.png")
    cbc_img.save(cbc_path)

    return {
        "key":           key.hex(),
        "original_path": original_path,
        "ecb_path":      ecb_path,
        "cbc_path":      cbc_path,
        "image_size":    f"{width}×{height}",
        "observation":   "ECB : motifs encore visibles. CBC : image indiscernable.",
    }


# ─────────────────────────────────────────────────────────────────────────────
#  TP2 Ex 2.2.3 — Triple-DES-CBC + Benchmark DES vs 3DES
# ─────────────────────────────────────────────────────────────────────────────

def tdes_encrypt_cbc(plaintext: bytes, key: bytes,
                     iv: bytes = None) -> tuple[bytes, bytes]:
    """Triple-DES-CBC. Retourne (ciphertext, iv)."""
    iv = iv or os.urandom(BLOCK_SIZE)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE)), iv


def tdes_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)


def benchmark_des_vs_3des(data_size_mb: float = 1.0,
                          iterations: int = 5) -> dict:
    """
    Mesure et compare les débits de DES vs 3DES sur `data_size_mb` Mo.

    Returns:
        {des_time_s, des_throughput_mbs, tdes_time_s, tdes_throughput_mbs,
         slowdown_factor}
    """
    data = os.urandom(int(data_size_mb * 1024 * 1024))
    des_key  = des_generate_key()
    tdes_key = tdes_generate_key(24)

    # ── DES ────────────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    for _ in range(iterations):
        ct, iv = des_encrypt_cbc(data, des_key)
        des_decrypt_cbc(ct, des_key, iv)
    des_time = (time.perf_counter() - t0) / iterations
    des_throughput = data_size_mb / des_time if des_time > 0 else 0

    # ── 3DES ───────────────────────────────────────────────────────────────
    t0 = time.perf_counter()
    for _ in range(iterations):
        ct, iv = tdes_encrypt_cbc(data, tdes_key)
        tdes_decrypt_cbc(ct, tdes_key, iv)
    tdes_time = (time.perf_counter() - t0) / iterations
    tdes_throughput = data_size_mb / tdes_time if tdes_time > 0 else 0

    return {
        "data_size_mb":        data_size_mb,
        "des_time_s":          des_time,
        "des_throughput_mbs":  des_throughput,
        "tdes_time_s":         tdes_time,
        "tdes_throughput_mbs": tdes_throughput,
        "slowdown_factor":     tdes_time / des_time if des_time > 0 else 0,
    }


# ─────────────────────────────────────────────────────────────────────────────
#  Fonctions de commodité
# ─────────────────────────────────────────────────────────────────────────────

def encrypt_text(plaintext: str, use_3des: bool = True) -> dict:
    data = plaintext.encode('utf-8')
    if use_3des:
        key = tdes_generate_key()
        ct, iv = tdes_encrypt_cbc(data, key)
        return {"ciphertext": ct, "key": key, "iv": iv, "algorithm": "3DES"}
    else:
        key = des_generate_key()
        ct, iv = des_encrypt_cbc(data, key)
        return {"ciphertext": ct, "key": key, "iv": iv, "algorithm": "DES"}


def decrypt_text(params: dict) -> str:
    algo = params["algorithm"]
    if algo == "3DES":
        pt = tdes_decrypt_cbc(params["ciphertext"], params["key"], params["iv"])
    else:
        pt = des_decrypt_cbc(params["ciphertext"], params["key"], params["iv"])
    return pt.decode('utf-8')


# ─────────────────────────────────────────────────────────────────────────────
#  Affichage des démonstrations TP2
# ─────────────────────────────────────────────────────────────────────────────

def print_ecb_vs_cbc_demo(plaintext: str = None) -> None:
    """Affiche la comparaison ECB vs CBC avec un texte répétitif."""
    if plaintext is None:
        # Texte avec blocs répétés pour rendre la faiblesse ECB visible
        plaintext = "BLOC_REPETITIF  " * 8    # 128 octets, blocs identiques

    data = plaintext.encode('utf-8')
    result = compare_ecb_cbc(data)

    print("\n" + "=" * 56)
    print("  FAIBLESSE ECB vs CBC")
    print("=" * 56)
    print(f"  Plaintext  ({len(data)} octets) : {plaintext[:40]}...")
    print(f"  Clé DES : {result['key']}")
    print(f"  IV CBC  : {result['iv']}")
    print()
    print(f"  ECB ciphertext (hex) :")
    print(f"    {result['ecb_hex']}")
    print(f"\n  CBC ciphertext (hex) :")
    print(f"    {result['cbc_hex']}")
    print()
    print(f"  Blocs identiques dans ECB : {result['ecb_repeated_blocks']}")
    print(f"  Blocs identiques dans CBC : {result['cbc_repeated_blocks']}")
    print()
    if result['ecb_repeated_blocks'] > 0:
        print("  ⚠ ECB : les blocs de plaintext identiques donnent des")
        print("    blocs de ciphertext IDENTIQUES → fuite de structure !")
    print("  ✓ CBC : la chaînage masque toute répétition.")


def print_benchmark_demo() -> None:
    """Affiche le benchmark DES vs 3DES."""
    print("\n" + "=" * 56)
    print("  BENCHMARK DES vs 3DES (1 Mo)")
    print("=" * 56)
    print("  Chiffrement en cours…")
    r = benchmark_des_vs_3des(data_size_mb=1.0, iterations=3)
    print(f"\n  DES  : {r['des_time_s']*1000:.1f} ms  "
          f"({r['des_throughput_mbs']:.1f} Mo/s)")
    print(f"  3DES : {r['tdes_time_s']*1000:.1f} ms  "
          f"({r['tdes_throughput_mbs']:.1f} Mo/s)")
    print(f"\n  3DES est ×{r['slowdown_factor']:.1f} plus lent que DES.")
    print("  → AES-256-CBC est ~10× plus rapide que 3DES et bien plus sûr.")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    msg = "DES / 3DES message de test"
    for use_3des in [False, True]:
        params = encrypt_text(msg, use_3des=use_3des)
        dec    = decrypt_text(params)
        algo   = params["algorithm"]
        print(f"=== {algo} ===")
        print(f"Clé  (hex) : {params['key'].hex()}")
        print(f"IV   (hex) : {params['iv'].hex()}")
        print(f"CT   (hex) : {params['ciphertext'].hex()}")
        print(f"Déchiffré  : {dec}\n")

    print_ecb_vs_cbc_demo()
    print_benchmark_demo()
    print("\n⚠ DES/3DES sont dépréciés. Utiliser AES-256.")
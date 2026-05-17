"""
main.py
--------
CryptoLab Interactive CLI
Couvre les 7 TPs de cryptographie — Ing3 Cybersécurité
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

# ─────────────────────────────────────────────────────────────────────────────
MENU = """
╔═══════════════════════════════════════════════════════════════╗
║                🔐 CRYPTOLAB — SUITE COMPLÈTE                  ║
╠═══════════════════════════════════════════════════════════════╣
║  TP1 — CHIFFREMENT CLASSIQUE                                  ║
║    1.  Chiffre de César (+ force brute + analyse IC)          ║
║    2.  Chiffre de Hill (2×2 / 3×3 + attaque clair connu)      ║
║    3.  Chiffre de Playfair                                     ║
║    4.  Chiffre de Vigenère (+ Kasiski + cryptanalyse IC)       ║
║    5.  One-Time Pad / Masque Jetable (+ vuln. réutilisation)  ║
║    6.  Analyse de fréquences + Indice de Coïncidence          ║
║                                                               ║
║  TP2 — CHIFFREMENT SYMÉTRIQUE                                 ║
║    7.  RC4 Stream Cipher                                      ║
║    8.  AES (128 / 192 / 256-bit)                              ║
║    9.  DES / Triple-DES                                       ║
║                                                               ║
║  TP3 — CRYPTOGRAPHIE ASYMÉTRIQUE                              ║
║   10.  RSA (2048-bit, OAEP)                                   ║
║   11.  Diffie-Hellman Key Exchange                            ║
║   12.  ElGamal Encryption                                     ║
║   13.  Shamir's Secret Sharing                                ║
║                                                               ║
║  TP4 — HACHAGE                                                ║
║   14.  MD5 / SHA-1 / SHA-256 / SHA-512 / SHA-3               ║
║   15.  HMAC-SHA256                                            ║
║                                                               ║
║  TP5 — SIGNATURES NUMÉRIQUES                                  ║
║   16.  RSA-PSS / ECDSA / EdDSA                               ║
║                                                               ║
║  TP6 — PROTOCOLES                                             ║
║   17.  Chiffrement Homomorphe (Paillier)                      ║
║                                                               ║
║    0.  Quitter                                                ║
╚═══════════════════════════════════════════════════════════════╝
"""

AFFINE_SUBMENU = """
  [a] Chiffrer / Déchiffrer
  [b] Retour au menu principal
"""


def sep(titre=""):
    w = 63
    print(f"\n{'─'*4} {titre} {'─'*(w-len(titre)-6)}" if titre else "─"*w)


def saisir(prompt, defaut=None):
    val = input(f"  {prompt}: ").strip()
    return val if val else defaut


# ══════════════════════════════════════════════════════════════════════════════
# TP1 — CLASSIQUE
# ══════════════════════════════════════════════════════════════════════════════

def demo_cesar():
    sep("CHIFFRE DE CÉSAR")
    from cesar import (chiffrer_cesar, dechiffrer_cesar,
                       afficher_analyse, force_brute_cesar)
    print("  [1] Chiffrer/Déchiffrer   [2] Force brute   [3] Analyse IC")
    choix = saisir("Choix", "1")

    if choix == "1":
        msg = saisir("Texte clair", "Bonjour le monde")
        k   = int(saisir("Décalage k", "7"))
        enc = chiffrer_cesar(msg, k)
        dec = dechiffrer_cesar(enc, k)
        print(f"\n  Chiffré   : {enc}")
        print(f"  Déchiffré : {dec}")

    elif choix == "2":
        crypto = saisir("Cryptogramme", chiffrer_cesar("Vive la cryptographie", 11))
        candidats = force_brute_cesar(crypto, top_n=5)
        print(f"\n  ── Force brute (top 5) ──")
        for k, score, texte in candidats:
            print(f"  k={k:2d}  score={score:.3f}  →  {texte[:60]}")

    elif choix == "3":
        msg = saisir("Message à chiffrer (clé cachée)", "les sciences sont belles")
        k   = int(saisir("Clé secrète k", "9"))
        crypto = chiffrer_cesar(msg, k)
        print(f"\n  Cryptogramme : {crypto}")
        afficher_analyse(crypto)


def demo_hill():
    sep("CHIFFRE DE HILL")
    from hill import (chiffrer_hill, dechiffrer_hill, valider_cle,
                      demo_attaque_clair_connu, CLE_2x2)
    print("  [1] Chiffrer/Déchiffrer 2×2   [2] Attaque clair connu")
    choix = saisir("Choix", "1")

    if choix == "1":
        msg = saisir("Texte clair", "CRYPTOGRAPHIE")
        print(f"  Clé utilisée (2×2) : {CLE_2x2}")
        valide, vmsg = valider_cle(CLE_2x2)
        print(f"  Validation clé     : {'✓' if valide else '✗'} {vmsg}")
        enc = chiffrer_hill(msg, CLE_2x2)
        dec = dechiffrer_hill(enc, CLE_2x2)
        print(f"\n  Chiffré   : {enc}")
        print(f"  Déchiffré : {dec}")

    elif choix == "2":
        print("\n  Démonstration de l'attaque à clair connu sur CLE_2x2 :")
        demo_attaque_clair_connu(CLE_2x2)


def demo_playfair():
    sep("CHIFFRE DE PLAYFAIR")
    from playfair import encrypt, decrypt
    cle = saisir("Mot-clé", "MONARCHY")
    msg = saisir("Texte clair", "INSTRUMENTS")
    enc = encrypt(msg, cle)
    dec = decrypt(enc, cle)
    print(f"\n  Chiffré   : {enc}")
    print(f"  Déchiffré : {dec}")


def demo_vigenere():
    sep("CHIFFRE DE VIGENÈRE")
    from vigenere import (chiffrer_vigenere, dechiffrer_vigenere,
                          afficher_cryptanalyse)
    print("  [1] Chiffrer/Déchiffrer   [2] Cryptanalyse complète")
    choix = saisir("Choix", "1")

    if choix == "1":
        cle = saisir("Clé", "LEMON")
        msg = saisir("Texte clair", "ATTACKATDAWN")
        enc = chiffrer_vigenere(msg, cle)
        dec = dechiffrer_vigenere(enc, cle)
        print(f"\n  Chiffré   : {enc}")
        print(f"  Déchiffré : {dec}")

    elif choix == "2":
        cle = saisir("Clé secrète (pour générer l'exemple)", "SECRET")
        msg = saisir("Message (sera répété 4× pour Kasiski)",
                     "les mathematiques sont le langage universel")
        crypto = chiffrer_vigenere(msg * 4, cle)
        print(f"\n  Cryptogramme (extrait) : {crypto[:80]}...")
        afficher_cryptanalyse(crypto)


def demo_otp():
    sep("ONE-TIME PAD / MASQUE JETABLE")
    from otp import (chiffrer_texte, dechiffrer_texte,
                     demo_reutilisation_cle, crib_dragging, demo_complete)
    print("  [1] Chiffrer/Déchiffrer   [2] Vulnérabilité réutilisation   [3] Démo complète")
    choix = saisir("Choix", "1")

    if choix == "1":
        msg = saisir("Message secret", "Top secret message")
        ct, cle = chiffrer_texte(msg)
        dec = dechiffrer_texte(ct, cle)
        print(f"\n  Clé (hex)  : {cle.hex()}")
        print(f"  Chiffré    : {ct.hex()}")
        print(f"  Déchiffré  : {dec}")
        print(f"  Correct    : {dec == msg} ✓")
        print(f"\n  ⚠ Clé à usage unique — NE JAMAIS réutiliser !")

    elif choix == "2":
        m1 = saisir("Message 1", "Le mot de passe est ALPHA")
        m2 = saisir("Message 2", "Rendez-vous a minuit ici")
        res = demo_reutilisation_cle(m1, m2)
        print(f"\n  C1 ⊕ C2 = M1 ⊕ M2 : {res['xor_c1_c2_hex'][:48]}...")
        print(f"  Identique à M1⊕M2 : {res['xor_egal']} ← la clé s'annule !")
        print(f"\n  {res['explication']}")
        xor = res['_xor']
        print(f"\n  Crib dragging avec 'Le ' :")
        for h in crib_dragging(xor, "Le ", seuil_score=1.0)[:3]:
            print(f"    pos={h['position']:3d}  fragment='{h['fragment_m2']}'  "
                  f"score={h['score']}")

    elif choix == "3":
        demo_complete()


def demo_frequences():
    sep("ANALYSE DE FRÉQUENCES")
    from frequency import print_frequency_analysis, index_of_coincidence
    msg = saisir("Texte à analyser",
                 "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
    print_frequency_analysis(msg)


# ══════════════════════════════════════════════════════════════════════════════
# TP2 — SYMÉTRIQUE
# ══════════════════════════════════════════════════════════════════════════════

def demo_rc4():
    sep("RC4 STREAM CIPHER")
    from rc4 import encrypt_text, decrypt_text
    cle = saisir("Clé", "SecretKey")
    msg = saisir("Texte clair", "Hello, RC4!")
    ct  = encrypt_text(msg, cle)
    dec = decrypt_text(ct, cle)
    print(f"\n  Chiffré (hex) : {ct.hex()}")
    print(f"  Déchiffré     : {dec}")
    print(f"  ⚠ RC4 est déprécié. Utiliser AES en production.")


def demo_aes():
    sep("AES 256-bit")
    from aes_cipher import encrypt_text, decrypt_text
    msg  = saisir("Texte clair", "Message confidentiel AES-256!")
    mode = saisir("Mode (GCM/CBC)", "GCM").upper()
    params = encrypt_text(msg, mode=mode)
    dec    = decrypt_text(params)
    print(f"\n  Clé  (hex) : {params['key'].hex()}")
    print(f"  CT   (hex) : {params['ciphertext'].hex()}")
    print(f"  Déchiffré  : {dec}")


def demo_des():
    sep("DES / 3DES")
    from des_cipher import encrypt_text, decrypt_text
    msg      = saisir("Texte clair", "Message DES exemple")
    use_3des = saisir("Utiliser 3DES ? (o/n)", "o").lower() == "o"
    params   = encrypt_text(msg, use_3des=use_3des)
    dec      = decrypt_text(params)
    print(f"\n  Algorithme : {params['algorithm']}")
    print(f"  Clé  (hex) : {params['key'].hex()}")
    print(f"  CT   (hex) : {params['ciphertext'].hex()}")
    print(f"  Déchiffré  : {dec}")


# ══════════════════════════════════════════════════════════════════════════════
# TP3 — ASYMÉTRIQUE
# ══════════════════════════════════════════════════════════════════════════════

def demo_rsa():
    sep("RSA 2048-bit")
    from rsa_cipher import generate_keypair, encrypt_oaep, decrypt_oaep
    print("  Génération de la paire de clés RSA 2048-bit...")
    priv, pub = generate_keypair(2048)
    msg = saisir("Texte clair", "Message secret RSA")
    ct  = encrypt_oaep(msg.encode(), pub)
    pt  = decrypt_oaep(ct, priv).decode()
    print(f"\n  CT   (hex) : {ct.hex()[:64]}...")
    print(f"  Déchiffré  : {pt}")


def demo_dh():
    sep("DIFFIE-HELLMAN")
    from diffie_hellman import DHParty
    print("  Simulation Alice ↔ Bob (groupe MODP 2048-bit)...")
    alice = DHParty()
    bob   = DHParty(p=alice.p, g=alice.g)
    cle_alice = alice.derive_aes_key(bob.public_key)
    cle_bob   = bob.derive_aes_key(alice.public_key)
    print(f"\n  Clé AES Alice : {cle_alice.hex()}")
    print(f"  Clé AES Bob   : {cle_bob.hex()}")
    print(f"  Identiques    : {cle_alice == cle_bob} ✓")


def demo_elgamal():
    sep("ELGAMAL")
    from elgamal import ElGamal
    eg  = ElGamal(bits=256)
    msg = saisir("Texte clair", "Message ElGamal")
    ct, longueur = eg.encrypt_text(msg)
    dec = eg.decrypt_text(ct, longueur)
    print(f"\n  Déchiffré : {dec}")


def demo_shamir():
    sep("PARTAGE DE SECRET DE SHAMIR")
    from shamir import split_text, reconstruct_text
    secret = saisir("Secret", "MotDePasseSecret!")
    n = int(saisir("Nombre total de parts (n)", "5"))
    k = int(saisir("Seuil (k)", "3"))
    shares, prime, byte_len = split_text(secret, n=n, k=k)
    print(f"\n  {n} parts générées. Reconstruction avec parts 1, 3, {n} :")
    subset   = [shares[0], shares[2], shares[n-1]]
    recupere = reconstruct_text(subset, prime, byte_len)
    print(f"  Récupéré  : {recupere}")
    print(f"  Correct   : {recupere == secret} ✓")


# ══════════════════════════════════════════════════════════════════════════════
# TP4 — HACHAGE
# ══════════════════════════════════════════════════════════════════════════════

def demo_hachage():
    sep("FONCTIONS DE HACHAGE")
    from sha_hash import hash_all
    msg = saisir("Texte à hacher", "Hello, World!")
    resultats = hash_all(msg)
    print()
    for algo, digest in resultats.items():
        print(f"  {algo:<10}: {digest}")


def demo_hmac():
    sep("HMAC-SHA256")
    from hmac_sign import generate_hmac_key, hmac_sha256, hmac_verify
    cle = generate_hmac_key()
    msg = saisir("Message", "Authentifier ce message")
    mac = hmac_sha256(cle, msg)
    valide = hmac_verify(cle, msg, mac)
    print(f"\n  Clé (hex) : {cle.hex()}")
    print(f"  MAC       : {mac}")
    print(f"  Valide    : {valide} ✓")


# ══════════════════════════════════════════════════════════════════════════════
# TP5 — SIGNATURES
# ══════════════════════════════════════════════════════════════════════════════

def demo_signatures():
    sep("SIGNATURES NUMÉRIQUES")
    from signature import RSASignature, ECDSASignature
    msg = saisir("Message à signer", "Signer ce document important")

    print("\n  RSA-PSS (2048-bit) :")
    rsa = RSASignature(2048)
    sig = rsa.sign(msg)
    print(f"  Valide  : {RSASignature.verify(msg, sig, rsa.public_key)} ✓")
    print(f"  Altéré  : {RSASignature.verify(msg + 'X', sig, rsa.public_key)} ✗")

    print("\n  ECDSA (P-256) :")
    ec  = ECDSASignature("P-256")
    sig = ec.sign(msg)
    print(f"  Valide  : {ECDSASignature.verify(msg, sig, ec.public_key)} ✓")


# ══════════════════════════════════════════════════════════════════════════════
# TP6 — PROTOCOLES
# ══════════════════════════════════════════════════════════════════════════════

def demo_homomorphe():
    sep("CHIFFREMENT HOMOMORPHE — PAILLIER")
    from homomorphic import Paillier
    p = Paillier(bits=256)
    a = int(saisir("Valeur a", "42"))
    b = int(saisir("Valeur b", "17"))
    ca     = p.encrypt(a)
    cb     = p.encrypt(b)
    c_sum  = p.add_ciphertexts(ca, cb)
    c_diff = p.subtract_ciphertexts(ca, cb)
    k = 5
    c_mul  = p.multiply_by_scalar(ca, k)
    print(f"\n  Enc({a}) + Enc({b}) déchiffré : {p.decrypt(c_sum)}  (attendu {a+b})")
    print(f"  Enc({a}) - Enc({b}) déchiffré : {p.decrypt(c_diff)}  (attendu {a-b})")
    print(f"  Enc({a}) × {k}       déchiffré : {p.decrypt(c_mul)}  (attendu {a*k})")


# ══════════════════════════════════════════════════════════════════════════════
# DISPATCH
# ══════════════════════════════════════════════════════════════════════════════

HANDLERS = {
    "1":  demo_cesar,
    "2":  demo_hill,
    "3":  demo_playfair,
    "4":  demo_vigenere,
    "5":  demo_otp,
    "6":  demo_frequences,
    "7":  demo_rc4,
    "8":  demo_aes,
    "9":  demo_des,
    "10": demo_rsa,
    "11": demo_dh,
    "12": demo_elgamal,
    "13": demo_shamir,
    "14": demo_hachage,
    "15": demo_hmac,
    "16": demo_signatures,
    "17": demo_homomorphe,
}


def main():
    print(MENU)
    while True:
        choix = input("\n  Sélectionner [0-17] : ").strip()
        if choix == "0":
            print("  Au revoir ! 🔐")
            break
        handler = HANDLERS.get(choix)
        if handler:
            try:
                handler()
            except Exception as e:
                print(f"\n  ❌ Erreur : {e}")
                import traceback
                traceback.print_exc()
        else:
            print("  Choix invalide. Entrer un nombre entre 0 et 17.")


if __name__ == "__main__":
    main()

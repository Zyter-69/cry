"""
classical/hill.py
-----------------
Chiffre de Hill — TP1 Exercice 1.3

1. Hill 2×2 et 3×3 — chiffrement/déchiffrement + vérification de la matrice clé
2. Attaque à clair connu (known-plaintext attack)
3. Analyse : pourquoi Hill est vulnérable même pour de grandes matrices
"""

import numpy as np
from math import gcd

ALPHABET = 26


# ── Fonctions mathématiques ───────────────────────────────────────────────────

def _pgcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _inverse_mod(a: int, m: int) -> int:
    """Inverse modulaire de a mod m (algorithme étendu d'Euclide)."""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} n'est pas inversible mod {m} (pgcd={g})")
    return x % m


def _extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def _determinant_mod(matrice: np.ndarray, mod: int) -> int:
    """Déterminant de la matrice, réduit mod `mod`."""
    return int(round(np.linalg.det(matrice))) % mod


def _verifier_matrice(K: np.ndarray) -> tuple[bool, str]:
    """
    Vérifie qu'une matrice K est valide comme clé Hill mod 26.
    Conditions : carrée, det(K) inversible mod 26 (i.e. pgcd(det, 26) == 1).
    """
    n, m = K.shape
    if n != m:
        return False, "La matrice doit être carrée."
    det = _determinant_mod(K, ALPHABET)
    if det == 0:
        return False, f"det(K) ≡ 0 (mod 26) → matrice singulière, non inversible."
    g = _pgcd(det, ALPHABET)
    if g != 1:
        return False, (f"pgcd(det(K) mod 26, 26) = pgcd({det}, 26) = {g} ≠ 1 "
                       f"→ matrice non inversible mod 26.")
    return True, f"Valide — det(K) ≡ {det} (mod 26), inversible mod 26."


def _inverse_matrice_mod(K: np.ndarray, mod: int) -> np.ndarray:
    """
    Inverse modulaire d'une matrice carrée K mod `mod`.
    Formule : K⁻¹ = det(K)⁻¹ × adj(K)  mod m
    """
    det = _determinant_mod(K, mod)
    det_inv = _inverse_mod(det, mod)
    n = K.shape[0]
    adj = np.zeros((n, n), dtype=int)
    for i in range(n):
        for j in range(n):
            mineur = np.delete(np.delete(K, i, axis=0), j, axis=1)
            cofacteur = int(round(np.linalg.det(mineur))) * ((-1) ** (i + j))
            adj[j][i] = cofacteur  # transposée ici
    return (det_inv * adj) % mod


# ── Préparation du texte ──────────────────────────────────────────────────────

def _texte_en_vecteurs(texte: str, n: int) -> list[np.ndarray]:
    """Convertit le texte en liste de vecteurs colonnes de taille n."""
    texte = ''.join(c for c in texte.upper() if c.isalpha())
    # Compléter avec 'X' pour atteindre un multiple de n
    while len(texte) % n:
        texte += 'X'
    return [
        np.array([ord(c) - ord('A') for c in texte[i:i+n]], dtype=int)
        for i in range(0, len(texte), n)
    ]


def _vecteurs_en_texte(vecteurs: list[np.ndarray]) -> str:
    return ''.join(chr(int(v) % ALPHABET + ord('A'))
                   for vec in vecteurs for v in vec)


# ── 1. Chiffrement / Déchiffrement ────────────────────────────────────────────

def valider_cle(cle_matrice: list[list[int]]) -> tuple[bool, str]:
    """Vérifie et retourne (valide: bool, message: str)."""
    K = np.array(cle_matrice, dtype=int)
    return _verifier_matrice(K)


def chiffrer_hill(texte: str, cle_matrice: list[list[int]]) -> str:
    """
    Chiffrement Hill : C = K × P  mod 26
    K doit être une matrice n×n inversible mod 26.
    """
    K = np.array(cle_matrice, dtype=int)
    valide, msg = _verifier_matrice(K)
    if not valide:
        raise ValueError(f"Matrice clé invalide : {msg}")
    n = K.shape[0]
    vecteurs = _texte_en_vecteurs(texte, n)
    chiffres = [(K @ v) % ALPHABET for v in vecteurs]
    return _vecteurs_en_texte(chiffres)


def dechiffrer_hill(cryptogramme: str, cle_matrice: list[list[int]]) -> str:
    """
    Déchiffrement Hill : P = K⁻¹ × C  mod 26
    """
    K = np.array(cle_matrice, dtype=int)
    valide, msg = _verifier_matrice(K)
    if not valide:
        raise ValueError(f"Matrice clé invalide : {msg}")
    n = K.shape[0]
    K_inv = _inverse_matrice_mod(K, ALPHABET)
    vecteurs = _texte_en_vecteurs(cryptogramme, n)
    dechiffres = [(K_inv @ v) % ALPHABET for v in vecteurs]
    return _vecteurs_en_texte(dechiffres)


# ── 2. Attaque à clair connu ──────────────────────────────────────────────────

def attaque_clair_connu(paires_clair_chiffre: list[tuple[str, str]], n: int) -> dict:
    """
    Attaque à clair connu sur le chiffre de Hill de taille n×n.

    Principe :
        C = K × P  mod 26
        Si on connaît n couples (p_i, c_i), on forme les matrices P et C
        avec les vecteurs colonnes, puis :
        K = C × P⁻¹  mod 26  (si P est inversible mod 26)

    Args:
        paires_clair_chiffre : liste de (clair, chiffre) — au moins n paires de n lettres
        n                    : taille de la matrice (2 pour Hill 2×2, 3 pour 3×3)

    Returns:
        dict avec 'cle_retrouvee', 'verification', 'details'
    """
    # Construire les matrices P (clair) et C (chiffré)
    paires_utiles = paires_clair_chiffre[:n]  # n paires suffisent
    if len(paires_utiles) < n:
        raise ValueError(f"Il faut au moins {n} paires (clair, chiffré) pour un Hill {n}×{n}.")

    # Extraire n vecteurs de longueur n
    P_cols = []
    C_cols = []
    for clair, chiffre in paires_utiles:
        p_net = ''.join(c for c in clair.upper() if c.isalpha())[:n]
        c_net = ''.join(c for c in chiffre.upper() if c.isalpha())[:n]
        if len(p_net) < n or len(c_net) < n:
            raise ValueError(f"Chaque paire doit contenir au moins {n} lettres.")
        P_cols.append([ord(c) - ord('A') for c in p_net])
        C_cols.append([ord(c) - ord('A') for c in c_net])

    # P et C sont des matrices dont les colonnes sont les vecteurs
    P = np.array(P_cols, dtype=int).T  # shape (n, n)
    C = np.array(C_cols, dtype=int).T  # shape (n, n)

    # Vérifier que P est inversible mod 26
    det_P = _determinant_mod(P, ALPHABET)
    if _pgcd(det_P, ALPHABET) != 1:
        return {
            'succes': False,
            'erreur': (f"La matrice clair P n'est pas inversible mod 26 "
                       f"(det={det_P}). Choisir d'autres paires de clair connu."),
            'P': P.tolist(),
            'det_P': det_P,
        }

    # K = C × P⁻¹ mod 26
    P_inv = _inverse_matrice_mod(P, ALPHABET)
    K_retrouvee = (C @ P_inv) % ALPHABET

    # Vérification : K × P doit donner C
    verification = np.all((K_retrouvee @ P) % ALPHABET == C)

    return {
        'succes': True,
        'cle_retrouvee': K_retrouvee.tolist(),
        'P': P.tolist(),
        'C': C.tolist(),
        'verification': bool(verification),
        'message': (
            "Clé retrouvée avec succès !" if verification
            else "⚠ Vérification échouée — paires peut-être inconsistantes."
        )
    }


def demo_attaque_clair_connu(cle_reelle: list[list[int]]) -> None:
    """
    Démontre l'attaque à clair connu sur une clé connue.
    Génère des paires aléatoires jusqu'à obtenir une matrice clair inversible mod 26.
    """
    n = len(cle_reelle)
    import random, string

    res = {'succes': False}
    tentatives = 0
    while not res['succes'] and tentatives < 50:
        tentatives += 1
        paires = []
        for _ in range(n):
            clair = ''.join(random.choices(string.ascii_uppercase, k=n))
            chiffre = chiffrer_hill(clair, cle_reelle)
            paires.append((clair, chiffre))
        res = attaque_clair_connu(paires, n)

    print(f"  Paires utilisées (après {tentatives} tentative(s)) :")
    for p, c in paires:
        print(f"    clair='{p}' → chiffré='{c}'")

    if res['succes']:
        print(f"\n  Clé réelle      : {cle_reelle}")
        print(f"  Clé retrouvée   : {res['cle_retrouvee']}")
        print(f"  Correspondance  : {res['cle_retrouvee'] == cle_reelle} ← {'✓' if res['cle_retrouvee'] == cle_reelle else '✗'}")
        print(f"  Vérif C=K×P     : {res['verification']}")
    else:
        print(f"  ✗ Échec après {tentatives} tentatives — {res.get('erreur', '')}")


# ── Matrices de démonstration ─────────────────────────────────────────────────

CLE_2x2 = [[3, 3], [2, 5]]    # det=9, pgcd(9,26)=1 ✓
CLE_3x3 = [[2, 4, 5],
            [9, 2, 1],
            [3, 17, 7]]        # det ≡ 21 mod 26, valide
CLE_3x3_VALIDE = [[1, 2, 3],
                   [4, 5, 6],
                   [7, 8, 10]] # à vérifier à l'exécution


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import random, string

    # ── Test validation de clés ──
    print("=" * 55)
    print("  VALIDATION DES MATRICES CLÉS")
    print("=" * 55)
    for nom, K in [("CLE_2x2", CLE_2x2), ("CLE_3x3 (invalide)", CLE_3x3),
                   ("CLE_3x3_VALIDE", CLE_3x3_VALIDE)]:
        valide, msg = valider_cle(K)
        print(f"  {nom:<22} → {'✓' if valide else '✗'} {msg}")

    # ── Chiffrement/Déchiffrement 2×2 ──
    print("\n" + "=" * 55)
    print("  HILL 2×2")
    print("=" * 55)
    msg = "CRYPTOGRAPHIE"
    enc = chiffrer_hill(msg, CLE_2x2)
    dec = dechiffrer_hill(enc, CLE_2x2)
    print(f"  Clair     : {msg}")
    print(f"  Chiffré   : {enc}")
    print(f"  Déchiffré : {dec}")

    # ── Attaque à clair connu 2×2 ──
    print("\n" + "=" * 55)
    print("  ATTAQUE À CLAIR CONNU — Hill 2×2")
    print("=" * 55)
    demo_attaque_clair_connu(CLE_2x2)

    # ── Chiffrement 3×3 avec clé valide ──
    K3_test = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]  # clé classique de Hill
    valide, msg_v = valider_cle(K3_test)
    print(f"\n  Clé 3×3 test : {'✓ valide' if valide else '✗ invalide'} — {msg_v}")
    if valide:
        msg3 = "GYBNQKURP"
        enc3 = chiffrer_hill(msg3, K3_test)
        dec3 = dechiffrer_hill(enc3, K3_test)
        print(f"  Clair     : {msg3}")
        print(f"  Chiffré   : {enc3}")
        print(f"  Déchiffré : {dec3}")

        print("\n  Attaque à clair connu — Hill 3×3 :")
        demo_attaque_clair_connu(K3_test)

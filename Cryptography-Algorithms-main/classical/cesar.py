"""
classical/cesar.py
------------------
Chiffre de César — TP1 Exercice 1.1

1. chiffrer_cesar / dechiffrer_cesar
2. Attaque par force brute (26 clés) + détection auto du français
3. Déduction de k par analyse de fréquences (IC + chi²)
"""

from collections import Counter
import math

# ── Fréquences françaises (%) ──────────────────────────────────────────────────
FREQ_FR = {
    'A': 7.636, 'B': 0.901, 'C': 3.260, 'D': 3.669, 'E': 14.715,
    'F': 1.066, 'G': 1.054, 'H': 1.069, 'I': 7.529, 'J': 0.545,
    'K': 0.049, 'L': 5.456, 'M': 2.968, 'N': 7.095, 'O': 5.378,
    'P': 3.021, 'Q': 0.836, 'R': 6.553, 'S': 7.948, 'T': 7.244,
    'U': 6.311, 'V': 1.628, 'W': 0.114, 'X': 0.427, 'Y': 0.128,
    'Z': 0.326
}

# IC théorique du français ≈ 0.074, anglais ≈ 0.065, aléatoire ≈ 0.038
IC_FRANCAIS = 0.074

# Mots français courants pour la détection automatique
MOTS_FRANCAIS = {
    'le', 'la', 'les', 'de', 'du', 'des', 'un', 'une', 'et', 'est',
    'en', 'que', 'qui', 'il', 'elle', 'nous', 'vous', 'ils', 'elles',
    'je', 'tu', 'on', 'par', 'sur', 'dans', 'avec', 'pour', 'pas',
    'ne', 'ce', 'se', 'sa', 'son', 'ses', 'mon', 'ma', 'mes', 'ton',
    'ta', 'tes', 'au', 'aux', 'ou', 'si', 'car', 'donc', 'mais', 'ni',
    'leur', 'leurs', 'tout', 'tous', 'bien', 'plus', 'très', 'avoir',
    'être', 'faire', 'dire', 'aller', 'voir', 'vouloir', 'pouvoir',
    'comme', 'quand', 'aussi', 'alors', 'encore', 'après', 'avant',
    'sans', 'sous', 'entre', 'vers', 'chez', 'lors'
}


# ── 1. Chiffrement / Déchiffrement ────────────────────────────────────────────

def chiffrer_cesar(texte: str, k: int) -> str:
    """
    Chiffre le texte avec le décalage k.
    Ignore les espaces et la casse (résultat en majuscules).
    Les caractères non-alphabétiques sont conservés tels quels.
    """
    k = k % 26
    resultat = []
    for c in texte.upper():
        if c.isalpha():
            resultat.append(chr((ord(c) - ord('A') + k) % 26 + ord('A')))
        else:
            resultat.append(c)
    return ''.join(resultat)


def dechiffrer_cesar(texte: str, k: int) -> str:
    """Déchiffre un texte chiffré avec le décalage k."""
    return chiffrer_cesar(texte, -k)


# ── 2. Attaque par force brute ────────────────────────────────────────────────

def _score_francais(texte: str) -> float:
    """
    Score de 'français-ité' d'un texte.
    Combine : mots reconnus + distance chi² aux fréquences françaises.
    Plus le score est élevé, plus le texte ressemble au français.
    """
    mots = texte.lower().split()
    if not mots:
        return 0.0

    # Proportion de mots français reconnus
    score_mots = sum(1 for m in mots if m in MOTS_FRANCAIS) / len(mots)

    # Chi² inversé (plus les fréquences collent, plus le score monte)
    lettres = [c for c in texte.upper() if c.isalpha()]
    if not lettres:
        return score_mots

    n = len(lettres)
    counts = Counter(lettres)
    chi2 = sum(
        (counts.get(c, 0) / n * 100 - FREQ_FR[c]) ** 2 / FREQ_FR[c]
        for c in FREQ_FR
    )
    score_freq = 1 / (1 + chi2)

    return 0.6 * score_mots + 0.4 * score_freq


def force_brute_cesar(cryptogramme: str, top_n: int = 5) -> list[tuple[int, float, str]]:
    """
    Teste les 26 décalages possibles.

    Returns:
        Liste triée (décalage, score, texte_déchiffré) — les meilleurs candidats en tête.
    """
    resultats = []
    for k in range(26):
        clair = dechiffrer_cesar(cryptogramme, k)
        score = _score_francais(clair)
        resultats.append((k, score, clair))

    resultats.sort(key=lambda x: x[1], reverse=True)
    return resultats[:top_n]


def detecter_cle_cesar(cryptogramme: str) -> tuple[int, str]:
    """
    Identifie automatiquement le décalage le plus probable.
    Returns: (k, texte_déchiffré)
    """
    meilleur = force_brute_cesar(cryptogramme, top_n=1)[0]
    return meilleur[0], meilleur[2]


# ── 3. Analyse de fréquences — déduction de k sans force brute ───────────────

def indice_de_coincidence(texte: str) -> float:
    """
    IC = Σ f_i*(f_i-1) / N*(N-1)
    Français ≈ 0.074 | Aléatoire ≈ 0.038
    """
    lettres = [c for c in texte.upper() if c.isalpha()]
    n = len(lettres)
    if n <= 1:
        return 0.0
    counts = Counter(lettres)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


def _chi2_avec_decalage(texte: str, decalage: int) -> float:
    """Chi² entre les fréquences observées (avec décalage) et le français."""
    lettres = [c for c in texte.upper() if c.isalpha()]
    n = len(lettres)
    if n == 0:
        return float('inf')
    counts = Counter(lettres)
    chi2 = 0.0
    for i, lettre in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
        lettre_orig = chr((i - decalage) % 26 + ord('A'))
        observee = counts.get(lettre, 0) / n * 100
        attendue = FREQ_FR[lettre_orig]
        chi2 += (observee - attendue) ** 2 / attendue
    return chi2


def deduire_cle_par_frequences(cryptogramme: str) -> tuple[int, float, float]:
    """
    Déduit k par analyse de fréquences (chi² minimal vs fréquences françaises).
    Ne nécessite pas de force brute.

    Returns:
        (k_probable, chi2_minimum, ic_cryptogramme)
    """
    ic = indice_de_coincidence(cryptogramme)

    # Pour César, on cherche le décalage qui minimise le chi²
    meilleur_k = 0
    meilleur_chi2 = float('inf')
    for k in range(26):
        chi2 = _chi2_avec_decalage(cryptogramme, k)
        if chi2 < meilleur_chi2:
            meilleur_chi2 = chi2
            meilleur_k = k

    return meilleur_k, meilleur_chi2, ic


def analyse_complete_cesar(cryptogramme: str) -> dict:
    """
    Analyse complète : IC, déduction par fréquences, force brute.
    Returns un dictionnaire avec tous les résultats.
    """
    ic = indice_de_coincidence(cryptogramme)
    k_freq, chi2, _ = deduire_cle_par_frequences(cryptogramme)
    candidats = force_brute_cesar(cryptogramme, top_n=3)

    return {
        'ic': ic,
        'ic_francais': IC_FRANCAIS,
        'diagnostic': 'monoalphabetique' if ic > 0.060 else 'probablement polyalphabetique',
        'k_par_frequences': k_freq,
        'chi2_min': chi2,
        'dechiffre_freq': dechiffrer_cesar(cryptogramme, k_freq),
        'top_candidats_brute': candidats,
    }


# ── Affichage ─────────────────────────────────────────────────────────────────

def afficher_analyse(cryptogramme: str) -> None:
    res = analyse_complete_cesar(cryptogramme)
    print("=" * 60)
    print("  ANALYSE CÉSAR")
    print("=" * 60)
    print(f"  Cryptogramme    : {cryptogramme[:60]}{'...' if len(cryptogramme)>60 else ''}")
    print(f"  IC calculé      : {res['ic']:.4f}  (français≈{res['ic_francais']})")
    print(f"  Diagnostic      : {res['diagnostic']}")
    print()
    print(f"  ── Déduction par fréquences (chi²) ──")
    print(f"  Clé probable    : k = {res['k_par_frequences']}")
    print(f"  Chi² minimal    : {res['chi2_min']:.2f}")
    print(f"  Déchiffré       : {res['dechiffre_freq'][:80]}")
    print()
    print(f"  ── Force brute (top 3) ──")
    for k, score, texte in res['top_candidats_brute']:
        print(f"  k={k:2d}  score={score:.3f}  →  {texte[:50]}")
    print("=" * 60)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # Exemple 1 : chiffrement simple
    msg = "Bonjour le monde, ceci est un message secret en francais"
    k = 13
    enc = chiffrer_cesar(msg, k)
    dec = dechiffrer_cesar(enc, k)
    print(f"Message   : {msg}")
    print(f"Clé       : k = {k}")
    print(f"Chiffré   : {enc}")
    print(f"Déchiffré : {dec}\n")

    # Exemple 2 : attaque
    cryptogramme = chiffrer_cesar(
        "les mathématiques sont le langage dans lequel dieu a écrit l univers", 7
    )
    print(f"Cryptogramme (k=7 caché) :")
    print(f"  {cryptogramme}\n")
    afficher_analyse(cryptogramme)

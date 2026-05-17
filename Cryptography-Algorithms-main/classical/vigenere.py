"""
classical/vigenere.py
---------------------
Chiffre de Vigenère — TP1 Exercice 1.2

1. chiffrer_vigenere / dechiffrer_vigenere
2. Test de Kasiski — trigrammes répétés → longueur probable de la clé
3. Analyse par IC — découper en sous-séquences, retrouver les lettres de la clé
4. Cryptanalyse complète automatique
"""

from collections import Counter
from math import gcd
from functools import reduce

# Fréquences françaises (%)
FREQ_FR = {
    'A': 7.636, 'B': 0.901, 'C': 3.260, 'D': 3.669, 'E': 14.715,
    'F': 1.066, 'G': 1.054, 'H': 1.069, 'I': 7.529, 'J': 0.545,
    'K': 0.049, 'L': 5.456, 'M': 2.968, 'N': 7.095, 'O': 5.378,
    'P': 3.021, 'Q': 0.836, 'R': 6.553, 'S': 7.948, 'T': 7.244,
    'U': 6.311, 'V': 1.628, 'W': 0.114, 'X': 0.427, 'Y': 0.128,
    'Z': 0.326
}
IC_FRANCAIS = 0.074


# ── Helpers ───────────────────────────────────────────────────────────────────

def _nettoyer(texte: str) -> str:
    """Majuscules, lettres uniquement."""
    return ''.join(c.upper() for c in texte if c.isalpha())


def _indice_de_coincidence(texte: str) -> float:
    """IC = Σ f_i*(f_i-1) / N*(N-1)"""
    n = len(texte)
    if n <= 1:
        return 0.0
    counts = Counter(texte)
    return sum(f * (f - 1) for f in counts.values()) / (n * (n - 1))


def _chi2_decalage(sous_seq: str, decalage: int) -> float:
    """Chi² en supposant un décalage César de `decalage` sur cette sous-séquence."""
    n = len(sous_seq)
    if n == 0:
        return float('inf')
    counts = Counter(sous_seq)
    chi2 = 0.0
    for i, lettre in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ'):
        lettre_orig = chr((i - decalage) % 26 + ord('A'))
        obs = counts.get(lettre, 0) / n * 100
        att = FREQ_FR[lettre_orig]
        chi2 += (obs - att) ** 2 / att
    return chi2


def _pgcd_liste(nombres: list[int]) -> int:
    """PGCD d'une liste de nombres."""
    if not nombres:
        return 1
    return reduce(gcd, nombres)


# ── 1. Chiffrement / Déchiffrement ────────────────────────────────────────────

def chiffrer_vigenere(texte: str, cle: str) -> str:
    """
    Chiffre le texte avec la clé Vigenère (mot alphabétique).
    Les caractères non-alphabétiques sont conservés.
    E(m_i) = (m_i + k_{i mod |k|}) mod 26
    """
    cle = _nettoyer(cle)
    if not cle:
        raise ValueError("La clé doit contenir au moins une lettre.")
    resultat = []
    idx = 0
    for c in texte.upper():
        if c.isalpha():
            decalage = ord(cle[idx % len(cle)]) - ord('A')
            resultat.append(chr((ord(c) - ord('A') + decalage) % 26 + ord('A')))
            idx += 1
        else:
            resultat.append(c)
    return ''.join(resultat)


def dechiffrer_vigenere(texte: str, cle: str) -> str:
    """
    Déchiffre un texte Vigenère.
    D(c_i) = (c_i - k_{i mod |k|}) mod 26
    """
    cle = _nettoyer(cle)
    if not cle:
        raise ValueError("La clé doit contenir au moins une lettre.")
    resultat = []
    idx = 0
    for c in texte.upper():
        if c.isalpha():
            decalage = ord(cle[idx % len(cle)]) - ord('A')
            resultat.append(chr((ord(c) - ord('A') - decalage) % 26 + ord('A')))
            idx += 1
        else:
            resultat.append(c)
    return ''.join(resultat)


# ── 2. Test de Kasiski ────────────────────────────────────────────────────────

def test_kasiski(cryptogramme: str, longueur_ngram: int = 3,
                 max_resultats: int = 10) -> dict:
    """
    Test de Kasiski : recherche de n-grammes répétés dans le cryptogramme.
    Les distances entre répétitions sont des multiples probables de la longueur de clé.

    Args:
        cryptogramme    : texte chiffré
        longueur_ngram  : longueur des séquences à chercher (3 = trigrammes)
        max_resultats   : nombre de n-grammes à retourner

    Returns:
        dict avec 'ngrams' (répétitions trouvées), 'distances', 'pgcd', 'longueurs_probables'
    """
    texte = _nettoyer(cryptogramme)
    n = len(texte)

    # Trouver tous les n-grammes répétés et leurs positions
    occurrences: dict[str, list[int]] = {}
    for i in range(n - longueur_ngram + 1):
        ng = texte[i:i + longueur_ngram]
        occurrences.setdefault(ng, []).append(i)

    # Garder seulement les répétitions
    repetes = {ng: pos for ng, pos in occurrences.items() if len(pos) > 1}

    if not repetes:
        return {
            'ngrams': {},
            'distances': [],
            'pgcd': None,
            'longueurs_probables': [],
            'message': f"Aucun {longueur_ngram}-gramme répété trouvé. "
                       "Texte trop court ou clé très longue ?"
        }

    # Calculer les distances entre chaque paire de répétitions
    toutes_distances = []
    details_ngrams = {}
    for ng, positions in sorted(repetes.items(),
                                 key=lambda x: len(x[1]), reverse=True)[:max_resultats]:
        dists = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
        toutes_distances.extend(dists)
        details_ngrams[ng] = {'positions': positions, 'distances': dists}

    # Facteurs de toutes les distances (diviseurs communs = longueur probable de clé)
    compteur_facteurs: dict[int, int] = Counter()
    for d in toutes_distances:
        for f in range(2, min(d + 1, 31)):   # Clés jusqu'à longueur 30
            if d % f == 0:
                compteur_facteurs[f] += 1

    # Trier par fréquence (le plus fréquent = longueur de clé probable)
    longueurs_probables = sorted(compteur_facteurs.items(),
                                  key=lambda x: x[1], reverse=True)[:8]

    pgcd = _pgcd_liste(toutes_distances) if toutes_distances else None

    return {
        'ngrams': details_ngrams,
        'distances': sorted(set(toutes_distances)),
        'pgcd': pgcd,
        'longueurs_probables': longueurs_probables,
    }


# ── 3. Analyse par IC — retrouver la clé ─────────────────────────────────────

def ic_par_longueur_cle(cryptogramme: str, max_longueur: int = 20) -> list[tuple[int, float]]:
    """
    Pour chaque longueur de clé candidate k, divise le cryptogramme en k
    sous-séquences et calcule l'IC moyen.
    La longueur k dont l'IC moyen est le plus proche de l'IC du français est la bonne.

    Returns:
        Liste (longueur_cle, ic_moyen) triée par proximité à IC_FRANCAIS.
    """
    texte = _nettoyer(cryptogramme)
    resultats = []
    for k in range(1, max_longueur + 1):
        sous_seqs = [texte[i::k] for i in range(k)]
        ics = [_indice_de_coincidence(s) for s in sous_seqs if len(s) > 1]
        if ics:
            ic_moy = sum(ics) / len(ics)
            resultats.append((k, ic_moy))

    resultats.sort(key=lambda x: abs(x[1] - IC_FRANCAIS))
    return resultats


def retrouver_cle(cryptogramme: str, longueur_cle: int) -> str:
    """
    Pour une longueur de clé connue, retrouve chaque lettre de la clé
    par analyse de fréquences (chi² minimal sur chaque sous-séquence).

    Args:
        cryptogramme  : texte chiffré (lettres uniquement)
        longueur_cle  : longueur de la clé à retrouver

    Returns:
        La clé probable sous forme de chaîne.
    """
    texte = _nettoyer(cryptogramme)
    cle = []
    for i in range(longueur_cle):
        sous_seq = texte[i::longueur_cle]
        # Trouver le décalage qui minimise le chi²
        meilleur_dec = min(range(26), key=lambda d: _chi2_decalage(sous_seq, d))
        cle.append(chr(meilleur_dec + ord('A')))
    return ''.join(cle)


def cryptanalyse_vigenere(cryptogramme: str, max_longueur_cle: int = 20) -> dict:
    """
    Cryptanalyse complète automatique d'un chiffré Vigenère.

    1. Test de Kasiski pour estimer la longueur de clé
    2. Confirmation par IC
    3. Retrouver les lettres de la clé par chi²

    Returns:
        dict avec 'longueur_probable', 'cle_probable', 'texte_dechiffre', détails...
    """
    # Étape 1 : Kasiski
    kasiski = test_kasiski(cryptogramme)
    kasiski_top = kasiski['longueurs_probables']

    # Étape 2 : IC par longueur de clé
    ic_resultats = ic_par_longueur_cle(cryptogramme, max_longueur_cle)
    longueur_ic = ic_resultats[0][0] if ic_resultats else 1

    # Réconcilier Kasiski + IC : on prend le top de l'IC comme principal
    longueur_probable = longueur_ic

    # Si Kasiski a un résultat fort qui figure dans le top 3 IC → priorité à Kasiski
    if kasiski_top:
        kasiski_top1 = kasiski_top[0][0]
        top3_ic = {r[0] for r in ic_resultats[:3]}
        if kasiski_top1 in top3_ic:
            longueur_probable = kasiski_top1

    # Étape 3 : retrouver la clé
    cle = retrouver_cle(cryptogramme, longueur_probable)
    texte_dec = dechiffrer_vigenere(cryptogramme, cle)

    return {
        'longueur_probable': longueur_probable,
        'cle_probable': cle,
        'texte_dechiffre': texte_dec,
        'kasiski': kasiski,
        'ic_par_longueur': ic_resultats[:8],
    }


# ── Affichage ─────────────────────────────────────────────────────────────────

def afficher_cryptanalyse(cryptogramme: str) -> None:
    res = cryptanalyse_vigenere(cryptogramme)
    print("=" * 65)
    print("  CRYPTANALYSE VIGENÈRE")
    print("=" * 65)
    print(f"  Cryptogramme ({len(_nettoyer(cryptogramme))} lettres) : "
          f"{cryptogramme[:50]}{'...' if len(cryptogramme)>50 else ''}")

    print(f"\n  ── Test de Kasiski ──")
    if res['kasiski']['longueurs_probables']:
        print(f"  Longueurs probables (fréquence des facteurs) :")
        for lng, freq in res['kasiski']['longueurs_probables'][:5]:
            print(f"    longueur {lng:2d} → score {freq}")
        if res['kasiski']['ngrams']:
            print(f"  Trigrammes répétés : "
                  f"{list(res['kasiski']['ngrams'].keys())[:5]}")
    else:
        print(f"  {res['kasiski'].get('message', 'Pas de répétitions.')}")

    print(f"\n  ── IC par longueur de clé (top 5) ──")
    for lng, ic in res['ic_par_longueur'][:5]:
        barre = '█' * int(ic * 100)
        print(f"    k={lng:2d}  IC={ic:.4f}  {barre}  "
              f"{'← ✓ proche IC français' if abs(ic - IC_FRANCAIS) < 0.005 else ''}")

    print(f"\n  ── Résultat ──")
    print(f"  Longueur de clé probable : {res['longueur_probable']}")
    print(f"  Clé probable             : {res['cle_probable']}")
    print(f"  Texte déchiffré          : {res['texte_dechiffre'][:100]}")
    print("=" * 65)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    cle = "CRYPTO"
    msg = ("les sciences mathematiques ont pour objet les relations "
           "entre les grandeurs et les mesures dans le monde physique")
    enc = chiffrer_vigenere(msg, cle)
    print(f"Clé       : {cle}")
    print(f"Clair     : {msg[:60]}...")
    print(f"Chiffré   : {enc[:60]}...\n")

    # Répéter le message pour avoir assez de données pour Kasiski
    enc_long = chiffrer_vigenere(msg * 3, cle)
    afficher_cryptanalyse(enc_long)

"""
classical/otp.py
----------------
One-Time Pad (Vernam) — TP1 Exercice 1.4

1. generate_key / chiffrer_otp / dechiffrer_otp — implémentation correcte
2. Vulnérabilité de réutilisation de clé : C1 ⊕ C2 = M1 ⊕ M2
3. Attaque « crib dragging » — récupération partielle de M1 et M2
4. Analyse des obstacles pratiques de l'OTP
"""

import os
import secrets
from collections import Counter

# Fréquences anglaises/françaises pour le crib dragging (on travaille en ASCII)
LETTRES_COMMUNES = set('etaoinshrdlucmfywgpbvkxjqzEASINTRULODMPCFBGHJKVXYQWZ ')


# ── 1. Implémentation OTP ──────────────────────────────────────────────────────

def generer_cle(longueur: int) -> bytes:
    """Génère une clé aléatoire cryptographiquement sûre de `longueur` octets."""
    return secrets.token_bytes(longueur)


def chiffrer_otp(message: bytes, cle: bytes) -> bytes:
    """
    Chiffrement OTP : C = M ⊕ K
    La clé DOIT être au moins aussi longue que le message.
    """
    if len(cle) < len(message):
        raise ValueError(
            f"La clé ({len(cle)} octets) doit être ≥ au message ({len(message)} octets). "
            "Une clé réutilisée ou trop courte brise la sécurité parfaite."
        )
    return bytes(m ^ k for m, k in zip(message, cle))


def dechiffrer_otp(cryptogramme: bytes, cle: bytes) -> bytes:
    """Déchiffrement OTP : M = C ⊕ K  (identique au chiffrement, XOR est symétrique)."""
    return chiffrer_otp(cryptogramme, cle)   # XOR est sa propre inverse


def chiffrer_texte(texte: str, cle: bytes = None) -> tuple[bytes, bytes]:
    """
    Chiffre un texte UTF-8. Génère la clé automatiquement si non fournie.
    Returns : (cryptogramme, cle)
    """
    data = texte.encode('utf-8')
    if cle is None:
        cle = generer_cle(len(data))
    ct = chiffrer_otp(data, cle)
    return ct, cle


def dechiffrer_texte(cryptogramme: bytes, cle: bytes) -> str:
    """Déchiffre des octets en texte UTF-8."""
    return dechiffrer_otp(cryptogramme, cle).decode('utf-8', errors='replace')


# ── 2. Vulnérabilité de réutilisation de clé ─────────────────────────────────

def demo_reutilisation_cle(message1: str, message2: str) -> dict:
    """
    Démontre la vulnérabilité quand la même clé est réutilisée.

    Si C1 = M1 ⊕ K  et  C2 = M2 ⊕ K
    Alors C1 ⊕ C2 = M1 ⊕ M2  (la clé s'annule !)

    L'attaquant n'a besoin d'aucune clé pour obtenir M1 ⊕ M2.
    """
    m1 = message1.encode('utf-8')
    m2 = message2.encode('utf-8')

    # Aligner sur la longueur commune (normalement les deux doivent être traitées)
    longueur = min(len(m1), len(m2))
    m1, m2 = m1[:longueur], m2[:longueur]

    # Une seule clé pour les deux messages (ERREUR FATALE)
    cle = generer_cle(longueur)
    c1 = chiffrer_otp(m1, cle)
    c2 = chiffrer_otp(m2, cle)

    # L'attaquant calcule C1 ⊕ C2 sans connaître K
    xor_chiffres = bytes(a ^ b for a, b in zip(c1, c2))
    # Ce XOR est exactement M1 ⊕ M2
    xor_clairs   = bytes(a ^ b for a, b in zip(m1, m2))

    # Vérification : xor_chiffres == xor_clairs
    identiques = xor_chiffres == xor_clairs

    return {
        'message1': message1[:longueur],
        'message2': message2[:longueur],
        'longueur': longueur,
        'c1_hex': c1.hex(),
        'c2_hex': c2.hex(),
        'xor_c1_c2_hex': xor_chiffres.hex(),
        'xor_m1_m2_hex': xor_clairs.hex(),
        'xor_egal': identiques,
        'explication': (
            "C1 ⊕ C2 = (M1⊕K) ⊕ (M2⊕K) = M1⊕M2  →  la clé disparaît.\n"
            "L'attaquant obtient M1⊕M2 sans connaître K."
        ),
        # Conserver pour crib dragging
        '_xor': xor_chiffres,
        '_m1_bytes': m1,
        '_m2_bytes': m2,
    }


# ── 3. Attaque Crib Dragging ───────────────────────────────────────────────────

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _est_imprimable(data: bytes, seuil: float = 0.85) -> bool:
    """
    Vérifie si les octets ressemblent à du texte imprimable.
    Heuristique : ≥ `seuil` fraction d'octets dans la plage ASCII imprimable.
    """
    if not data:
        return False
    imprimables = sum(1 for b in data if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D))
    return imprimables / len(data) >= seuil


def _score_texte(data: bytes) -> float:
    """
    Score de 'lisibilité' d'une séquence d'octets.
    Basé sur la proportion de caractères textuels courants.
    """
    if not data:
        return 0.0
    score = sum(
        3 if chr(b) in 'eEaAiIoOuUsSntNT ' else
        2 if chr(b).isalpha() else
        1 if chr(b).isprintable() else
        -1
        for b in data
    )
    return score / len(data)


def crib_dragging(xor_m1_m2: bytes, crib: str,
                  seuil_score: float = 1.5) -> list[dict]:
    """
    Attaque « crib dragging » (glissement de mot deviné).

    Principe :
        Si on suppose que M1 contient le mot `crib` à la position i,
        alors : M2[i:i+|crib|] = XOR[i:i+|crib|] ⊕ crib
        Si le résultat est du texte lisible → hypothèse probablement correcte.

    Args:
        xor_m1_m2   : C1 ⊕ C2 = M1 ⊕ M2 (obtenu sans la clé)
        crib        : mot deviné supposé présent dans M1 ou M2
        seuil_score : score minimum pour garder une hypothèse

    Returns:
        Liste de {'position', 'fragment_m2', 'score', 'crib_dans_m1'} triée par score.
    """
    crib_bytes = crib.encode('utf-8')
    n_crib = len(crib_bytes)
    resultats = []

    for i in range(len(xor_m1_m2) - n_crib + 1):
        segment = xor_m1_m2[i:i + n_crib]
        # Si crib ∈ M1 à position i → M2[i:] = XOR[i:] ⊕ crib
        candidat_m2 = _xor_bytes(segment, crib_bytes)
        score = _score_texte(candidat_m2)
        if score >= seuil_score and _est_imprimable(candidat_m2):
            resultats.append({
                'position': i,
                'fragment_m2': candidat_m2.decode('utf-8', errors='replace'),
                'score': round(score, 3),
                'crib_dans': f"M1[{i}:{i+n_crib}]",
            })
        # Inversement, si crib ∈ M2 à position i → M1[i:] = XOR[i:] ⊕ crib
        candidat_m1 = candidat_m2  # même calcul, rôles de M1/M2 inversés
        if score >= seuil_score and _est_imprimable(candidat_m1):
            # Déjà ajouté ci-dessus (symétrique), on complète le champ
            if resultats and resultats[-1]['position'] == i:
                resultats[-1]['crib_dans'] += f" | M2[{i}:{i+n_crib}]"

    resultats.sort(key=lambda x: x['score'], reverse=True)
    return resultats


def attaque_statistique_xor(xor_m1_m2: bytes) -> dict:
    """
    Analyse statistique de M1 ⊕ M2.

    Observation clé : si un octet de M1 et de M2 sont tous les deux
    des lettres ASCII, leur XOR a ses bits 5 et 6 qui révèlent de l'info.
    En particulier : lettre ⊕ espace = même lettre en casse opposée.
    Cela permet d'identifier les positions contenant des espaces dans M1 ou M2.
    """
    positions_espace = []
    for i, b in enumerate(xor_m1_m2):
        # Si XOR ∈ [0x41..0x5A] ou [0x61..0x7A] → un des deux octets est un espace
        if 0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A:
            positions_espace.append({
                'position': i,
                'xor': b,
                'char_xor': chr(b),
                'interpretation': (
                    f"M1[{i}]=' ', M2[{i}]='{chr(b)}' "
                    f"  OU  M1[{i}]='{chr(b)}', M2[{i}]=' '"
                )
            })
    return {
        'longueur_xor': len(xor_m1_m2),
        'positions_espaces_probables': positions_espace[:20],
        'nb_positions': len(positions_espace),
        'explication': (
            "lettre ⊕ espace = même lettre en casse opposée.\n"
            "Si XOR[i] est une lettre → l'un des messages a un espace en position i."
        )
    }


# ── Démonstration complète ────────────────────────────────────────────────────

def demo_complete() -> None:
    print("=" * 65)
    print("  ONE-TIME PAD — DÉMONSTRATION COMPLÈTE")
    print("=" * 65)

    # 1. Usage correct
    print("\n  ── 1. Utilisation correcte ──")
    msg = "Message ultra secret"
    ct, cle = chiffrer_texte(msg)
    dec = dechiffrer_texte(ct, cle)
    print(f"  Message   : {msg}")
    print(f"  Clé (hex) : {cle.hex()}")
    print(f"  Chiffré   : {ct.hex()}")
    print(f"  Déchiffré : {dec}")
    print(f"  Correct   : {dec == msg} ✓")

    # 2. Réutilisation de clé
    print("\n  ── 2. Vulnérabilité — réutilisation de clé ──")
    m1 = "Le mot de passe est ALPHA"
    m2 = "Rendez-vous a minuit ici"
    res = demo_reutilisation_cle(m1, m2)
    print(f"  M1         : {res['message1']}")
    print(f"  M2         : {res['message2']}")
    print(f"  C1 ⊕ C2    : {res['xor_c1_c2_hex'][:48]}...")
    print(f"  M1 ⊕ M2    : {res['xor_m1_m2_hex'][:48]}...")
    print(f"  Égaux      : {res['xor_egal']} ← la clé a disparu !")
    print(f"\n  {res['explication']}")

    # 3. Crib dragging
    print("\n  ── 3. Attaque crib dragging ──")
    xor = res['_xor']
    for crib in ["mot de passe", "Rendez-vous", "minuit", "Le "]:
        hits = crib_dragging(xor, crib, seuil_score=1.2)
        if hits:
            print(f"\n  Crib '{crib}' → {len(hits)} hit(s) :")
            for h in hits[:3]:
                print(f"    pos={h['position']:3d}  fragment='{h['fragment_m2']}'  "
                      f"score={h['score']}  ({h['crib_dans']})")

    # 4. Analyse des espaces
    print("\n  ── 4. Analyse statistique (espaces) ──")
    stats = attaque_statistique_xor(xor)
    print(f"  {stats['nb_positions']} positions avec espaces probables détectées.")
    for p in stats['positions_espaces_probables'][:5]:
        print(f"    {p['interpretation']}")

    print("\n" + "=" * 65)
    print("  OBSTACLES PRATIQUES DE L'OTP :")
    print("  1. Distribution sécurisée de la clé (aussi longue que le message)")
    print("  2. Génération vraiment aléatoire (pas pseudo-aléatoire)")
    print("  3. Destruction garantie de la clé après usage")
    print("  4. Synchronisation entre émetteur et récepteur")
    print("  5. Une seule utilisation par clé — aucune réutilisation possible")
    print("=" * 65)


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    demo_complete()

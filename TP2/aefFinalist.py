"""
modern/aes_finalists.py
-----------------------
TP2 Exercice 2.4 — Les 5 Finalistes du Concours AES (NIST 1997-2000)

Concours NIST : 15 candidats → 5 finalistes → Rijndael retenu (octobre 2000)

┌─────────────────────────────────────────────────────────────────────────┐
│  Finaliste  │ Structure │ Bloc  │ Clé            │ Tours │ Originalité  │
├─────────────────────────────────────────────────────────────────────────┤
│  Rijndael   │ SPN       │ 128b  │ 128/192/256b   │ 10-14 │ GF(2⁸), MixColumns, ShiftRows │
│  Twofish    │ Feistel   │ 128b  │ 128/192/256b   │ 16    │ MDS, PHT, S-boxes dépendantes de la clé │
│  Serpent    │ SPN       │ 128b  │ 128/192/256b   │ 32    │ 32 tours (le plus sûr), 8 S-boxes bitslicées │
│  RC6        │ ARX       │ 128b  │ 128-2040b      │ 20    │ Multiplication entière, registres rotatifs │
│  MARS       │ Hétérogène│ 128b  │ 128-1248b      │ 32    │ 3 phases : ajout, mélange cryptographique, soustraction │
└─────────────────────────────────────────────────────────────────────────┘

Réponse à la question 2.4.4 :
  Serpent a obtenu la meilleure note de sécurité (32 tours, marges énormes)
  mais Rijndael a été retenu car :
  ① Performance nettement supérieure (sur hardware ET software)
  ② Implémentation simple et élégante (faible empreinte mémoire)
  ③ Flexibilité : tailles de blocs et clés multiples
  ④ Bonne résistance aux attaques différentielles et linéaires
  Le NIST a jugé que Rijndael offrait le meilleur compromis sécurité/performance.
"""

import os
import time
import struct


# ═══════════════════════════════════════════════════════════════════════════════
#  1. RIJNDAEL (AES) — wrapper pycryptodome
# ═══════════════════════════════════════════════════════════════════════════════

class Rijndael:
    """
    Rijndael (AES) — Structure : SPN (Substitution-Permutation Network)
    Bloc 128 bits · Clé 128/192/256 bits · 10/12/14 tours.
    Opérations : SubBytes (S-box GF(2⁸)), ShiftRows, MixColumns (GF(2⁸)), AddRoundKey.
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Clé Rijndael : 16/24/32 octets")
        self.key = key

    def encrypt_block(self, block: bytes) -> bytes:
        from Crypto.Cipher import AES
        assert len(block) == 16
        return AES.new(self.key, AES.MODE_ECB).encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        from Crypto.Cipher import AES
        assert len(block) == 16
        return AES.new(self.key, AES.MODE_ECB).decrypt(block)

    def encrypt(self, plaintext: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        return AES.new(self.key, AES.MODE_ECB).encrypt(pad(plaintext, 16))

    def decrypt(self, ciphertext: bytes) -> bytes:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import unpad
        return unpad(AES.new(self.key, AES.MODE_ECB).decrypt(ciphertext), 16)

    @staticmethod
    def description() -> str:
        return (
            "Rijndael (AES) : Réseau de substitution-permutation (SPN). "
            "Bloc 128 bits, clé 128/192/256 bits, 10-14 tours selon la clé. "
            "Opérations algébriques dans GF(2⁸) : SubBytes, ShiftRows, "
            "MixColumns, AddRoundKey. Élégant, rapide sur hardware/software."
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  2. RC6 — implémentation pure Python
# ═══════════════════════════════════════════════════════════════════════════════

class RC6:
    """
    RC6 — Structure : ARX (Add-Rotate-XOR) sur 4 mots de 32 bits.
    Bloc 128 bits · Clé variable (typiquement 128/192/256 bits) · 20 tours.
    Originalité : première utilisation de la multiplication entière dans
    une primitive de bloc (pour piloter les rotations de façon dépendante des données).
    Inventé par RSA Security (Ron Rivest et al.).
    """

    # Constantes magiques (basées sur e et φ, converties en base 2^32)
    P32 = 0xB7E15163
    Q32 = 0x9E3779B9
    MOD = 2 ** 32
    LGW = 5   # log2(32)

    def __init__(self, key: bytes, rounds: int = 20):
        if not key:
            raise ValueError("Clé RC6 vide")
        self.r = rounds
        self._S = self._expand_key(key)

    # ── Rotations ──────────────────────────────────────────────────────────

    @staticmethod
    def _rotl(val: int, shift: int) -> int:
        shift &= 31
        return ((val << shift) | (val >> (32 - shift))) & 0xFFFFFFFF

    @staticmethod
    def _rotr(val: int, shift: int) -> int:
        shift &= 31
        return ((val >> shift) | (val << (32 - shift))) & 0xFFFFFFFF

    # ── Expansion de clé ───────────────────────────────────────────────────

    def _expand_key(self, key: bytes) -> list[int]:
        """Génère le tableau S de 2r+4 sous-clés de 32 bits."""
        u = 4   # octets par mot (w/8 = 32/8)
        b = len(key)
        c = max(1, (b + u - 1) // u)

        L = [0] * c
        for i in range(b - 1, -1, -1):
            L[i // u] = ((L[i // u] << 8) | key[i]) & 0xFFFFFFFF

        t = 2 * (self.r + 2)
        S = [0] * t
        S[0] = self.P32
        for i in range(1, t):
            S[i] = (S[i - 1] + self.Q32) & 0xFFFFFFFF

        A = B = idx = j = 0
        for _ in range(3 * max(t, c)):
            A = S[idx] = self._rotl((S[idx] + A + B) & 0xFFFFFFFF, 3)
            B = L[j]   = self._rotl((L[j] + A + B) & 0xFFFFFFFF, (A + B) & 31)
            idx = (idx + 1) % t
            j   = (j + 1) % c

        return S

    # ── Chiffrement d'un bloc de 16 octets ────────────────────────────────

    def encrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        A, B, C, D = struct.unpack('<4I', block)

        B = (B + self._S[0]) & 0xFFFFFFFF
        D = (D + self._S[1]) & 0xFFFFFFFF

        for i in range(1, self.r + 1):
            t = self._rotl((B * (2 * B + 1)) & 0xFFFFFFFF, self.LGW)
            u = self._rotl((D * (2 * D + 1)) & 0xFFFFFFFF, self.LGW)
            A = (self._rotl(A ^ t, u & 31) + self._S[2 * i])     & 0xFFFFFFFF
            C = (self._rotl(C ^ u, t & 31) + self._S[2 * i + 1]) & 0xFFFFFFFF
            A, B, C, D = B, C, D, A

        A = (A + self._S[2 * self.r + 2]) & 0xFFFFFFFF
        C = (C + self._S[2 * self.r + 3]) & 0xFFFFFFFF
        return struct.pack('<4I', A, B, C, D)

    def decrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        A, B, C, D = struct.unpack('<4I', block)

        C = (C - self._S[2 * self.r + 3]) & 0xFFFFFFFF
        A = (A - self._S[2 * self.r + 2]) & 0xFFFFFFFF

        for i in range(self.r, 0, -1):
            A, B, C, D = D, A, B, C
            u = self._rotl((D * (2 * D + 1)) & 0xFFFFFFFF, self.LGW)
            t = self._rotl((B * (2 * B + 1)) & 0xFFFFFFFF, self.LGW)
            C = self._rotr((C - self._S[2 * i + 1]) & 0xFFFFFFFF, t & 31) ^ u
            A = self._rotr((A - self._S[2 * i])     & 0xFFFFFFFF, u & 31) ^ t

        D = (D - self._S[1]) & 0xFFFFFFFF
        B = (B - self._S[0]) & 0xFFFFFFFF
        return struct.pack('<4I', A, B, C, D)

    def encrypt(self, plaintext: bytes) -> bytes:
        return _ecb_encrypt(self, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return _ecb_decrypt(self, ciphertext)

    @staticmethod
    def description() -> str:
        return (
            "RC6 : Structure ARX (Add-Rotate-XOR) sur 4 mots de 32 bits. "
            "Bloc 128 bits, clé variable, 20 tours. "
            "Premier algorithme à utiliser la multiplication entière pour "
            "des rotations data-dépendantes — très efficace sur processeurs 32 bits."
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  3. SERPENT — implémentation pure Python
# ═══════════════════════════════════════════════════════════════════════════════

class Serpent:
    """
    Serpent — Structure : SPN avec 32 tours (le plus conservateur des 5).
    Bloc 128 bits · Clé 128/192/256 bits · 32 tours · 8 S-boxes × 4 bits.
    Conçu pour la sécurité maximale : analyse différentielle/linéaire impossible
    avec moins de 28 tours. A obtenu la meilleure note de sécurité au concours NIST.
    """

    # 8 S-boxes de Serpent (sur 4 bits, représentées comme substitutions de [0..15])
    _SBOX = [
        [3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12],  # S0
        [15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4],  # S1
        [8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2],  # S2
        [0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14],  # S3
        [1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13],  # S4
        [15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1],  # S5
        [7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0],  # S6
        [1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6],  # S7
    ]

    # S-boxes inverses
    _SBOX_INV = [None] * 8

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Clé Serpent : 16/24/32 octets")
        # Pré-calculer les S-boxes inverses
        for i in range(8):
            inv = [0] * 16
            for j, v in enumerate(self._SBOX[i]):
                inv[v] = j
            self._SBOX_INV[i] = inv
        self._subkeys = self._key_schedule(key)

    # ── Utilitaires bits ───────────────────────────────────────────────────

    @staticmethod
    def _rotl32(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _rotr32(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _apply_sbox(self, sbox_idx: int, block_words: list[int]) -> list[int]:
        """Applique la S-box sbox_idx sur les 128 bits représentés en 4 mots de 32 bits."""
        result = [0, 0, 0, 0]
        sbox = self._SBOX[sbox_idx % 8]
        for bit in range(32):
            nibble = (
                ((block_words[0] >> bit) & 1) |
                (((block_words[1] >> bit) & 1) << 1) |
                (((block_words[2] >> bit) & 1) << 2) |
                (((block_words[3] >> bit) & 1) << 3)
            )
            mapped = sbox[nibble]
            for w in range(4):
                if (mapped >> w) & 1:
                    result[w] |= (1 << bit)
        return result

    def _apply_sbox_inv(self, sbox_idx: int, block_words: list[int]) -> list[int]:
        result = [0, 0, 0, 0]
        sbox = self._SBOX_INV[sbox_idx % 8]
        for bit in range(32):
            nibble = (
                ((block_words[0] >> bit) & 1) |
                (((block_words[1] >> bit) & 1) << 1) |
                (((block_words[2] >> bit) & 1) << 2) |
                (((block_words[3] >> bit) & 1) << 3)
            )
            mapped = sbox[nibble]
            for w in range(4):
                if (mapped >> w) & 1:
                    result[w] |= (1 << bit)
        return result

    def _linear_transform(self, w: list[int]) -> list[int]:
        """Transformation linéaire de Serpent (mélange des mots)."""
        x0, x1, x2, x3 = w
        x0 = self._rotl32(x0, 13)
        x2 = self._rotl32(x2, 3)
        x1 ^= x0 ^ x2
        x3 ^= x2 ^ ((x0 << 3) & 0xFFFFFFFF)
        x1 = self._rotl32(x1, 1)
        x3 = self._rotl32(x3, 7)
        x0 ^= x1 ^ x3
        x2 ^= x3 ^ ((x1 << 7) & 0xFFFFFFFF)
        x0 = self._rotl32(x0, 5)
        x2 = self._rotl32(x2, 22)
        return [x0, x1, x2, x3]

    def _linear_transform_inv(self, w: list[int]) -> list[int]:
        x0, x1, x2, x3 = w
        x2 = self._rotr32(x2, 22)
        x0 = self._rotr32(x0, 5)
        x2 ^= x3 ^ ((x1 << 7) & 0xFFFFFFFF)
        x0 ^= x1 ^ x3
        x3 = self._rotr32(x3, 7)
        x1 = self._rotr32(x1, 1)
        x3 ^= x2 ^ ((x0 << 3) & 0xFFFFFFFF)
        x1 ^= x0 ^ x2
        x2 = self._rotr32(x2, 3)
        x0 = self._rotr32(x0, 13)
        return [x0, x1, x2, x3]

    # ── Calendrier de clé ──────────────────────────────────────────────────

    def _key_schedule(self, key: bytes) -> list[list[int]]:
        """Génère 33 sous-clés de 128 bits (132 mots de 32 bits)."""
        GOLDEN = 0x9E3779B9

        # Padder la clé à 256 bits si nécessaire
        k = list(key) + ([0] * (32 - len(key)))
        if len(key) < 32:
            k[len(key)] = 1

        # Charger en 8 mots de 32 bits
        w = list(struct.unpack('<8I', bytes(k)))

        # Étendre à 132 mots
        for i in range(8, 140):
            val = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ GOLDEN ^ (i - 8)
            w.append(self._rotl32(val, 11))

        # Appliquer les S-boxes pour former les 33 sous-clés de 128 bits
        subkeys = []
        for i in range(33):
            sb_idx = (32 - i) % 8
            blk = [w[4*i], w[4*i+1], w[4*i+2], w[4*i+3]]
            subkeys.append(self._apply_sbox(sb_idx, blk))

        return subkeys

    # ── Chiffrement ────────────────────────────────────────────────────────

    def encrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        w = list(struct.unpack('<4I', block))

        for r in range(32):
            # AddRoundKey
            w = [w[i] ^ self._subkeys[r][i] for i in range(4)]
            # S-box
            w = self._apply_sbox(r % 8, w)
            # Linear transform (sauf dernier tour)
            if r < 31:
                w = self._linear_transform(w)

        # Dernier AddRoundKey
        w = [w[i] ^ self._subkeys[32][i] for i in range(4)]
        return struct.pack('<4I', *w)

    def decrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        w = list(struct.unpack('<4I', block))

        w = [w[i] ^ self._subkeys[32][i] for i in range(4)]

        for r in range(31, -1, -1):
            if r < 31:
                w = self._linear_transform_inv(w)
            w = self._apply_sbox_inv(r % 8, w)
            w = [w[i] ^ self._subkeys[r][i] for i in range(4)]

        return struct.pack('<4I', *w)

    def encrypt(self, plaintext: bytes) -> bytes:
        return _ecb_encrypt(self, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return _ecb_decrypt(self, ciphertext)

    @staticmethod
    def description() -> str:
        return (
            "Serpent : SPN ultra-conservateur avec 32 tours (vs 10 pour AES). "
            "Bloc 128 bits, clé 128/192/256 bits. "
            "8 S-boxes de 4 bits appliquées en rotation à chaque tour. "
            "Meilleure sécurité prouvée des 5 finalistes, "
            "mais 3× plus lent que Rijndael — perdant sur la performance."
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  4. TWOFISH — implémentation pure Python
# ═══════════════════════════════════════════════════════════════════════════════

class Twofish:
    """
    Twofish — Structure : réseau de Feistel à 16 tours.
    Bloc 128 bits · Clé 128/192/256 bits · 16 tours.
    Originalité : S-boxes dépendantes de la clé, matrice MDS, PHT (Pseudo-Hadamard Transform).
    Conçu par Bruce Schneier et al. (Counterpane Systems).
    """

    # Tables fixes q0, q1 (permutations sur 8 bits)
    _Q0 = [
        0xa9,0x67,0xb3,0xe8,0x04,0xfd,0xa3,0x76,0x9a,0x92,0x80,0x78,0xe4,0xdd,0xd1,0x38,
        0x0d,0xc6,0x35,0x98,0x18,0xf7,0xec,0x6c,0x43,0x75,0x37,0x26,0xfa,0x13,0x94,0x48,
        0xf2,0xd0,0x8b,0x30,0x84,0x54,0xdf,0x23,0x19,0x5b,0x3d,0x59,0xf3,0xae,0xa2,0x82,
        0x63,0x01,0x83,0x2e,0xd9,0x51,0x9b,0x7c,0xa6,0xeb,0xa5,0xbe,0x16,0x0c,0xe3,0x61,
        0xc0,0x8c,0x3a,0xf5,0x73,0x2c,0x25,0x0b,0xbb,0x4e,0x89,0x6b,0x53,0x6a,0xb4,0xf1,
        0xe1,0xe6,0xbd,0x45,0xe2,0xf4,0xb6,0x66,0xcc,0x95,0x03,0x56,0xd4,0x1c,0x1e,0xd7,
        0xfb,0xc3,0x8e,0xb5,0xe9,0xcf,0xbf,0xba,0xea,0x77,0x39,0xaf,0x33,0xc9,0x62,0x71,
        0x81,0x79,0x09,0xad,0x24,0xcd,0xf9,0xd8,0xe5,0xc5,0xb9,0x4d,0x44,0x08,0x86,0xe7,
        0xa1,0x1d,0xaa,0xed,0x06,0x70,0xb2,0xd2,0x41,0x7b,0xa0,0x11,0x31,0xc2,0x27,0x90,
        0x20,0xf6,0x60,0xff,0x96,0x5c,0xb1,0xab,0x9e,0x9c,0x52,0x1b,0x5f,0x93,0x0a,0xef,
        0x91,0x85,0x49,0xee,0x2d,0x4f,0x8f,0x3b,0x47,0x87,0x6d,0x46,0xd6,0x3e,0x69,0x64,
        0x2a,0xce,0xcb,0x2f,0xfc,0x97,0x05,0x7a,0xac,0x7f,0xd5,0x1a,0x4b,0x0e,0xa7,0x5a,
        0x28,0x14,0x3f,0x29,0x88,0x3c,0x4c,0x02,0xb8,0xda,0xb0,0x17,0x55,0x1f,0x8a,0x7d,
        0x57,0xc7,0x8d,0x74,0xb7,0xc4,0x9f,0x72,0x7e,0x15,0x22,0x12,0x58,0x07,0x99,0x34,
        0x6e,0x50,0xde,0x68,0x65,0xbc,0xdb,0xf8,0xc8,0xa8,0x2b,0x40,0xdc,0xfe,0x32,0xa4,
        0xca,0x10,0x21,0xf0,0xd3,0x5d,0x0f,0x00,0x6f,0x9d,0x36,0x42,0x4a,0x5e,0xc1,0xe0,
    ]
    _Q1 = [
        0x75,0xf3,0xc6,0xf4,0xdb,0x7b,0xfb,0xc8,0x4a,0xd3,0xe6,0x6b,0x45,0x7d,0xe8,0x4b,
        0xd6,0x32,0xd8,0xfd,0x37,0x71,0xf1,0xe1,0x30,0x0f,0xf8,0x1b,0x87,0xfa,0x06,0x3f,
        0x5e,0xba,0xae,0x5b,0x8a,0x00,0xbc,0x9d,0x6d,0xc1,0xb1,0x0e,0x80,0x5d,0xd2,0xd5,
        0xa0,0x84,0x07,0x14,0xb5,0x90,0x2c,0xa3,0xb2,0x73,0x4c,0x54,0x92,0x74,0x36,0x51,
        0x38,0xb0,0xbd,0x5a,0xfc,0x60,0x62,0x96,0x6c,0x42,0xf7,0x10,0x7c,0x28,0x27,0x8c,
        0x13,0x95,0x9c,0xc7,0x24,0x46,0x3b,0x70,0xca,0xe3,0x85,0xcb,0x11,0xd0,0x93,0xb8,
        0xa6,0x83,0x20,0xff,0x9f,0x77,0xc3,0xcc,0x03,0x6f,0x08,0xbf,0x40,0xe7,0x2b,0xe2,
        0x79,0x0c,0xaa,0x82,0x41,0x3a,0xea,0xb9,0xe4,0x9a,0xa4,0x97,0x7e,0xda,0x7a,0x17,
        0x66,0x94,0xa1,0x1d,0x3d,0xf0,0xde,0xb3,0x0b,0x72,0xa7,0x1c,0xef,0xd1,0x53,0x3e,
        0x8f,0x33,0x26,0x5f,0xec,0x76,0x2a,0x49,0x81,0x88,0xee,0x21,0xc4,0x1a,0xeb,0xd9,
        0xc5,0x39,0x99,0xcd,0xad,0x31,0x8b,0x01,0x18,0x23,0xdd,0x1f,0x4e,0x2d,0xf9,0x48,
        0x4f,0xf2,0x65,0x8e,0x78,0x5c,0x58,0x19,0x8d,0xe5,0x98,0x57,0x67,0x7f,0x05,0x64,
        0xaf,0x63,0xb6,0xfe,0xf5,0xb7,0x3c,0xa5,0xce,0xe9,0x68,0x44,0xe0,0x4d,0x43,0x69,
        0x29,0x2e,0xac,0x15,0x59,0xa8,0x0a,0x9e,0x6e,0x47,0xdf,0x34,0x35,0x6a,0xcf,0xdc,
        0x22,0xc9,0xc0,0x9b,0x89,0xd4,0xed,0xab,0x12,0xa2,0x0d,0x52,0xbb,0x02,0x2f,0xa9,
        0xd7,0x61,0x1e,0xb4,0x50,0x04,0xf6,0xc2,0x16,0x25,0x86,0x56,0x55,0x09,0xbe,0x91,
    ]

    # Polynôme irreduit MDS : x^8 + x^6 + x^3 + x^2 + 1
    _GF_MOD = 0x169

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Clé Twofish : 16/24/32 octets")
        self._key_len = len(key)
        self._subkeys, self._sboxes = self._key_schedule(key)

    # ── GF(2^8) multiplication ─────────────────────────────────────────────

    def _gf_mult(self, a: int, b: int) -> int:
        """Multiplication dans GF(2^8) avec polynôme générateur 0x169."""
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= self._GF_MOD
            a &= 0xFF
            b >>= 1
        return result

    def _mds_mult(self, val: int) -> int:
        """MDS matrix-vector product (colonne MDS de Twofish)."""
        v0 = val & 0xFF
        v1 = (val >> 8) & 0xFF
        v2 = (val >> 16) & 0xFF
        v3 = (val >> 24) & 0xFF
        # MDS matrix (sur GF(2^8)) — rangées de la matrice MDS de Twofish
        r0 = self._gf_mult(v0,0x01) ^ self._gf_mult(v1,0xEF) ^ self._gf_mult(v2,0x5B) ^ self._gf_mult(v3,0x5B)
        r1 = self._gf_mult(v0,0x5B) ^ self._gf_mult(v1,0xEF) ^ self._gf_mult(v2,0xEF) ^ self._gf_mult(v3,0x01)
        r2 = self._gf_mult(v0,0xEF) ^ self._gf_mult(v1,0x5B) ^ self._gf_mult(v2,0x01) ^ self._gf_mult(v3,0xEF)
        r3 = self._gf_mult(v0,0xEF) ^ self._gf_mult(v1,0x01) ^ self._gf_mult(v2,0xEF) ^ self._gf_mult(v3,0x5B)
        return r0 | (r1 << 8) | (r2 << 16) | (r3 << 24)

    def _q(self, x: int, table: list[int]) -> int:
        return table[x & 0xFF]

    # ── g() function ────────────────────────────────────────────────────────

    def _g(self, x: int) -> int:
        """Fonction g : substitution + MDS."""
        b0 = (x) & 0xFF
        b1 = (x >> 8)  & 0xFF
        b2 = (x >> 16) & 0xFF
        b3 = (x >> 24) & 0xFF
        y0 = self._sboxes[0][b0]
        y1 = self._sboxes[1][b1]
        y2 = self._sboxes[2][b2]
        y3 = self._sboxes[3][b3]
        return self._mds_mult(y0 | (y1 << 8) | (y2 << 16) | (y3 << 24))

    # ── PHT ────────────────────────────────────────────────────────────────

    @staticmethod
    def _pht(a: int, b: int) -> tuple[int, int]:
        """Pseudo-Hadamard Transform."""
        return (a + b) & 0xFFFFFFFF, (a + 2 * b) & 0xFFFFFFFF

    @staticmethod
    def _rotl(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _rotr(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    # ── Calendrier de clé ──────────────────────────────────────────────────

    def _key_schedule(self, key: bytes):
        k_len = len(key)
        Nk = k_len // 8  # 2, 3 ou 4

        # Diviser la clé en mots de 32 bits
        m_words = list(struct.unpack(f'<{k_len//4}I', key))

        # Me (indices pairs) et Mo (indices impairs)
        Me = [m_words[2*i]     for i in range(Nk)]
        Mo = [m_words[2*i + 1] for i in range(Nk)]

        # Vecteurs S (via RS matrix)
        # S_i = RS × m_i (RS = Reed-Solomon matrix sur GF(2^8) avec poly 0x14D)
        def rs_mult(a, b):
            res = 0
            while b:
                if b & 1: res ^= a
                a = (a << 1) ^ (0x14D if a & 0x80 else 0)
                a &= 0xFF
                b >>= 1
            return res

        RS = [
            [0x01,0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E],
            [0xA4,0x56,0x82,0xF3,0x1E,0xC6,0x68,0xE5],
            [0x02,0xA1,0xFC,0xC1,0x47,0xAE,0x3D,0x19],
            [0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E,0x03],
        ]

        S = []
        for i in range(Nk):
            m8 = [(m_words[2*i] >> (8*j)) & 0xFF for j in range(4)]
            m8 += [(m_words[2*i+1] >> (8*j)) & 0xFF for j in range(4)]
            s_word = 0
            for row in range(4):
                byte = 0
                for col in range(8):
                    byte ^= rs_mult(RS[row][col], m8[col])
                s_word |= (byte << (8 * row))
            S.append(s_word)
        S = list(reversed(S))

        # S-boxes clé-dépendantes
        def h_func(x, ls):
            y = [(x >> (8*i)) & 0xFF for i in range(4)]
            if Nk >= 4:
                y = [self._q(y[i], self._Q1 if i in (0,3) else self._Q0) ^ ((ls[3] >> (8*i)) & 0xFF) for i in range(4)]
            if Nk >= 3:
                y = [self._q(y[i], self._Q1 if i in (0,1) else self._Q0) ^ ((ls[2] >> (8*i)) & 0xFF) for i in range(4)]
            y = [self._q(y[i], self._Q0 if i in (0,3) else self._Q1) ^ ((ls[1] >> (8*i)) & 0xFF) for i in range(4)]
            y = [self._q(y[i], self._Q0 if i in (0,2) else self._Q1) ^ ((ls[0] >> (8*i)) & 0xFF) for i in range(4)]
            return y

        sboxes = [
            [self._mds_mult(b | 0) for b in range(256)],
            [self._mds_mult(b << 8) for b in range(256)],
            [self._mds_mult(b << 16) for b in range(256)],
            [self._mds_mult(b << 24) for b in range(256)],
        ]

        # Sous-clés K_i = PHT(h(ρ^i·Me), ROL(h(ρ^i·Mo), 8))
        rho = 0x01010101
        subkeys = []
        for i in range(20):
            A = self._mds_mult(sum(
                h_func(((rho * 2*i) * Me[j] & 0xFFFFFFFF) if j == 0 else Me[j], Me)[j] << (8*j)
                for j in range(4)
            ) & 0xFFFFFFFF) if False else 0
            # Simplified: use h() directly
            xi = (2 * i * rho) & 0xFFFFFFFF
            yi = (2 * i * rho + rho) & 0xFFFFFFFF
            Ai = sum(h_func(xi, Me)[j] << (8*j) for j in range(4)) & 0xFFFFFFFF
            Bi = sum(h_func(yi, Mo)[j] << (8*j) for j in range(4)) & 0xFFFFFFFF
            Bi = self._rotl(Bi, 8)
            K2i, K2i1 = self._pht(Ai, Bi)
            subkeys.append(K2i)
            subkeys.append(self._rotl(K2i1, 9))

        # Build actual key-dependent sboxes from S
        s_flat = S
        def make_sbox(byte_pos):
            result = []
            for x in range(256):
                ys = h_func(x | (x << 8) | (x << 16) | (x << 24), s_flat)
                result.append(ys[byte_pos])
            return result

        kd_sboxes = [make_sbox(i) for i in range(4)]
        return subkeys, kd_sboxes

    def _g_sbox(self, x: int) -> int:
        b = [(x >> (8*i)) & 0xFF for i in range(4)]
        y = [self._sboxes[i][b[i]] for i in range(4)]
        return self._mds_mult(y[0] | (y[1]<<8) | (y[2]<<16) | (y[3]<<24))

    # ── Chiffrement ────────────────────────────────────────────────────────

    def encrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        words = list(struct.unpack('<4I', block))

        # Input whitening
        R = [words[i] ^ self._subkeys[i] for i in range(4)]

        for r in range(16):
            T0 = self._g_sbox(R[0])
            T1 = self._g_sbox(self._rotl(R[1], 8))
            T0_pht, T1_pht = self._pht(T0, T1)
            F0 = (T0_pht + self._subkeys[2*r + 8]) & 0xFFFFFFFF
            F1 = (T1_pht + self._subkeys[2*r + 9]) & 0xFFFFFFFF
            new_R2 = self._rotr(R[2] ^ F0, 1)
            new_R3 = self._rotl(R[3], 1) ^ F1
            R = [R[2], R[3], new_R2, new_R3] if r < 15 else [new_R2, new_R3, R[0] ^ F0, R[1] ^ F1]
            if r < 15:
                R = [R[2], R[3], R[0], R[1]]
                R[2] = self._rotr(R[2] ^ F0, 1)
                R[3] = self._rotl(R[3], 1) ^ F1
                R = [R[2], R[3], R[0], R[1]]

        # Output whitening (simplified)
        out = [(R[i] ^ self._subkeys[i + 4]) & 0xFFFFFFFF for i in range(4)]
        return struct.pack('<4I', *out)

    def decrypt_block(self, block: bytes) -> bytes:
        # For this educational implementation, use the inverse
        assert len(block) == 16
        # Simplified: run encryption path in reverse
        words = list(struct.unpack('<4I', block))
        R = [words[i] ^ self._subkeys[i + 4] for i in range(4)]

        for r in range(15, -1, -1):
            T0 = self._g_sbox(R[0])
            T1 = self._g_sbox(self._rotl(R[1], 8))
            T0_pht, T1_pht = self._pht(T0, T1)
            F0 = (T0_pht + self._subkeys[2*r + 8]) & 0xFFFFFFFF
            F1 = (T1_pht + self._subkeys[2*r + 9]) & 0xFFFFFFFF
            old_R2 = self._rotl(R[2], 1) ^ F0
            old_R3 = self._rotr(R[3] ^ F1, 1)
            R = [R[2], R[3], old_R2, old_R3]
            R = [R[2], R[3], R[0], R[1]]

        out = [(R[i] ^ self._subkeys[i]) & 0xFFFFFFFF for i in range(4)]
        return struct.pack('<4I', *out)

    def encrypt(self, plaintext: bytes) -> bytes:
        return _ecb_encrypt(self, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return _ecb_decrypt(self, ciphertext)

    @staticmethod
    def description() -> str:
        return (
            "Twofish : Réseau de Feistel à 16 tours. "
            "Bloc 128 bits, clé 128/192/256 bits. "
            "S-boxes clé-dépendantes (générées pendant le key schedule), "
            "MDS (Maximum Distance Separable) matrix, PHT (Pseudo-Hadamard Transform). "
            "Très sécurisé, légèrement plus lent que Rijndael."
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  5. MARS — implémentation pure Python (IBM Research)
# ═══════════════════════════════════════════════════════════════════════════════

class MARS:
    """
    MARS — Structure hétérogène : 3 phases distinctes (IBM Research, 1998).
    Bloc 128 bits · Clé 128-1248 bits · 32 demi-tours.
    Structure unique : mélange de 3 phases : forward mixing, cryptographic core,
    backward mixing. S-box fixe, keyed addition, rotation data-dépendante.
    """

    # MARS S-box (256 entrées × 32 bits)
    _SBOX = [
        0x09d0c479,0x28c8ffe0,0x84aa6c39,0x9dad7287,0x7dff9be3,0xd4268361,0xc96da1d4,0x7974cc93,
        0x85d0582e,0x2a4b5705,0x1ca16a62,0xc3bd279d,0x0f1f25e5,0x5160372f,0xc695c1fb,0x4d7ff1e4,
        0xae5f6bf4,0x0d72ee46,0xff23de8a,0xb1cf8e83,0xf14902e2,0x3e981e42,0x8bf53eb6,0x7f4bf8ac,
        0x83631f83,0x25970205,0x76afe784,0x3a7931d4,0x4f846450,0x5c64c3f6,0x210a5f18,0xc6986a26,
        0x28f4e826,0x3a60a81c,0xd340a664,0x7ea820c4,0x526687c5,0x7eddd12b,0x32a11d1d,0x9c9ef086,
        0x80f6e831,0xab6f04ad,0x56fb9b53,0x8b2e095c,0xb68556ae,0xd2250b0d,0x294a7721,0xe21fb253,
        0xae136749,0xe82aae86,0x93365104,0x99404a66,0x78a784dc,0xb69ba84b,0x04046793,0x23db5c1e,
        0x46cae1d6,0x2fe28134,0x5a223942,0x1863cd5b,0xc190c6e3,0x07dfb846,0x6eb88816,0x2d0dcc4a,
        0xa4ccae59,0x3798670d,0xcbfa9493,0x4f481d45,0xeafc8ca8,0xdb1129d6,0xb0449e20,0x0f5407fb,
        0x6167d9a8,0xd1f45763,0x4daa96c3,0x3bec5958,0xababa014,0xb6ccd201,0x38d6279f,0x02682215,
        0x8f376cd5,0x092c237e,0xbfc56593,0x32d38c3a,0x9b9d8dae,0xa2208d7e,0x5a0c7d83,0x7f791c0b,
        0x045585a3,0x007bf9b6,0xf3d44cb0,0x28f9a89b,0xf6b0a706,0x8aff5d3b,0x96efaf55,0x2e15327b,
        0xa0e75f0e,0x4c9e61ed,0x99ae742e,0x2b277ec9,0x5d33b9e0,0xed56e204,0x7d9e2c1d,0x9a31aad7,
        0x5dac5beb,0x5ee02a80,0x4c3e3010,0xfd02b8e0,0x38a9f8e7,0xdb1fad4b,0xb14d0f93,0x72a1614e,
        0x8a7b97c9,0x5a49de2a,0x5ad3d3e1,0xb3826d32,0xcfe2b01b,0xd7d9b7fc,0x7cf0a200,0xd0e93a33,
        0x9dc6bf6c,0xca79b959,0x27d83295,0x8f0dae47,0x04f8f5e7,0x9cd2cbb1,0xa62571b4,0xa82b22b2,
        0x6f3e7f00,0x6df2c3e9,0xd6ad0547,0xd1a8d388,0x90f607cf,0xe1a42c60,0x8f30fa8a,0x7be02d48,
        0x97a73503,0x843fd1e5,0x2fafedb3,0x5a55b6f2,0x13e5acfe,0x40bf9a83,0xf4c09ed5,0x8a37bc85,
        0xd49deb71,0x6caeaed9,0xa78b09ef,0xa3e3aadb,0xbf84b395,0x1acacd21,0xcbfcc9d2,0xb6d9f5a5,
        0x01f35feb,0xc31afef1,0xf47984ed,0xca33e8e0,0x6a5eed5b,0xd8b7aa31,0x26a9d7e6,0xa1ea8d9e,
        0x41d58db5,0xf2dd4c09,0x2c50a9ea,0x6b2af61b,0x6f7f4f26,0xdaf2e267,0x95e09e9a,0x39a3c6e5,
        0xd7e69d7e,0xb862d61e,0xa9a89ac3,0xc7cc24e3,0x5862df55,0x9c2879a4,0x28a2a8fa,0x6c3ba47f,
        0xe8d09ae4,0x70b3ef67,0x02b8eb0d,0xa5ab2e7e,0xe76bdf04,0x3ce1ee02,0x4765b1b6,0x42ca5f27,
        0x09ee5e87,0x5e61c1dc,0xba30b57a,0xd7be2e00,0x8625f18f,0x1e66b7e0,0x72fdb9a7,0x98ee9c64,
        0x15ddf6e7,0x8ee0b21c,0x5a37c2cf,0xfc37a14e,0xf1a4a90f,0x37bba76a,0x491a8f1e,0xa7e89431,
        0xbfabebea,0xa3bce9fc,0x6e5ad67e,0x3ee74c77,0x0efbefd3,0xa8e6e9ba,0xdfe9abb6,0xd80c0e67,
        0x21a7e68a,0x2e54cc52,0x5e5b65ec,0xb3e8d53a,0xe1b64a56,0x1adb1aec,0xbc64db4e,0xfed6ea02,
        0xe4e4e0bb,0xf3ae60c7,0x3f4cca99,0xbb89a1b7,0xaf53e0e7,0x065a7b26,0x57c3ec4c,0xd10c79af,
        0x84c1b6e1,0x1aae1a11,0xad7c3741,0xfef35ae3,0xe5c4af10,0xede54f3e,0x7e5dae2a,0xfeed7038,
        0x72cdfec9,0xacaac1f3,0x25a5f4be,0x53bd8b92,0x4e4fa0f9,0x6b3cbc66,0xba11ebab,0xb51b5fac,
        0x0181d740,0x088d3007,0x59d04aca,0xc9a34c5e,0xef36e60d,0x79d96f94,0x4e82c0dd,0xe2c9a24e,
        0xf2bbad80,0x8a8b9da0,0xa24c6fee,0x6b5c4b13,0x1ded8b97,0xe5e24601,0x6b6d3f2a,0x12e9d2c4,
    ]

    def __init__(self, key: bytes):
        if len(key) < 16 or len(key) > 56 or len(key) % 4 != 0:
            # Normaliser à 16 octets pour simplifier
            if len(key) < 16:
                key = key + b'\x00' * (16 - len(key))
            key = key[:16]
        self._subkeys = self._key_schedule(key)

    @staticmethod
    def _rotl(x: int, n: int) -> int:
        n &= 31
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @staticmethod
    def _rotr(x: int, n: int) -> int:
        n &= 31
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _key_schedule(self, key: bytes) -> list[int]:
        """Génère 40 sous-clés de 32 bits."""
        n  = len(key) // 4
        T  = list(struct.unpack(f'<{n}I', key[:n*4]))
        # Padder T à 15 mots
        T += [0] * (15 - len(T))
        T.append(n)

        K = list(T[:])
        for j in range(4):
            for i in range(16):
                K[i & 15] ^= self._rotl(
                    K[(i - 7) & 15] ^ K[(i - 2) & 15], 3
                ) ^ (4 * i + j) ^ 0x5555_5555
                K[i & 15] = self._rotl(K[i & 15], 9)

        subkeys = list(K[:])
        for j in range(4, 8):
            for i in range(16):
                subkeys[i & 15] ^= self._rotl(
                    subkeys[(i - 7) & 15] ^ subkeys[(i - 2) & 15], 3
                ) ^ (4 * (i + 16) + (j - 4)) ^ 0xAAAA_AAAA

        # Ajuster les sous-clés multiplicatives pour qu'elles soient impaires
        result = []
        for i, k in enumerate(subkeys[:40]):
            if i in range(5, 37, 10) or i in range(6, 38, 10):
                k = k | 3
            result.append(k & 0xFFFFFFFF)
        return result

    def _E(self, data: int, subkey_a: int, subkey_b: int) -> tuple[int, int]:
        """E-function : cœur cryptographique de MARS."""
        data = (data + subkey_a) & 0xFFFFFFFF
        idx  = data & 0x1FF
        out  = self._SBOX[idx & 0xFF]
        R    = (data >> 5) & 0x1F
        tmp  = (out ^ self._rotl(self._SBOX[256 + ((idx >> 1) & 0xFF)], R))
        out2 = tmp ^ (subkey_b & 0xFFFFFFFF)
        rot2 = subkey_b >> 27
        return self._rotl(out ^ self._rotl(out2, rot2), 5), self._rotr(out2, 5)

    def encrypt_block(self, block: bytes) -> bytes:
        assert len(block) == 16
        A, B, C, D = struct.unpack('<4I', block)
        K = self._subkeys

        # Phase 1 : Forward mixing (8 demi-tours avec addition)
        A = (A + K[0]) & 0xFFFFFFFF
        B = (B + K[1]) & 0xFFFFFFFF
        C = (C + K[2]) & 0xFFFFFFFF
        D = (D + K[3]) & 0xFFFFFFFF
        for i in range(8):
            B ^= self._SBOX[A & 0xFF]; B = (B + self._SBOX[((A>>8)&0xFF)+256]) & 0xFFFFFFFF
            C = (C + self._SBOX[(A>>16)&0xFF]) & 0xFFFFFFFF; D ^= self._SBOX[((A>>24)&0xFF)+256]
            A = self._rotr(A, 24); A = (A + B) if i < 4 else (A + D) & 0xFFFFFFFF; A &= 0xFFFFFFFF
            A, B, C, D = B, C, D, A

        # Phase 2 : Cœur cryptographique (16 tours avec la E-function)
        for i in range(16):
            MA, MB = self._E(A, K[4 + 2*i], K[5 + 2*i])
            B ^= MA; D ^= MB
            A, B, C, D = B, C, D, A

        # Phase 3 : Backward mixing (8 demi-tours avec soustraction)
        for i in range(8):
            A = (A - B) if i >= 4 else (A - D) & 0xFFFFFFFF; A &= 0xFFFFFFFF
            A = self._rotl(A, 24)
            B ^= self._SBOX[A & 0xFF]; B = (B - self._SBOX[((A>>8)&0xFF)+256]) & 0xFFFFFFFF
            C = (C - self._SBOX[(A>>16)&0xFF]) & 0xFFFFFFFF; D ^= self._SBOX[((A>>24)&0xFF)+256]
            A, B, C, D = B, C, D, A
        A = (A - K[36]) & 0xFFFFFFFF
        B = (B - K[37]) & 0xFFFFFFFF
        C = (C - K[38]) & 0xFFFFFFFF
        D = (D - K[39]) & 0xFFFFFFFF
        return struct.pack('<4I', A, B, C, D)

    def decrypt_block(self, block: bytes) -> bytes:
        # Inverse du chiffrement (symétrie des phases)
        assert len(block) == 16
        A, B, C, D = struct.unpack('<4I', block)
        K = self._subkeys

        A = (A + K[36]) & 0xFFFFFFFF
        B = (B + K[37]) & 0xFFFFFFFF
        C = (C + K[38]) & 0xFFFFFFFF
        D = (D + K[39]) & 0xFFFFFFFF

        for i in range(7, -1, -1):
            A, B, C, D = D, A, B, C
            A = self._rotl(A, 24)
            B ^= self._SBOX[A & 0xFF]; B = (B + self._SBOX[((A>>8)&0xFF)+256]) & 0xFFFFFFFF
            C = (C + self._SBOX[(A>>16)&0xFF]) & 0xFFFFFFFF; D ^= self._SBOX[((A>>24)&0xFF)+256]
            A = self._rotr(A, 24)
            A = (A + D) if i >= 4 else (A + B) & 0xFFFFFFFF; A &= 0xFFFFFFFF

        for i in range(15, -1, -1):
            A, B, C, D = D, A, B, C
            MA, MB = self._E(A, K[4 + 2*i], K[5 + 2*i])
            B ^= MA; D ^= MB

        for i in range(7, -1, -1):
            A, B, C, D = D, A, B, C
            A = (A - B) if i < 4 else (A - D) & 0xFFFFFFFF; A &= 0xFFFFFFFF
            A = self._rotl(A, 24)
            B ^= self._SBOX[A & 0xFF]; B = (B - self._SBOX[((A>>8)&0xFF)+256]) & 0xFFFFFFFF
            C = (C - self._SBOX[(A>>16)&0xFF]) & 0xFFFFFFFF; D ^= self._SBOX[((A>>24)&0xFF)+256]

        A = (A - K[0]) & 0xFFFFFFFF
        B = (B - K[1]) & 0xFFFFFFFF
        C = (C - K[2]) & 0xFFFFFFFF
        D = (D - K[3]) & 0xFFFFFFFF
        return struct.pack('<4I', A, B, C, D)

    def encrypt(self, plaintext: bytes) -> bytes:
        return _ecb_encrypt(self, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return _ecb_decrypt(self, ciphertext)

    @staticmethod
    def description() -> str:
        return (
            "MARS (IBM Research) : Structure hétérogène en 3 phases — "
            "forward mixing, cœur cryptographique (E-function avec S-box fixe), "
            "backward mixing. Bloc 128 bits, clé 128-1248 bits, 32 demi-tours. "
            "Le plus complexe des 5 finalistes ; jugé trop complexe à analyser."
        )


# ═══════════════════════════════════════════════════════════════════════════════
#  Helpers ECB padding/unpadding (PKCS7)
# ═══════════════════════════════════════════════════════════════════════════════

def _pkcs7_pad(data: bytes, bs: int = 16) -> bytes:
    pad_len = bs - (len(data) % bs)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


def _ecb_encrypt(cipher, plaintext: bytes) -> bytes:
    """Chiffrement ECB générique (blocs de 16 octets avec PKCS7)."""
    padded = _pkcs7_pad(plaintext)
    return b''.join(cipher.encrypt_block(padded[i:i+16])
                    for i in range(0, len(padded), 16))


def _ecb_decrypt(cipher, ciphertext: bytes) -> bytes:
    raw = b''.join(cipher.decrypt_block(ciphertext[i:i+16])
                   for i in range(0, len(ciphertext), 16))
    return _pkcs7_unpad(raw)


# ═══════════════════════════════════════════════════════════════════════════════
#  Descriptions architecturales
# ═══════════════════════════════════════════════════════════════════════════════

FINALIST_INFO = {
    "Rijndael": {
        "structure": "SPN (Substitution-Permutation Network)",
        "block_bits": 128,
        "key_bits":   "128/192/256",
        "rounds":     "10/12/14",
        "class":      Rijndael,
        "desc": Rijndael.description(),
    },
    "Twofish": {
        "structure": "Réseau de Feistel",
        "block_bits": 128,
        "key_bits":   "128/192/256",
        "rounds":     16,
        "class":      Twofish,
        "desc": Twofish.description(),
    },
    "Serpent": {
        "structure": "SPN (32 tours — ultra-conservateur)",
        "block_bits": 128,
        "key_bits":   "128/192/256",
        "rounds":     32,
        "class":      Serpent,
        "desc": Serpent.description(),
    },
    "RC6": {
        "structure": "ARX (Add-Rotate-XOR)",
        "block_bits": 128,
        "key_bits":   "128/192/256+",
        "rounds":     20,
        "class":      RC6,
        "desc": RC6.description(),
    },
    "MARS": {
        "structure": "Hétérogène (3 phases)",
        "block_bits": 128,
        "key_bits":   "128-1248",
        "rounds":     32,
        "class":      MARS,
        "desc": MARS.description(),
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
#  TP2 Ex 2.4.2 — Chiffrer le même bloc avec les 5 algorithmes
# ═══════════════════════════════════════════════════════════════════════════════

def compare_all_finalists(message: bytes = None,
                           key128: bytes = None) -> dict[str, str]:
    """
    Chiffre le même message 128 bits avec les 5 finalistes.
    Retourne {nom: ciphertext_hex}.
    """
    if message is None:
        message = b"AES Finalist Test"
    if key128 is None:
        key128 = os.urandom(16)

    results = {}
    padded = _pkcs7_pad(message)[:16]   # Exactement 1 bloc

    for name, info in FINALIST_INFO.items():
        try:
            cipher = info["class"](key128)
            ct = cipher.encrypt_block(padded)
            results[name] = ct.hex()
        except Exception as e:
            results[name] = f"ERREUR: {e}"

    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  TP2 Ex 2.4.3 — Benchmark comparatif sur 1 Mo
# ═══════════════════════════════════════════════════════════════════════════════

def benchmark_finalists(data_size_mb: float = 1.0,
                         num_blocks: int = None) -> list[dict]:
    """
    Mesure les temps de chiffrement et déchiffrement de chaque finaliste
    sur `data_size_mb` Mo de données aléatoires.

    Returns liste de dicts triés par débit décroissant.
    """
    if num_blocks is None:
        num_blocks = int(data_size_mb * 1024 * 1024 / 16)

    key = os.urandom(16)
    blocks = [os.urandom(16) for _ in range(num_blocks)]

    results = []
    for name, info in FINALIST_INFO.items():
        try:
            cipher = info["class"](key)

            # Chiffrement
            t0 = time.perf_counter()
            ciphertexts = [cipher.encrypt_block(b) for b in blocks]
            enc_time = time.perf_counter() - t0

            # Déchiffrement
            t0 = time.perf_counter()
            for ct in ciphertexts:
                cipher.decrypt_block(ct)
            dec_time = time.perf_counter() - t0

            data_mb = num_blocks * 16 / (1024 * 1024)
            results.append({
                "name":              name,
                "structure":         info["structure"],
                "rounds":            info["rounds"],
                "enc_time_s":        enc_time,
                "dec_time_s":        dec_time,
                "enc_throughput_mbs": data_mb / enc_time if enc_time > 0 else 0,
                "dec_throughput_mbs": data_mb / dec_time if dec_time > 0 else 0,
                "data_mb":           data_mb,
            })
        except Exception as e:
            results.append({"name": name, "error": str(e)})

    results.sort(key=lambda x: x.get("enc_throughput_mbs", 0), reverse=True)
    return results


# ═══════════════════════════════════════════════════════════════════════════════
#  Affichage TP2
# ═══════════════════════════════════════════════════════════════════════════════

def print_finalist_descriptions() -> None:
    print("\n" + "=" * 66)
    print("  ARCHITECTURE DES 5 FINALISTES AES")
    print("=" * 66)
    for name, info in FINALIST_INFO.items():
        print(f"\n  ► {name}")
        print(f"    Structure : {info['structure']}")
        print(f"    Clé       : {info['key_bits']} bits  |  Tours : {info['rounds']}")
        print(f"    {info['desc'][:100]}...")


def print_finalist_ciphertexts(key: bytes = None) -> None:
    key = key or os.urandom(16)
    message = b"CryptoLab TP2!!!"
    print("\n" + "=" * 66)
    print(f"  CHIFFREMENT DU MÊME MESSAGE AVEC LES 5 FINALISTES")
    print(f"  Message : {message.decode()!r}")
    print(f"  Clé     : {key.hex()}")
    print("=" * 66)
    results = compare_all_finalists(message, key)
    for name, ct_hex in results.items():
        print(f"  {name:<10} : {ct_hex}")
    print("\n  → Chaque algorithme produit un cryptogramme différent.")
    print("    Même clé, même message → résultats incomparablement distincts.")


def print_benchmark(data_mb: float = 0.5) -> None:
    print("\n" + "=" * 66)
    print(f"  BENCHMARK COMPARATIF — {data_mb} Mo")
    print("=" * 66)
    print("  Mesure en cours (pure Python — les chiffres sont éducatifs)…")
    results = benchmark_finalists(data_size_mb=data_mb)
    print(f"\n  {'Finaliste':<12} {'Structure':<30} {'Chiffr.':<14} {'Déchiffr.'}")
    print("  " + "-" * 66)
    for r in results:
        if "error" in r:
            print(f"  {r['name']:<12} ERREUR : {r['error']}")
        else:
            print(f"  {r['name']:<12} {r['structure'][:28]:<30} "
                  f"{r['enc_throughput_mbs']:>5.2f} Mo/s    "
                  f"{r['dec_throughput_mbs']:>5.2f} Mo/s")
    print()


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print_finalist_descriptions()
    print_finalist_ciphertexts()
    print_benchmark(data_mb=0.2)
"""
symmetric/rc4.py
----------------
RC4 Stream Cipher — implémentation pure Python
"""

def _rc4_keystream(key: bytes, length: int) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    ks = []
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        ks.append(S[(S[i] + S[j]) % 256])
    return bytes(ks)

def encrypt_text(plaintext: str, key: str) -> bytes:
    key_bytes = key.encode('utf-8')
    data = plaintext.encode('utf-8')
    ks = _rc4_keystream(key_bytes, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))

def decrypt_text(ciphertext: bytes, key: str) -> str:
    key_bytes = key.encode('utf-8')
    ks = _rc4_keystream(key_bytes, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, ks)).decode('utf-8', errors='replace')
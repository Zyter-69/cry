# 🔐 CryptoLab

A Python cryptography suite built for a 3rd year Cybersecurity course, covering classical to modern encryption with a full GUI.

---

## Quick Start

```bash
pip install pycryptodome cryptography sympy numpy
python cryptolab_gui.py   # GUI
python main.py            # CLI
```

---

## What's Inside

| Category | Algorithms |
|----------|-----------|
| **Classical** | Caesar, Hill, Playfair, Vigenère, OTP, Frequency Analysis |
| **Symmetric** | RC4, DES/3DES, AES-128/192/256 (ECB/CBC/CTR/GCM) |
| **Asymmetric** | RSA, Diffie-Hellman, ElGamal, ECC/ECDH, Shamir Secret Sharing |
| **Hashing** | MD5, SHA-1/256/512, SHA-3, HMAC, pure Python SHA-256 |
| **Signatures** | RSA-PSS, ECDSA, DSA, ElGamal Sig, EdDSA |
| **Protocols** | TCP chat, Bluetooth (sim), UDP group chat, Homomorphic voting (Paillier) |

---

## Project Structure

```
CryptoLab/
├── cryptolab_gui.py      # Main GUI
├── main.py               # CLI
├── classical/            # Caesar, Hill, Vigenère, OTP...
├── symmetric/            # AES, DES, RC4...
├── asymmetric/           # RSA, DH, ElGamal, ECC...
├── hashing/              # SHA, HMAC...
├── protocols/            # Signatures, Paillier...
└── utils/                # Math helpers, prime generation
```

---

## Dependencies

```
pycryptodome >= 3.19
cryptography >= 41.0
sympy        >= 1.12
numpy        >= 1.24
```

---

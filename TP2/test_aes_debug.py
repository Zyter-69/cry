#!/usr/bin/env python3
"""Debug AES implementation"""

from aes import encrypt, decrypt, generate_key

# Test 1: ECB mode (simpler, no IV involvement)
print("=" * 70)
print("Test 1: ECB Mode (No IV)")
print("=" * 70)

key = generate_key("test", 256)
plaintext = b"Hello World!!!!! "  # Exactly 16 bytes
print(f"Key: {key.hex()[:32]}...")
print(f"Plaintext: {plaintext}")
print(f"Plaintext hex: {plaintext.hex()}")

ciphertext, iv = encrypt(plaintext, key, 256, 'ECB')
print(f"Ciphertext: {ciphertext.hex()}")

decrypted = decrypt(ciphertext, key, iv, 256, 'ECB')
print(f"Decrypted: {decrypted}")
print(f"Decrypted hex: {decrypted.hex()}")
print(f"Match: {plaintext == decrypted}")

# Test 2: CBC mode
print("\n" + "=" * 70)
print("Test 2: CBC Mode")
print("=" * 70)

plaintext2 = b"This is a test message for CBC mode!"
print(f"Plaintext: {plaintext2}")
print(f"Plaintext length: {len(plaintext2)}")

ciphertext2, iv2 = encrypt(plaintext2, key, 256, 'CBC')
print(f"Ciphertext: {ciphertext2.hex()[:64]}...")
print(f"IV: {iv2.hex()}")
print(f"Ciphertext length: {len(ciphertext2)}")

decrypted2 = decrypt(ciphertext2, key, iv2, 256, 'CBC')
print(f"Decrypted: {decrypted2}")
print(f"Decrypted length: {len(decrypted2)}")
print(f"Decrypted hex: {decrypted2.hex()}")
print(f"Match: {plaintext2 == decrypted2}")

# Test 3: Debug single block
print("\n" + "=" * 70)
print("Test 3: Single block encryption/decryption")
print("=" * 70)

from aes import key_expansion, aes_encrypt_block, aes_decrypt_block

plainblock = b"16ByteBlockTest!"  # Exactly 16 bytes
print(f"Plain block: {plainblock}")
print(f"Plain hex: {plainblock.hex()}")

w, nr = key_expansion(key, 256)
encrypted = aes_encrypt_block(plainblock, w, nr)
print(f"Encrypted: {encrypted.hex()}")

decrypted_block = aes_decrypt_block(encrypted, w, nr)
print(f"Decrypted: {decrypted_block}")
print(f"Decrypted hex: {decrypted_block.hex()}")
print(f"Match: {plainblock == decrypted_block}")

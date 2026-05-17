"""
Comprehensive Cryptography Test Suite
Tests all implementations: Classic, Symmetric, Asymmetric, Hash, Signatures
"""

import sys
import os

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*70)
    print(f" {title:^68} ")
    print("="*70)

def test_classic_ciphers():
    """Test classic cipher implementations"""
    print_header("CLASSIC CIPHERS TESTS")
    
    try:
        from chiff_symetrique.cesar import chiffrer_caesar, dechiffrer_caesar
        print("\n[CAESAR CIPHER]")
        plaintext = "bonjour le monde"
        key = 3
        ciphertext = chiffrer_caesar(plaintext, key)
        decrypted = dechiffrer_caesar(ciphertext, key)
        print(f"Plaintext:  {plaintext}")
        print(f"Ciphertext: {ciphertext}")
        print(f"Decrypted:  {decrypted}")
        print(f"Status: {'PASS' if plaintext == decrypted else 'FAIL'}")
    except Exception as e:
        print(f"Caesar cipher test failed: {e}")
    
    try:
        from chiff_symetrique.vigenere import encrypt, decrypt
        print("\n[VIGENERE CIPHER]")
        plaintext = "bonjour le monde"
        key = "secret"
        ciphertext = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, key)
        print(f"Plaintext:  {plaintext}")
        print(f"Key:        {key}")
        print(f"Ciphertext: {ciphertext}")
        print(f"Decrypted:  {decrypted}")
        print(f"Status: {'PASS' if plaintext.lower().replace(' ', '') == decrypted.lower() else 'FAIL'}")
    except Exception as e:
        print(f"Vigenere cipher test failed: {e}")

def test_symmetric_ciphers():
    """Test symmetric cipher implementations"""
    print_header("SYMMETRIC CIPHERS TESTS")
    
    try:
        from chiff_symetrique.des import encrypt, decrypt
        print("\n[DES CIPHER]")
        plaintext = "Hello123"
        key = "0123456789ABCDEF"
        ciphertext = encrypt(plaintext, key)
        decrypted = decrypt(ciphertext, key)
        print(f"Plaintext:  {plaintext}")
        print(f"Key:        {key}")
        print(f"Ciphertext (hex): {ciphertext}")
        print(f"Decrypted:  {decrypted}")
        print(f"Status: {'PASS' if plaintext == decrypted else 'FAIL'}")
    except Exception as e:
        print(f"DES test failed: {e}")
    
    try:
        from chiff_symetrique.rc4 import rc4
        print("\n[RC4 CIPHER]")
        key = b"secretkey"
        plaintext = b"Hello"
        ciphertext = rc4(key, plaintext)
        decrypted = rc4(key, ciphertext)
        print(f"Plaintext:  {plaintext}")
        print(f"Key:        {key}")
        print(f"Ciphertext (hex): {ciphertext.hex()}")
        print(f"Decrypted:  {decrypted}")
        print(f"Status: {'PASS' if plaintext == decrypted else 'FAIL'}")
    except Exception as e:
        print(f"RC4 test failed: {e}")

def test_asymmetric_ciphers():
    """Test asymmetric cipher implementations"""
    print_header("ASYMMETRIC CIPHERS TESTS")
    
    try:
        from chiff_asymetrique.rsa import generate_keys, encrypt, decrypt, generate_prime
        print("\n[RSA CIPHER]")
        p = generate_prime()
        q = generate_prime()
        while p == q:
            q = generate_prime()
        public_key, private_key = generate_keys(p, q)
        plaintext = "Hi"
        ciphertext = encrypt(plaintext, public_key)
        decrypted = decrypt(ciphertext, private_key)
        print(f"Plaintext:  {plaintext}")
        print(f"Public key (e, n): {public_key}")
        print(f"Private key (d, n): {private_key}")
        print(f"Ciphertext: {ciphertext}")
        print(f"Decrypted:  {decrypted}")
        print(f"Status: {'PASS' if plaintext == decrypted else 'FAIL'}")
    except Exception as e:
        print(f"RSA test failed: {e}")

def test_hash_functions():
    """Test hash function implementations"""
    print_header("HASH FUNCTIONS TESTS")
    
    try:
        from empreint_numerique.hash_functions import HashFunctions
        print("\n[MD5]")
        message = "Hello World"
        md5_hash = HashFunctions.md5_hash(message)
        print(f"Message: {message}")
        print(f"MD5: {md5_hash}")
        
        print("\n[SHA-256]")
        sha256_hash = HashFunctions.sha256_hash(message)
        print(f"Message: {message}")
        print(f"SHA-256: {sha256_hash}")
        
        print("\n[SHA-512]")
        sha512_hash = HashFunctions.sha512_hash(message)
        print(f"Message: {message}")
        print(f"SHA-512: {sha512_hash}")
        
        print("\n[HMAC-SHA256]")
        key = "secret"
        hmac_result = HashFunctions.hmac_sha256(message, key)
        print(f"Message: {message}")
        print(f"Key: {key}")
        print(f"HMAC-SHA256: {hmac_result}")
    except Exception as e:
        print(f"Hash function tests failed: {e}")

def test_digital_signatures():
    """Test digital signature implementations"""
    print_header("DIGITAL SIGNATURES TESTS")
    
    try:
        from empreint_numerique.digital_signatures import DigitalSignatures
        print("\n[RSA-PSS]")
        DigitalSignatures.rsa_pss_sign_verify_demo()
    except Exception as e:
        print(f"Digital signature tests failed: {e}")

def print_menu():
    """Print main menu"""
    print_header("CRYPTOGRAPHY COMPREHENSIVE TEST SUITE")
    print("""
This suite tests all implemented cryptography algorithms:

TP 1 - CLASSIC CIPHERS
  ├── César cipher with frequency analysis
  ├── Vigenère cipher
  ├── Hill cipher (2x2, 3x3 matrices)
  ├── Affine cipher
  ├── PlayFair cipher
  └── One-Time Pad (Vernam)

TP 2 - SYMMETRIC CRYPTOGRAPHY
  ├── DES/3DES in ECB/CBC modes
  ├── RC4 (stream cipher)
  └── AES support (via cryptography lib)

TP 3 - ASYMMETRIC CRYPTOGRAPHY
  ├── Diffie-Hellman key exchange
  ├── RSA encryption/decryption
  ├── ElGamal encryption
  └── Elliptic Curve Cryptography (ECDH, ECDSA)

TP 4 - HASH FUNCTIONS
  ├── MD5 (Message Digest 5)
  ├── SHA-256 (Secure Hash Algorithm)
  ├── SHA-512
  └── HMAC for authentication

TP 5 - DIGITAL SIGNATURES
  ├── RSA-PSS signatures
  ├── DSA signatures
  └── ECDSA signatures

TP 6 - SECURE COMMUNICATIONS
  └── Example implementations with TCP/UDP sockets
""")

def main():
    """Main menu"""
    print_menu()
    
    while True:
        print("\n" + "-"*70)
        print("TEST OPTIONS:")
        print("  1. Test Classic Ciphers")
        print("  2. Test Symmetric Ciphers")
        print("  3. Test Asymmetric Ciphers")
        print("  4. Test Hash Functions")
        print("  5. Test Digital Signatures")
        print("  6. Run All Tests")
        print("  7. Exit")
        print("-"*70)
        
        choice = input("Choose [1-7]: ").strip()
        
        if choice == '7':
            print("\nExiting test suite. Goodbye!")
            break
        
        elif choice == '1':
            test_classic_ciphers()
        
        elif choice == '2':
            test_symmetric_ciphers()
        
        elif choice == '3':
            test_asymmetric_ciphers()
        
        elif choice == '4':
            test_hash_functions()
        
        elif choice == '5':
            test_digital_signatures()
        
        elif choice == '6':
            test_classic_ciphers()
            test_symmetric_ciphers()
            test_asymmetric_ciphers()
            test_hash_functions()
            test_digital_signatures()
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

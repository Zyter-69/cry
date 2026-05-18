"""
AES (Advanced Encryption Standard)
Supports AES-128, AES-192, and AES-256 encryption/decryption

Block size: 128 bits (16 bytes)
Key sizes: 128, 192, or 256 bits (16, 24, or 32 bytes)
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


# ==================== Key Generation ====================

def generate_key(key_input=None, key_size=256):
    """
    Generate or normalize AES key
    
    Args:
        key_input: Key string or bytes (generated if None)
        key_size: Key size in bits (128, 192, or 256)
    
    Returns:
        bytes: AES key of specified size
    """
    # Convert bits to bytes
    key_length = key_size // 8
    
    if key_input is None:
        return os.urandom(key_length)
    
    if isinstance(key_input, str):
        key_input = key_input.encode()
    
    # If key is longer than needed, truncate/hash it
    if len(key_input) > key_length:
        import hashlib
        key_input = hashlib.sha256(key_input).digest()[:key_length]
    
    # If key is shorter, pad with zeros
    if len(key_input) < key_length:
        key_input = key_input + b'\x00' * (key_length - len(key_input))
    
    return key_input[:key_length]


def generate_iv():
    """Generate random 128-bit IV for CBC mode"""
    return os.urandom(16)


# ==================== Encryption/Decryption ====================

def encrypt(plaintext, key, key_size=256, mode='CBC'):
    """
    Encrypt plaintext using AES
    
    Args:
        plaintext: Message to encrypt (bytes or str)
        key: Secret key (bytes or str)
        key_size: Key size in bits (128, 192, or 256)
        mode: Cipher mode ('CBC' or 'ECB')
    
    Returns:
        tuple: (ciphertext, iv) where iv is only for CBC mode
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    if isinstance(key, str):
        key = key.encode()
    
    # Normalize key
    key = generate_key(key, key_size)
    
    # Pad plaintext to 16-byte blocks (PKCS7)
    block_size = 16
    padding_length = block_size - (len(plaintext) % block_size)
    if padding_length == 0:
        padding_length = block_size
    plaintext = plaintext + bytes([padding_length] * padding_length)
    
    if mode.upper() == 'CBC':
        iv = generate_iv()
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, iv
    
    elif mode.upper() == 'ECB':
        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, None
    
    else:
        raise ValueError("Mode must be 'CBC' or 'ECB'")


def decrypt(ciphertext, key, iv=None, key_size=256, mode='CBC'):
    """
    Decrypt ciphertext using AES
    
    Args:
        ciphertext: Encrypted message (bytes or hex string)
        key: Secret key (bytes or str)
        iv: Initialization vector (required for CBC mode)
        key_size: Key size in bits (128, 192, or 256)
        mode: Cipher mode ('CBC' or 'ECB')
    
    Returns:
        bytes: Decrypted plaintext
    """
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    if isinstance(key, str):
        key = key.encode()
    
    # Normalize key
    key = generate_key(key, key_size)
    
    if mode.upper() == 'CBC':
        if iv is None:
            raise ValueError("IV required for CBC mode")
        if isinstance(iv, str):
            iv = bytes.fromhex(iv)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    elif mode.upper() == 'ECB':
        cipher = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    else:
        raise ValueError("Mode must be 'CBC' or 'ECB'")
    
    # Remove PKCS7 padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]
    
    return plaintext


# ==================== Demonstrations ====================

def demo_aes128():
    """Demonstrate AES-128"""
    print("\n" + "="*70)
    print("AES-128 Encryption/Decryption Demonstration")
    print("="*70)
    
    key = generate_key("secret_password_128", 128)
    plaintext = b"This is a secret message encrypted with AES-128"
    
    print(f"\n[*] Key: {key.hex()[:32]}...")
    print(f"[*] Key size: 128 bits")
    print(f"[*] Plaintext: {plaintext.decode()}")
    
    # Encrypt
    print("\n[*] Encrypting with AES-128 (CBC mode)...")
    ciphertext, iv = encrypt(plaintext, key, 128, 'CBC')
    print(f"[+] Ciphertext: {ciphertext.hex()[:64]}...")
    print(f"[+] IV: {iv.hex()}")
    
    # Decrypt
    print("\n[*] Decrypting...")
    decrypted = decrypt(ciphertext, key, iv, 128, 'CBC')
    print(f"[+] Decrypted: {decrypted.decode()}")
    print(f"[+] Match: {plaintext == decrypted}")


def demo_aes192():
    """Demonstrate AES-192"""
    print("\n" + "="*70)
    print("AES-192 Encryption/Decryption Demonstration")
    print("="*70)
    
    key = generate_key("secret_password_192", 192)
    plaintext = b"Stronger encryption with AES-192 key"
    
    print(f"\n[*] Key: {key.hex()[:32]}...")
    print(f"[*] Key size: 192 bits")
    print(f"[*] Plaintext: {plaintext.decode()}")
    
    # Encrypt
    print("\n[*] Encrypting with AES-192 (CBC mode)...")
    ciphertext, iv = encrypt(plaintext, key, 192, 'CBC')
    print(f"[+] Ciphertext: {ciphertext.hex()[:64]}...")
    print(f"[+] IV: {iv.hex()}")
    
    # Decrypt
    print("\n[*] Decrypting...")
    decrypted = decrypt(ciphertext, key, iv, 192, 'CBC')
    print(f"[+] Decrypted: {decrypted.decode()}")
    print(f"[+] Match: {plaintext == decrypted}")


def demo_aes256():
    """Demonstrate AES-256"""
    print("\n" + "="*70)
    print("AES-256 Encryption/Decryption Demonstration (High-Security)")
    print("="*70)
    
    key = generate_key("secret_password_256", 256)
    plaintext = b"Maximum security with AES-256 encryption"
    
    print(f"\n[*] Key: {key.hex()[:32]}...")
    print(f"[*] Key size: 256 bits")
    print(f"[*] Plaintext: {plaintext.decode()}")
    
    # Encrypt
    print("\n[*] Encrypting with AES-256 (CBC mode)...")
    ciphertext, iv = encrypt(plaintext, key, 256, 'CBC')
    print(f"[+] Ciphertext: {ciphertext.hex()[:64]}...")
    print(f"[+] IV: {iv.hex()}")
    
    # Decrypt
    print("\n[*] Decrypting...")
    decrypted = decrypt(ciphertext, key, iv, 256, 'CBC')
    print(f"[+] Decrypted: {decrypted.decode()}")
    print(f"[+] Match: {plaintext == decrypted}")


def demonstrate_attacks():
    """Show common AES attacks and security demonstrations"""
    print("\n" + "="*70)
    print("AES Security Demonstrations")
    print("="*70)
    
    # 1. Tampering Detection
    print("\n1. TAMPERING DETECTION")
    print("-" * 70)
    key = generate_key("secret", 256)
    plaintext = b"Transfer $100 to Alice"
    ciphertext, iv = encrypt(plaintext, key, 256, 'CBC')
    
    print(f"Original plaintext: {plaintext.decode()}")
    print(f"Ciphertext: {ciphertext.hex()[:40]}...")
    
    # Tamper with ciphertext
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF  # Flip bits
    tampered = bytes(tampered)
    
    print(f"\nTampered ciphertext: {tampered.hex()[:40]}...")
    try:
        decrypted = decrypt(tampered, key, iv, 256, 'CBC')
        if decrypted != plaintext:
            print(f"[+] Decrypted to: {decrypted}")
            print("[!] Tampering may go undetected without authentication")
    except Exception as e:
        print(f"[+] Decryption failed (good!): {e}")
    
    # 2. Key Size Comparison
    print("\n2. KEY SIZE STRENGTH COMPARISON")
    print("-" * 70)
    msg = b"Encryption comparison"
    key128 = generate_key("password", 128)
    key192 = generate_key("password", 192)
    key256 = generate_key("password", 256)
    
    cipher128, iv = encrypt(msg, key128, 128, 'CBC')
    cipher192, _ = encrypt(msg, key192, 192, 'CBC')
    cipher256, _ = encrypt(msg, key256, 256, 'CBC')
    
    print(f"Message: {msg.decode()}\n")
    print(f"AES-128: {len(key128)*8:3d}-bit key → {cipher128.hex()[:40]}...")
    print(f"AES-192: {len(key192)*8:3d}-bit key → {cipher192.hex()[:40]}...")
    print(f"AES-256: {len(key256)*8:3d}-bit key → {cipher256.hex()[:40]}...")
    print("\n[!] Recommendation: Use AES-256 for maximum security")
    
    # 3. Mode Comparison
    print("\n3. ENCRYPTION MODE COMPARISON")
    print("-" * 70)
    msg = b"Same plaintext block repeated" * 2
    key = generate_key("secret", 256)
    
    cipher_cbc, iv_cbc = encrypt(msg, key, 256, 'CBC')
    cipher_ecb, _ = encrypt(msg, key, 256, 'ECB')
    
    print("Message with repeated pattern encrypted:")
    print(f"  CBC mode: {cipher_cbc.hex()[:64]}...")
    print(f"  ECB mode: {cipher_ecb.hex()[:64]}...")
    print("\n[!] CBC mode hides patterns (IVs vary), ECB exposes patterns")


# ==================== Interactive Menu ====================

def menu():
    """Interactive menu for AES encryption"""
    print("=" * 70)
    print("       AES (Advanced Encryption Standard)")
    print("       Supports 128, 192, and 256-bit keys")
    print("=" * 70)
    
    key_size = 256  # Default
    key = None
    mode = 'CBC'    # Default
    
    while True:
        print(f"\nCurrent: AES-{key_size} ({mode} mode)")
        print("\nOptions:")
        print("  1. Switch to AES-128")
        print("  2. Switch to AES-192")
        print("  3. Switch to AES-256 (Default)")
        print("  4. Switch to CBC mode (Default)")
        print("  5. Switch to ECB mode")
        print("  6. Generate new key")
        print("  7. Set custom key")
        print("  8. Encrypt message")
        print("  9. Decrypt message")
        print("  10. Security Demonstrations")
        print("  11. Run All Demos")
        print("  12. Exit")
        
        choice = input("\nChoose [1-12]: ").strip()
        
        if choice == '12':
            break
        
        try:
            if choice == '1':
                key_size = 128
                print("[+] Switched to AES-128")
            
            elif choice == '2':
                key_size = 192
                print("[+] Switched to AES-192")
            
            elif choice == '3':
                key_size = 256
                print("[+] Switched to AES-256")
            
            elif choice == '4':
                mode = 'CBC'
                print("[+] Switched to CBC mode")
            
            elif choice == '5':
                mode = 'ECB'
                print("[+] Switched to ECB mode")
            
            elif choice == '6':
                print(f"\n[*] Generating AES-{key_size} key...")
                key = generate_key(None, key_size)
                print(f"[+] Key generated: {key.hex()[:40]}...")
            
            elif choice == '7':
                key_input = input("\nEnter secret key (or password): ").strip()
                key = generate_key(key_input, key_size)
                print(f"[+] Key set (normalized to {key_size} bits)")
            
            elif choice == '8':
                if key is None:
                    print("[-] Generate or set key first")
                    continue
                plaintext = input("\nEnter plaintext: ").strip()
                ciphertext, iv = encrypt(plaintext, key, key_size, mode)
                print(f"\n[+] Ciphertext: {ciphertext.hex()}")
                if iv:
                    print(f"[+] IV: {iv.hex()}")
            
            elif choice == '9':
                if key is None:
                    print("[-] Generate or set key first")
                    continue
                ciphertext_hex = input("\nEnter ciphertext (hex): ").strip()
                if mode.upper() == 'CBC':
                    iv_hex = input("Enter IV (hex): ").strip()
                    iv = bytes.fromhex(iv_hex)
                else:
                    iv = None
                try:
                    plaintext = decrypt(ciphertext_hex, key, iv, key_size, mode)
                    print(f"\n[+] Plaintext: {plaintext.decode()}")
                except Exception as e:
                    print(f"[-] Decryption failed: {e}")
            
            elif choice == '10':
                demonstrate_attacks()
            
            elif choice == '11':
                demo_aes128()
                demo_aes192()
                demo_aes256()
            
            else:
                print("[-] Invalid choice")
        
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    menu()

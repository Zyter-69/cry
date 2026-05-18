"""
HMAC (Hash-based Message Authentication Code)
Provides message authentication and integrity verification

Supports three HMAC algorithms:
- HMAC-MD5: Uses MD5 (legacy, not recommended for new applications)
- HMAC-SHA256: Uses SHA-256 (recommended for general use)
- HMAC-SHA512: Uses SHA-512 (high-security variant)
"""

import hashlib
import os


# ==================== Key Generation ====================

def generate_key(key_input=None, hash_algo='sha256', key_length=None):
    """
    Generate or normalize HMAC key
    
    Args:
        key_input: Key string or bytes (generated if None)
        hash_algo: Hash algorithm ('md5', 'sha256', 'sha512')
        key_length: Desired key length (auto-set based on algorithm)
    
    Returns:
        bytes: Normalized HMAC key
    """
    # Set block sizes based on algorithm
    block_sizes = {
        'md5': 64,
        'sha256': 64,
        'sha512': 128
    }
    
    if key_length is None:
        key_length = block_sizes.get(hash_algo.lower(), 64)
    
    if key_input is None:
        return os.urandom(key_length)
    
    if isinstance(key_input, str):
        key_input = key_input.encode()
    
    # If key is longer than block size, hash it
    if len(key_input) > key_length:
        h = hashlib.new(hash_algo)
        h.update(key_input)
        key_input = h.digest()
    
    # Pad key to block size
    if len(key_input) < key_length:
        key_input = key_input + b'\x00' * (key_length - len(key_input))
    
    return key_input


# ==================== HMAC Computation ====================

def compute_hmac(message, key, hash_algo='sha256'):
    """
    Compute HMAC
    
    Args:
        message: Message to authenticate (bytes or str)
        key: Secret key (bytes or str)
        hash_algo: Hash algorithm ('md5', 'sha256', 'sha512')
    
    Returns:
        bytes: HMAC digest
    """
    if isinstance(message, str):
        message = message.encode()
    if isinstance(key, str):
        key = key.encode()
    
    # Block sizes
    block_sizes = {'md5': 64, 'sha256': 64, 'sha512': 128}
    block_size = block_sizes.get(hash_algo.lower(), 64)
    
    # Normalize key
    key = generate_key(key, hash_algo, block_size)
    
    # Create inner and outer padding
    ipad = bytes([x ^ 0x36 for x in key])
    opad = bytes([x ^ 0x5c for x in key])
    
    # Compute HMAC: H((K XOR opad) || H((K XOR ipad) || message))
    h = hashlib.new(hash_algo)
    h.update(ipad + message)
    inner_hash = h.digest()
    
    h = hashlib.new(hash_algo)
    h.update(opad + inner_hash)
    hmac_result = h.digest()
    
    return hmac_result


def verify(message, key, expected_hmac, hash_algo='sha256'):
    """
    Verify HMAC
    
    Args:
        message: Original message (bytes or str)
        key: Secret key (bytes or str)
        expected_hmac: Expected HMAC (bytes or hex string)
        hash_algo: Hash algorithm ('md5', 'sha256', 'sha512')
    
    Returns:
        bool: True if valid, False otherwise
    """
    if isinstance(expected_hmac, str):
        expected_hmac = bytes.fromhex(expected_hmac)
    
    computed = compute_hmac(message, key, hash_algo)
    
    # Constant-time comparison to prevent timing attacks
    return computed == expected_hmac


# ==================== Demonstrations ====================

def demo_md5():
    """Demonstrate HMAC-MD5"""
    print("\n" + "="*70)
    print("HMAC-MD5 Demonstration")
    print("="*70)
    
    key = generate_key("secret_key", 'md5')
    message = b"Authenticate this message with HMAC-MD5"
    print(f"\n[*] Message: {message.decode()}")
    print(f"[*] Key (first 16 bytes): {key[:16].hex()}...")
    
    hmac_value = compute_hmac(message, key, 'md5')
    print(f"\n[+] HMAC-MD5: {hmac_value.hex()}")
    print(f"[+] Length: {len(hmac_value)} bytes ({len(hmac_value)*8} bits)")
    
    if verify(message, key, hmac_value, 'md5'):
        print("[+] Verification: SUCCESS")
    else:
        print("[-] Verification: FAILED")


def demo_sha256():
    """Demonstrate HMAC-SHA256"""
    print("\n" + "="*70)
    print("HMAC-SHA256 Demonstration")
    print("="*70)
    
    key = generate_key("secret_key", 'sha256')
    message = b"Authenticate with HMAC-SHA256 (Recommended)"
    print(f"\n[*] Message: {message.decode()}")
    print(f"[*] Key (first 16 bytes): {key[:16].hex()}...")
    
    hmac_value = compute_hmac(message, key, 'sha256')
    print(f"\n[+] HMAC-SHA256: {hmac_value.hex()}")
    print(f"[+] Length: {len(hmac_value)} bytes ({len(hmac_value)*8} bits)")
    
    if verify(message, key, hmac_value, 'sha256'):
        print("[+] Verification: SUCCESS")
    else:
        print("[-] Verification: FAILED")


def demo_sha512():
    """Demonstrate HMAC-SHA512"""
    print("\n" + "="*70)
    print("HMAC-SHA512 Demonstration (High-Security)")
    print("="*70)
    
    key = generate_key("secret_key", 'sha512')
    message = b"High-security authentication using HMAC-SHA512"
    print(f"\n[*] Message: {message.decode()}")
    print(f"[*] Key (first 16 bytes): {key[:16].hex()}...")
    
    hmac_value = compute_hmac(message, key, 'sha512')
    print(f"\n[+] HMAC-SHA512: {hmac_value.hex()}")
    print(f"[+] Length: {len(hmac_value)} bytes ({len(hmac_value)*8} bits)")
    
    if verify(message, key, hmac_value, 'sha512'):
        print("[+] Verification: SUCCESS")
    else:
        print("[-] Verification: FAILED")


def demonstrate_attacks():
    """Show common HMAC attacks and security demonstrations"""
    print("\n" + "="*70)
    print("HMAC Attack Demonstrations & Security Analysis")
    print("="*70)
    
    # 1. Key Length Impact
    print("\n1. KEY LENGTH IMPACT ON SECURITY")
    print("-" * 70)
    key_short = b"key"
    key_long = generate_key("secure_password", 'sha256')
    message = b"Important message"
    
    hmac_short = compute_hmac(message, key_short, 'sha256')
    hmac_long = compute_hmac(message, key_long, 'sha256')
    
    print(f"Message: {message.decode()}")
    print(f"\nShort key HMAC: {hmac_short.hex()[:32]}...")
    print(f"Long key HMAC:  {hmac_long.hex()[:32]}...")
    print("[!] Longer keys provide better security")
    
    # 2. Tampering Detection
    print("\n2. TAMPERING DETECTION")
    print("-" * 70)
    key = generate_key("secret", 'sha256')
    original = b"Transfer $100 to Alice"
    hmac_val = compute_hmac(original, key, 'sha256')
    
    print(f"Original: {original.decode()}")
    print(f"HMAC: {hmac_val.hex()[:40]}...")
    
    tampered = b"Transfer $1000 to Alice"
    print(f"\nTampered: {tampered.decode()}")
    if verify(tampered, key, hmac_val, 'sha256'):
        print("[-] SECURITY FAILURE: Message accepted!")
    else:
        print("[+] CORRECTLY DETECTED: Message rejected")
    
    # 3. Wrong Key Detection
    print("\n3. WRONG KEY DETECTION")
    print("-" * 70)
    correct_key = generate_key("correct", 'sha256')
    wrong_key = generate_key("wrong", 'sha256')
    msg = b"Authenticate this"
    
    hmac_val = compute_hmac(msg, correct_key, 'sha256')
    print(f"Message: {msg.decode()}")
    print(f"Signed with: 'correct' key")
    
    print(f"\nVerifying with: 'wrong' key")
    if verify(msg, wrong_key, hmac_val, 'sha256'):
        print("[-] SECURITY FAILURE")
    else:
        print("[+] CORRECTLY DETECTED: Wrong key")
    
    # 4. Algorithm Comparison
    print("\n4. ALGORITHM STRENGTH COMPARISON")
    print("-" * 70)
    msg = b"Compare HMAC algorithms"
    key = "secret"
    
    hmac_md5 = compute_hmac(msg, key, 'md5')
    hmac_sha256 = compute_hmac(msg, key, 'sha256')
    hmac_sha512 = compute_hmac(msg, key, 'sha512')
    
    print(f"Message: {msg.decode()}\n")
    print(f"HMAC-MD5     ({len(hmac_md5)*8:3d} bits): {hmac_md5.hex()[:40]}...")
    print(f"HMAC-SHA256  ({len(hmac_sha256)*8:3d} bits): {hmac_sha256.hex()[:40]}...")
    print(f"HMAC-SHA512  ({len(hmac_sha512)*8:3d} bits): {hmac_sha512.hex()[:40]}...")
    print("\n[!] Recommendation: Use SHA256 or SHA512")


# ==================== Interactive Menu ====================

def menu():
    """Interactive menu for HMAC"""
    print("=" * 70)
    print("       HMAC (Hash-based Message Authentication Code)")
    print("=" * 70)
    
    algo = 'sha256'  # Default algorithm
    key = None
    
    while True:
        print("\nOptions:")
        print("  1. HMAC-MD5")
        print("  2. HMAC-SHA256 (Current, Recommended)")
        print("  3. HMAC-SHA512 (High-Security)")
        print("  4. Generate new key")
        print("  5. Set custom key")
        print("  6. Compute HMAC")
        print("  7. Verify HMAC")
        print("  8. Security Demonstrations")
        print("  9. Run All Demos")
        print("  10. Exit")
        
        choice = input("\nChoose [1-10]: ").strip()
        
        if choice == '10':
            break
        
        try:
            if choice == '1':
                algo = 'md5'
                print("[!] Switched to HMAC-MD5 (legacy)")
            
            elif choice == '2':
                algo = 'sha256'
                print("[+] Switched to HMAC-SHA256")
            
            elif choice == '3':
                algo = 'sha512'
                print("[+] Switched to HMAC-SHA512")
            
            elif choice == '4':
                print(f"\n[*] Generating key for {algo.upper()}...")
                key = generate_key(None, algo)
                print(f"[+] Key generated: {key.hex()[:40]}...")
            
            elif choice == '5':
                key_input = input("\nEnter secret key: ").strip()
                key = generate_key(key_input, algo)
                print(f"[+] Key set (normalized)")
            
            elif choice == '6':
                if key is None:
                    print("[-] Generate or set key first")
                    continue
                message = input("\nEnter message: ").strip()
                hmac_val = compute_hmac(message, key, algo)
                print(f"[+] HMAC-{algo.upper()}: {hmac_val.hex()}")
            
            elif choice == '7':
                if key is None:
                    print("[-] Generate or set key first")
                    continue
                message = input("\nEnter message: ").strip()
                hmac_input = input("Enter HMAC (hex): ").strip()
                if verify(message, key, hmac_input, algo):
                    print("[+] HMAC is VALID")
                else:
                    print("[-] HMAC is INVALID")
            
            elif choice == '8':
                demonstrate_attacks()
            
            elif choice == '9':
                demo_md5()
                demo_sha256()
                demo_sha512()
            
            else:
                print("[-] Invalid choice")
        
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    menu()

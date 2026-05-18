"""
ElGamal Digital Signature Scheme
Signature variant based on discrete logarithm problem
Different from ElGamal encryption; uses a signature protocol
"""

import hashlib
import random


def is_prime(n, k=5):
    """
    Miller-Rabin primality test
    
    Args:
        n: Number to test
        k: Number of rounds (higher = more accurate)
    
    Returns:
        bool: True if probably prime, False if composite
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True


def generate_prime(min_val=10000, max_val=100000):
    """Generate a random prime number in range"""
    while True:
        p = random.randint(min_val, max_val)
        if is_prime(p):
            return p


def find_generator(p):
    """
    Find a generator g for the multiplicative group modulo p
    A generator g has order p-1 (or at least a large order)
    """
    while True:
        g = random.randint(2, p - 1)
        # Simple check: g^((p-1)/2) != 1 (mod p)
        if pow(g, (p - 1) // 2, p) != 1:
            return g


def mod_inverse(a, m):
    """Calculate modular multiplicative inverse using Extended Euclidean Algorithm"""
    if __gcd(a, m) != 1:
        raise ValueError(f"No inverse exists: gcd({a}, {m}) != 1")
    
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    
    return x1 + m0 if x1 < 0 else x1


def __gcd(a, b):
    """Calculate GCD of two numbers"""
    while b:
        a, b = b, a % b
    return a


def generate_keys(p=None, g=None):
    """
    Generate ElGamal signature key pair
    
    Args:
        p: Prime modulus (generated if None)
        g: Generator (generated if None)
    
    Returns:
        tuple: (public_key, private_key) where
               public_key = (p, g, y) and y = g^x mod p
               private_key = x
    """
    if p is None:
        p = generate_prime(10000, 100000)
    if g is None:
        g = find_generator(p)
    
    # Private key: random x in [1, p-2]
    x = random.randint(1, p - 2)
    
    # Public key: y = g^x mod p
    y = pow(g, x, p)
    
    return (p, g, y), x


def hash_message(message):
    """
    Hash message to a number less than p
    
    Args:
        message: Message to hash (bytes or str)
    
    Returns:
        int: Hash value
    """
    if isinstance(message, str):
        message = message.encode()
    
    hash_obj = hashlib.sha256(message)
    return int(hash_obj.hexdigest(), 16)


def sign(message, public_key, private_key):
    """
    Create ElGamal signature
    
    Signature = (r, s) where:
    - r = g^k mod p
    - s = (H(m) - x*r) * k^(-1) mod (p-1)
    
    Args:
        message: Message to sign (bytes or str)
        public_key: Tuple (p, g, y)
        private_key: Private key x
    
    Returns:
        tuple: (r, s) signature components
    """
    p, g, y = public_key
    
    # Hash message
    h = hash_message(message) % (p - 1)
    
    # Generate random k, gcd(k, p-1) = 1
    while True:
        k = random.randint(1, p - 2)
        if __gcd(k, p - 1) == 1:
            break
    
    # r = g^k mod p
    r = pow(g, k, p)
    
    # s = (h - x*r) * k^(-1) mod (p-1)
    k_inv = mod_inverse(k, p - 1)
    s = (h - private_key * r) * k_inv % (p - 1)
    
    return r, s


def verify(message, signature, public_key):
    """
    Verify ElGamal signature
    
    Verification: g^h = y^r * r^s (mod p)
    
    Args:
        message: Original message (bytes or str)
        signature: Tuple (r, s)
        public_key: Tuple (p, g, y)
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    p, g, y = public_key
    r, s = signature
    
    # Check if r is in valid range
    if not (0 < r < p):
        return False
    
    # Hash message
    h = hash_message(message) % (p - 1)
    
    # Verify: g^h = y^r * r^s (mod p)
    left = pow(g, h, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p
    
    return left == right


def demo():
    """Interactive demonstration of ElGamal signatures"""
    print("\n" + "="*70)
    print("ElGamal Digital Signature Scheme Demonstration")
    print("="*70)
    
    # Generate keys
    print("\n[*] Generating prime p and generator g...")
    public_key, private_key = generate_keys()
    p, g, y = public_key
    print(f"[+] Prime p: {p}")
    print(f"[+] Generator g: {g}")
    print(f"[+] Public key y = g^x mod p: {y}")
    print(f"[+] Private key x: {private_key}")
    
    # Sign a message
    message = b"Sign this important document with ElGamal"
    print(f"\n[*] Message: {message.decode()}")
    
    print("[*] Creating signature...")
    r, s = sign(message, public_key, private_key)
    print(f"[+] Signature r: {r}")
    print(f"[+] Signature s: {s}")
    
    # Verify signature
    print("\n[*] Verifying signature with original message...")
    if verify(message, (r, s), public_key):
        print("[+] Signature verification: SUCCESS")
    else:
        print("[-] Signature verification: FAILED")
    
    # Try with tampered message
    tampered_message = b"This document has been tampered with"
    print(f"\n[*] Verifying signature with tampered message...")
    print(f"[*] Tampered message: {tampered_message.decode()}")
    if verify(tampered_message, (r, s), public_key):
        print("[-] Signature verification: UNEXPECTED SUCCESS (Security breach!)")
    else:
        print("[+] Signature verification: CORRECTLY DETECTED (FAILED)")


def menu():
    """Interactive menu for ElGamal signatures"""
    print("=" * 70)
    print("            ElGamal Digital Signature Module")
    print("=" * 70)
    
    public_key, private_key = None, None
    
    while True:
        print("\nOptions:")
        print("  1. Generate new key pair")
        print("  2. Sign a message")
        print("  3. Verify a signature")
        print("  4. Run demo")
        print("  5. Back to main menu")
        
        choice = input("\nChoose [1-5]: ").strip()
        
        if choice == '5':
            break
        
        try:
            if choice == '1':
                print("\n[*] Generating prime and generator...")
                public_key, private_key = generate_keys()
                p, g, y = public_key
                print(f"[+] Key pair generated successfully")
                print(f"    Prime p: {p}")
                print(f"    Generator g: {g}")
                print(f"    Public key y: {y}")
            
            elif choice == '2':
                if private_key is None:
                    print("[-] Please generate keys first (option 1)")
                    continue
                message = input("\nEnter message to sign: ").strip()
                r, s = sign(message, public_key, private_key)
                print(f"\n[+] Signature (r, s):")
                print(f"    r: {r}")
                print(f"    s: {s}")
            
            elif choice == '3':
                if public_key is None:
                    print("[-] Please generate keys first (option 1)")
                    continue
                message = input("\nEnter original message: ").strip()
                try:
                    r = int(input("Enter r value: ").strip())
                    s = int(input("Enter s value: ").strip())
                    if verify(message, (r, s), public_key):
                        print("[+] Signature is VALID")
                    else:
                        print("[-] Signature is INVALID")
                except ValueError:
                    print("[-] Invalid input format")
            
            elif choice == '4':
                demo()
            
            else:
                print("[-] Invalid choice")
        
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    menu()

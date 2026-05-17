import random
import math

def is_prime(n: int, k=5) -> bool:
    """Fermat primality test"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_prime(min_val=100, max_val=1000) -> int:
    while True:
        p = random.randint(min_val, max_val)
        if is_prime(p):
            return p

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_inverse(a, m):
    m0 = m
    y = 0
    x = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if x < 0:
        x = x + m0
    return x

def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    
    # Choose e
    e = 65537 # Common choice
    if e >= phi or gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
            
    # Calculate d
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n)) # (public, private)

def encrypt(text: str, public_key: tuple) -> list:
    e, n = public_key
    # Encrypt each character
    return [pow(ord(char), e, n) for char in text]

def decrypt(cipher_vals: list, private_key: tuple) -> str:
    d, n = private_key
    # Decrypt each integer back to character
    return ''.join([chr(pow(char, d, n)) for char in cipher_vals])

def menu() -> None:
    print("=" * 50)
    print("                 RSA Cipher")
    print("=" * 50)

    # Initial keys
    p = generate_prime()
    q = generate_prime()
    while p == q:
        q = generate_prime()
        
    public_key, private_key = generate_keys(p, q)

    while True:
        print("\nOptions:")
        print("  1. Generate new keys")
        print("  2. Encrypt a message")
        print("  3. Decrypt a message")
        print("  4. View current keys")
        print("  5. Exit")
        choice = input("\nChoose [1-5]: ").strip()

        if choice == '5':
            print("Exiting...")
            break

        if choice not in ('1', '2', '3', '4'):
            print("Invalid choice. Please enter a number from 1 to 5.")
            continue

        try:
            if choice == '1':
                p_str = input("Enter prime p (leave blank for random): ").strip()
                q_str = input("Enter prime q (leave blank for random): ").strip()
                
                if p_str and q_str:
                    p = int(p_str)
                    q = int(q_str)
                    if not (is_prime(p) and is_prime(q)):
                        print("Warning: One or both numbers might not be prime.")
                else:
                    p = generate_prime()
                    q = generate_prime()
                    while p == q:
                        q = generate_prime()
                        
                public_key, private_key = generate_keys(p, q)
                print(f"Keys generated! p={p}, q={q}")
                print(f"Public key (e, n): {public_key}")
                print(f"Private key (d, n): {private_key}")

            elif choice == '2':
                text = input("Enter text to encrypt: ")
                cipher = encrypt(text, public_key)
                print(f"Encrypted message (list of integers): {cipher}")

            elif choice == '3':
                cipher_str = input("Enter space-separated integers to decrypt: ")
                cipher = [int(x) for x in cipher_str.split()]
                plaintext = decrypt(cipher, private_key)
                print(f"Decrypted message: {plaintext}")

            elif choice == '4':
                print(f"Public key (e, n): {public_key}")
                print(f"Private key (d, n): {private_key}")

        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    menu()

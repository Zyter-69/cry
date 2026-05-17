import random
import re

def is_prime(n: int, k=5) -> bool:
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

def generate_keys():
    p = generate_prime(1000, 5000)
    # Generator g
    g = random.randint(2, p - 1)
    
    # Private key x
    x = random.randint(1, p - 2)
    
    # Public key y
    y = pow(g, x, p)
    
    return ((p, g, y), x) # (Public, Private)

def encrypt(text: str, public_key: tuple) -> list:
    p, g, y = public_key
    cipher_pairs = []
    
    for char in text:
        m = ord(char)
        # Choosing random k
        k = random.randint(1, p - 2)
        
        c1 = pow(g, k, p)
        c2 = (m * pow(y, k, p)) % p
        cipher_pairs.append((c1, c2))
        
    return cipher_pairs

def decrypt(cipher_pairs: list, private_key: int, p: int) -> str:
    plaintext = []
    for c1, c2 in cipher_pairs:
        # compute s = c1^x mod p
        s = pow(c1, private_key, p)
        
        # mod inverse of s
        s_inv = mod_inverse(s, p)
        
        m = (c2 * s_inv) % p
        plaintext.append(chr(m))
        
    return ''.join(plaintext)

def menu() -> None:
    print("=" * 50)
    print("               ElGamal Cipher")
    print("=" * 50)

    public_key, private_key = generate_keys()

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
            print("Invalid choice.")
            continue

        try:
            if choice == '1':
                public_key, private_key = generate_keys()
                print("New keys generated!")
                print(f"Public key (p, g, y): {public_key}")
                print(f"Private key (x): {private_key}")

            elif choice == '2':
                text = input("Enter text to encrypt: ")
                cipher = encrypt(text, public_key)
                print(f"Encrypted message (list of (c1, c2) pairs): {cipher}")

            elif choice == '3':
                cipher_str = input("Enter list of pairs e.g., (1,2) (3,4): ")
                # parse "(c1,c2) (c1,c2)"
                matches = re.findall(r'\((\d+),\s*(\d+)\)', cipher_str)
                cipher = [(int(c1), int(c2)) for c1, c2 in matches]
                
                if not cipher:
                    print("Could not parse pairs. Use format (c1,c2) (c1,c2)")
                    continue
                    
                p = public_key[0]
                plaintext = decrypt(cipher, private_key, p)
                print(f"Decrypted message: {plaintext}")

            elif choice == '4':
                print(f"Public key (p, g, y): {public_key}")
                print(f"Private key (x): {private_key}")

        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    menu()

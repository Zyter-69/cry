import secrets
import string

def generate_key(length: int) -> str:
    """Generate a random key of the specified length."""
    return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))

def encrypt(plaintext: str, key: str) -> str:
    # First calculate the number of alphabetic characters
    alpha_count = sum(1 for c in plaintext if c.isalpha())
    
    key = key.lower()
    if not key.isalpha():
        raise ValueError("Key must contain only alphabetic characters.")
        
    if len(key) < alpha_count:
        raise ValueError(f"Key too short. Requires at least {alpha_count} alphabetic characters.")

    result = []
    key_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            x = ord(ch.lower()) - ord('a')
            k = ord(key[key_idx]) - ord('a')
            encrypted = (x + k) % 26
            letter = chr(encrypted + ord('a'))
            result.append(letter.upper() if ch.isupper() else letter)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def decrypt(ciphertext: str, key: str) -> str:
    # First calculate the number of alphabetic characters
    alpha_count = sum(1 for c in ciphertext if c.isalpha())
    
    key = key.lower()
    if not key.isalpha():
        raise ValueError("Key must contain only alphabetic characters.")
        
    if len(key) < alpha_count:
        raise ValueError(f"Key too short. Requires at least {alpha_count} alphabetic characters.")

    result = []
    key_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            y = ord(ch.lower()) - ord('a')
            k = ord(key[key_idx]) - ord('a')
            decrypted = (y - k) % 26
            letter = chr(decrypted + ord('a'))
            result.append(letter.upper() if ch.isupper() else letter)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def demonstrate_key_reuse_vulnerability():
    """Demonstrate the vulnerability of reusing OTP keys"""
    print("\n" + "="*70)
    print("ONE-TIME PAD - KEY REUSE VULNERABILITY DEMONSTRATION")
    print("="*70)
    
    # Generate a shared key
    key_length = 50
    shared_key = generate_key(key_length)
    print(f"\nGenerated key (length {key_length}): {shared_key[:20]}...")
    
    # Encrypt two different messages with the same key
    message1 = "this is the first secret message"
    message2 = "send reinforcements immediately now"
    
    ciphertext1 = encrypt(message1, shared_key)
    ciphertext2 = encrypt(message2, shared_key)
    
    print(f"\nMessage 1: {message1}")
    print(f"Ciphertext 1: {ciphertext1}")
    
    print(f"\nMessage 2: {message2}")
    print(f"Ciphertext 2: {ciphertext2}")
    
    # Calculate C1 XOR C2 = M1 XOR M2
    xor_result = []
    for i in range(len(ciphertext1)):
        xor_result.append(chr(ord(ciphertext1[i]) ^ ord(ciphertext2[i])))
    
    xor_str = ''.join(xor_result)
    print(f"\nC1 XOR C2: {xor_str}")
    
    print("\n" + "-"*70)
    print("ANALYSIS: When same key reuses, C1 XOR C2 = M1 XOR M2")
    print("This reveals information about the relationship between messages!")
    print("="*70)

def menu() -> None:
    print("=" * 70)
    print("       One-Time Pad (Vernam Cipher)")
    print("=" * 70)
    print("Perfect security if key is:")
    print("  - As long as the message")
    print("  - Truly random")
    print("  - Never reused")
    print("=" * 70)

    while True:
        print("\nOptions:")
        print("  1. Encrypt a message")
        print("  2. Decrypt a message")
        print("  3. Demonstrate key reuse vulnerability")
        print("  4. Exit")
        choice = input("\nChoose [1-4]: ").strip()

        if choice == '4':
            print("Exiting...")
            break

        try:
            if choice == '1':
                plaintext = input("Enter plaintext: ")
                key = input("Enter key (must be at least as long as the message): ").strip()
                ciphertext = encrypt(plaintext, key)
                print(f"\nCiphertext: {ciphertext}")
            
            elif choice == '2':
                ciphertext = input("Enter ciphertext: ")
                key = input("Enter key: ").strip()
                plaintext = decrypt(ciphertext, key)
                print(f"\nPlaintext: {plaintext}")
            
            elif choice == '3':
                demonstrate_key_reuse_vulnerability()
            
            else:
                print("Invalid choice.")

        except ValueError as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    menu()
            letter = chr(decrypted + ord('a'))
            result.append(letter.upper() if ch.isupper() else letter)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def menu() -> None:
    print("=" * 50)
    print("  One-Time Pad (Vernam) Cipher — Encrypt / Decrypt")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("  1. Encrypt a message (Provide your own key)")
        print("  2. Encrypt a message (Generate a random key)")
        print("  3. Decrypt a message")
        print("  4. Exit")
        choice = input("\nChoose [1-4]: ").strip()

        if choice == '4':
            print("Exiting...")
            break

        if choice not in ('1', '2', '3'):
            print("Invalid choice. Please enter 1, 2, 3, or 4.")
            continue

        try:
            if choice == '1':
                text = input("Enter text to encrypt: ")
                alpha_count = sum(1 for c in text if c.isalpha())
                key = input(f"Enter key (alphabetic string, at least {alpha_count} chars long): ").strip()
                if not key:
                    print("Error: Key cannot be empty.")
                    continue
                result = encrypt(text, key)
                print(f"\nEncrypted: {result}")
                
            elif choice == '2':
                text = input("Enter text to encrypt: ")
                alpha_count = sum(1 for c in text if c.isalpha())
                if alpha_count == 0:
                    print("Error: No alphabetic characters to encrypt.")
                    continue
                key = generate_key(alpha_count)
                print(f"\nGenerated Key: {key}")
                result = encrypt(text, key)
                print(f"Encrypted: {result}")
                
            elif choice == '3':
                text = input("Enter text to decrypt: ")
                alpha_count = sum(1 for c in text if c.isalpha())
                key = input(f"Enter key (alphabetic string, at least {alpha_count} chars long): ").strip()
                if not key:
                    print("Error: Key cannot be empty.")
                    continue
                result = decrypt(text, key)
                print(f"\nDecrypted: {result}")

        except ValueError as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    menu()

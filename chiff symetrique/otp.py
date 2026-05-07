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

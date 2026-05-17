def encrypt(plaintext: str, key: str) -> str:
    key = key.lower()
    if not key.isalpha():
        raise ValueError("Key must contain only alphabetic characters.")
        
    result = []
    key_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            x = ord(ch.lower()) - ord('a')
            k = ord(key[key_idx % len(key)]) - ord('a')
            encrypted = (x + k) % 26
            letter = chr(encrypted + ord('a'))
            result.append(letter.upper() if ch.isupper() else letter)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def decrypt(ciphertext: str, key: str) -> str:
    key = key.lower()
    if not key.isalpha():
        raise ValueError("Key must contain only alphabetic characters.")
        
    result = []
    key_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            y = ord(ch.lower()) - ord('a')
            k = ord(key[key_idx % len(key)]) - ord('a')
            decrypted = (y - k) % 26
            letter = chr(decrypted + ord('a'))
            result.append(letter.upper() if ch.isupper() else letter)
            key_idx += 1
        else:
            result.append(ch)
    return ''.join(result)

def menu() -> None:
    print("=" * 50)
    print("       Vigenère Cipher — Encrypt / Decrypt")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("  1. Encrypt a message")
        print("  2. Decrypt a message")
        print("  3. Exit")
        choice = input("\nChoose [1-3]: ").strip()

        if choice == '3':
            print("Exiting...")
            break

        if choice not in ('1', '2'):
            print("Invalid choice. Please enter 1, 2, or 3.")
            continue

        try:
            key = input("Enter key (alphabetic string): ").strip()
            if not key:
                print("Error: Key cannot be empty.")
                continue

            text = input("Enter text: ")

            if choice == '1':
                result = encrypt(text, key)
                print(f"\nEncrypted: {result}")
            else:
                result = decrypt(text, key)
                print(f"\nDecrypted: {result}")

        except ValueError as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    menu()

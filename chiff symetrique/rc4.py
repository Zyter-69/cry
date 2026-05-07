def ksa(key: bytes) -> list:
    """Key-Scheduling Algorithm (KSA)"""
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S: list, text_length: int) -> list:
    """Pseudo-Random Generation Algorithm (PRGA)"""
    i = 0
    j = 0
    keystream = []
    for _ in range(text_length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return keystream

def rc4(key: bytes, text: bytes) -> bytes:
    """Encrypt/Decrypt text using RC4."""
    S = ksa(key)
    keystream = prga(S, len(text))
    return bytes([text[i] ^ keystream[i] for i in range(len(text))])

def menu() -> None:
    print("=" * 50)
    print("             RC4 — Encrypt / Decrypt")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("  1. Encrypt/Decrypt a message")
        print("  2. Exit")
        choice = input("\nChoose [1-2]: ").strip()

        if choice == '2':
            print("Exiting...")
            break

        if choice != '1':
            print("Invalid choice. Please enter 1 or 2.")
            continue

        try:
            key_input = input("Enter key (string): ")
            text_input = input("Enter text (string or hex): ")
            
            # Since RC4 operates on bytes, we encode the string to bytes
            key = key_input.encode('utf-8')
            
            # Check if input is likely hex intended for decryption
            # The user can just type plain text to encrypt, or hex to decrypt.
            text_bytes = None
            try:
                # If it's valid hex and even length, might be ciphertext
                if len(text_input) % 2 == 0:
                    text_bytes = bytes.fromhex(text_input)
            except ValueError:
                pass
                
            if text_bytes is None:
                text_bytes = text_input.encode('utf-8')
            
            result_bytes = rc4(key, text_bytes)
            
            # Often RC4 output is non-printable, so we print hex for ciphertext
            print(f"\nResult (hex): {result_bytes.hex()}")
            
            # Try to decode to string if possible (useful when testing decryption)
            try:
                print(f"Result (string): {result_bytes.decode('utf-8')}")
            except UnicodeDecodeError:
                pass

        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    menu()

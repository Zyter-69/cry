"""
DSA (Digital Signature Algorithm)
NIST's standard signature algorithm based on discrete logarithm problem
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def generate_keys(key_size=1024):
    """
    Generate DSA key pair
    
    Args:
        key_size: DSA key size in bits (1024, 2048, or 3072)
    
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = dsa.generate_private_key(
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key, message):
    """
    Sign a message using DSA
    
    Args:
        private_key: DSA private key
        message: Message to sign (bytes or str)
    
    Returns:
        bytes: Signature
    """
    if isinstance(message, str):
        message = message.encode()
    
    signature = private_key.sign(
        message,
        hashes.SHA256()
    )
    return signature


def verify(public_key, message, signature):
    """
    Verify a DSA signature
    
    Args:
        public_key: DSA public key
        message: Original message (bytes or str)
        signature: Signature to verify (bytes)
    
    Returns:
        bool: True if valid, False otherwise
    """
    if isinstance(message, str):
        message = message.encode()
    
    try:
        public_key.verify(
            signature,
            message,
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def demo():
    """Interactive demonstration of DSA signatures"""
    print("\n" + "="*70)
    print("DSA (Digital Signature Algorithm) Demonstration")
    print("="*70)
    
    # Generate keys
    print("\n[*] Generating DSA-1024 key pair...")
    private_key, public_key = generate_keys(1024)
    print("[+] Key pair generated successfully")
    
    # Sign a message
    message = b"This document is digitally signed using DSA"
    print(f"\n[*] Message: {message.decode()}")
    
    print("[*] Signing message...")
    signature = sign(private_key, message)
    print(f"[+] Signature (first 32 bytes): {signature[:32].hex()}...")
    print(f"[+] Signature length: {len(signature)} bytes")
    
    # Verify signature
    print("\n[*] Verifying signature with original message...")
    if verify(public_key, message, signature):
        print("[+] Signature verification: SUCCESS")
    else:
        print("[-] Signature verification: FAILED")
    
    # Try with tampered message
    tampered_message = b"This document has been tampered with"
    print(f"\n[*] Verifying signature with tampered message...")
    print(f"[*] Tampered message: {tampered_message.decode()}")
    if verify(public_key, tampered_message, signature):
        print("[-] Signature verification: UNEXPECTED SUCCESS (Security breach!)")
    else:
        print("[+] Signature verification: CORRECTLY DETECTED (FAILED)")


def menu():
    """Interactive menu for DSA signatures"""
    print("=" * 70)
    print("            DSA (Digital Signature Algorithm) Module")
    print("=" * 70)
    
    private_key, public_key = None, None
    
    while True:
        print("\nOptions:")
        print("  1. Generate new key pair (1024-bit)")
        print("  2. Generate new key pair (2048-bit)")
        print("  3. Sign a message")
        print("  4. Verify a signature")
        print("  5. Run demo")
        print("  6. Back to main menu")
        
        choice = input("\nChoose [1-6]: ").strip()
        
        if choice == '6':
            break
        
        try:
            if choice == '1':
                print("\n[*] Generating DSA-1024 key pair...")
                private_key, public_key = generate_keys(1024)
                print("[+] Key pair generated successfully")
            
            elif choice == '2':
                print("\n[*] Generating DSA-2048 key pair...")
                private_key, public_key = generate_keys(2048)
                print("[+] Key pair generated successfully")
            
            elif choice == '3':
                if private_key is None:
                    print("[-] Please generate keys first (option 1 or 2)")
                    continue
                message = input("\nEnter message to sign: ").strip()
                signature = sign(private_key, message)
                print(f"\n[+] Signature (hex): {signature.hex()}")
            
            elif choice == '4':
                if public_key is None:
                    print("[-] Please generate keys first (option 1 or 2)")
                    continue
                message = input("\nEnter original message: ").strip()
                sig_input = input("Enter signature (hex): ").strip()
                try:
                    signature = bytes.fromhex(sig_input)
                    if verify(public_key, message, signature):
                        print("[+] Signature is VALID")
                    else:
                        print("[-] Signature is INVALID")
                except ValueError:
                    print("[-] Invalid hex format")
            
            elif choice == '5':
                demo()
            
            else:
                print("[-] Invalid choice")
        
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    menu()

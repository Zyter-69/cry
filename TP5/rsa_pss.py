"""
RSA-PSS Digital Signature Scheme
Provides probabilistic signature with security against chosen message attacks
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def generate_keys(key_size=2048):
    """
    Generate RSA key pair for PSS signatures
    
    Args:
        key_size: RSA key size in bits (default: 2048)
    
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key, message):
    """
    Sign a message using RSA-PSS
    
    Args:
        private_key: RSA private key
        message: Message to sign (bytes or str)
    
    Returns:
        bytes: Signature
    """
    if isinstance(message, str):
        message = message.encode()
    
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify(public_key, message, signature):
    """
    Verify an RSA-PSS signature
    
    Args:
        public_key: RSA public key
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
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def demo():
    """Interactive demonstration of RSA-PSS signatures"""
    print("\n" + "="*70)
    print("RSA-PSS Digital Signature Demonstration")
    print("="*70)
    
    # Generate keys
    print("\n[*] Generating RSA-2048 key pair...")
    private_key, public_key = generate_keys(2048)
    print("[+] Key pair generated successfully")
    
    # Sign a message
    message = b"This is an important financial transaction"
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
    tampered_message = b"This is a tampered transaction"
    print(f"\n[*] Verifying signature with tampered message...")
    print(f"[*] Tampered message: {tampered_message.decode()}")
    if verify(public_key, tampered_message, signature):
        print("[-] Signature verification: UNEXPECTED SUCCESS (Security breach!)")
    else:
        print("[+] Signature verification: CORRECTLY DETECTED (FAILED)")


def menu():
    """Interactive menu for RSA-PSS signatures"""
    print("=" * 70)
    print("            RSA-PSS Digital Signature Module")
    print("=" * 70)
    
    private_key, public_key = None, None
    
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
                print("\n[*] Generating RSA-2048 key pair...")
                private_key, public_key = generate_keys(2048)
                print("[+] Key pair generated successfully")
            
            elif choice == '2':
                if private_key is None:
                    print("[-] Please generate keys first (option 1)")
                    continue
                message = input("\nEnter message to sign: ").strip()
                signature = sign(private_key, message)
                print(f"\n[+] Signature (hex): {signature.hex()}")
            
            elif choice == '3':
                if public_key is None:
                    print("[-] Please generate keys first (option 1)")
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

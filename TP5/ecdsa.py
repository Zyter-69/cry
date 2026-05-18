"""
ECDSA (Elliptic Curve Digital Signature Algorithm)
Provides signature security based on elliptic curve discrete logarithm problem
Advantages: Smaller key sizes with equivalent security to RSA and DSA
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# Supported elliptic curves
CURVES = {
    'P256': ec.SECP256R1(),     # 256-bit, ~128-bit security
    'P384': ec.SECP384R1(),     # 384-bit, ~192-bit security
    'P521': ec.SECP521R1(),     # 521-bit, ~256-bit security
}


def generate_keys(curve='P256'):
    """
    Generate ECDSA key pair
    
    Args:
        curve: Elliptic curve to use ('P256', 'P384', 'P521')
    
    Returns:
        tuple: (private_key, public_key)
    """
    if curve not in CURVES:
        raise ValueError(f"Invalid curve. Choose from: {list(CURVES.keys())}")
    
    private_key = ec.generate_private_key(
        CURVES[curve],
        default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign(private_key, message):
    """
    Sign a message using ECDSA
    
    Args:
        private_key: ECDSA private key
        message: Message to sign (bytes or str)
    
    Returns:
        bytes: Signature
    """
    if isinstance(message, str):
        message = message.encode()
    
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature


def verify(public_key, message, signature):
    """
    Verify an ECDSA signature
    
    Args:
        public_key: ECDSA public key
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
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


def demo():
    """Interactive demonstration of ECDSA signatures"""
    print("\n" + "="*70)
    print("ECDSA (Elliptic Curve Digital Signature Algorithm) Demonstration")
    print("="*70)
    
    # Generate keys
    print("\n[*] Generating ECDSA-P256 key pair...")
    private_key, public_key = generate_keys('P256')
    print("[+] Key pair generated successfully")
    print("[+] Curve: P-256 (256-bit, ~128-bit security)")
    
    # Sign a message
    message = b"This is an ECDSA signed message with strong cryptographic security"
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
    tampered_message = b"This ECDSA signed message has been tampered with"
    print(f"\n[*] Verifying signature with tampered message...")
    print(f"[*] Tampered message: {tampered_message.decode()}")
    if verify(public_key, tampered_message, signature):
        print("[-] Signature verification: UNEXPECTED SUCCESS (Security breach!)")
    else:
        print("[+] Signature verification: CORRECTLY DETECTED (FAILED)")


def menu():
    """Interactive menu for ECDSA signatures"""
    print("=" * 70)
    print("            ECDSA (Elliptic Curve DSA) Module")
    print("=" * 70)
    
    private_key, public_key = None, None
    current_curve = 'P256'
    
    while True:
        print("\nOptions:")
        print("  1. Generate new key pair (P-256)")
        print("  2. Generate new key pair (P-384)")
        print("  3. Generate new key pair (P-521)")
        print("  4. Sign a message")
        print("  5. Verify a signature")
        print("  6. Run demo")
        print("  7. Back to main menu")
        
        choice = input("\nChoose [1-7]: ").strip()
        
        if choice == '7':
            break
        
        try:
            if choice == '1':
                print("\n[*] Generating ECDSA-P256 key pair...")
                current_curve = 'P256'
                private_key, public_key = generate_keys(current_curve)
                print("[+] Key pair generated successfully (P-256)")
            
            elif choice == '2':
                print("\n[*] Generating ECDSA-P384 key pair...")
                current_curve = 'P384'
                private_key, public_key = generate_keys(current_curve)
                print("[+] Key pair generated successfully (P-384)")
            
            elif choice == '3':
                print("\n[*] Generating ECDSA-P521 key pair...")
                current_curve = 'P521'
                private_key, public_key = generate_keys(current_curve)
                print("[+] Key pair generated successfully (P-521)")
            
            elif choice == '4':
                if private_key is None:
                    print("[-] Please generate keys first (option 1, 2, or 3)")
                    continue
                message = input("\nEnter message to sign: ").strip()
                signature = sign(private_key, message)
                print(f"\n[+] Signature (hex): {signature.hex()}")
            
            elif choice == '5':
                if public_key is None:
                    print("[-] Please generate keys first (option 1, 2, or 3)")
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
            
            elif choice == '6':
                demo()
            
            else:
                print("[-] Invalid choice")
        
        except Exception as e:
            print(f"[-] Error: {e}")
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    menu()

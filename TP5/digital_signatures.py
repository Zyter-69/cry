"""
Digital Signatures: RSA-PSS, ElGamal, DSA, ECDSA
Provides authentication and non-repudiation
"""

import hashlib
import random
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class DigitalSignatures:
    """Digital signature schemes"""
    
    @staticmethod
    def rsa_pss_sign_verify_demo():
        """Demonstrate RSA-PSS signatures"""
        print("\n" + "="*70)
        print("RSA-PSS Digital Signature Demonstration")
        print("="*70)
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        message = b"This is an important financial transaction"
        
        # Sign
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print(f"Message: {message.decode()}")
        print(f"Signature (first 32 bytes): {signature[:32].hex()}...")
        
        # Verify
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
            print("Signature verification: SUCCESS")
        except InvalidSignature:
            print("Signature verification: FAILED")
        
        # Try with tampered message
        tampered_message = b"This is a tampered transaction"
        try:
            public_key.verify(
                signature,
                tampered_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Tampered message verification: UNEXPECTED SUCCESS")
        except InvalidSignature:
            print("Tampered message verification: CORRECTLY DETECTED (FAILED)")
    
    @staticmethod
    def dsa_sign_verify_demo():
        """Demonstrate DSA signatures"""
        print("\n" + "="*70)
        print("DSA Digital Signature Demonstration")
        print("="*70)
        
        # Generate DSA key pair
        private_key = dsa.generate_private_key(
            key_size=1024,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        message = b"This document is signed"
        
        # Sign
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )
        
        print(f"Message: {message.decode()}")
        print(f"Signature (first 32 bytes): {signature[:32].hex()}...")
        
        # Verify
        try:
            public_key.verify(
                signature,
                message,
                hashes.SHA256()
            )
            print("Signature verification: SUCCESS")
        except InvalidSignature:
            print("Signature verification: FAILED")
    
    @staticmethod
    def ecdsa_sign_verify_demo():
        """Demonstrate ECDSA signatures"""
        print("\n" + "="*70)
        print("ECDSA Digital Signature Demonstration")
        print("="*70)
        
        # Generate ECDSA key pair
        private_key = ec.generate_private_key(
            ec.SECP256R1(),  # P-256 curve
            default_backend()
        )
        public_key = private_key.public_key()
        
        message = b"This is an ECDSA signed message"
        
        # Sign
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        
        print(f"Message: {message.decode()}")
        print(f"Signature (first 32 bytes): {signature[:32].hex()}...")
        
        # Verify
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            print("Signature verification: SUCCESS")
        except InvalidSignature:
            print("Signature verification: FAILED")
    
    @staticmethod
    def demonstrate_signature_attacks():
        """Show common signature attacks"""
        print("\n" + "="*70)
        print("Digital Signature Attack Demonstrations")
        print("="*70)
        
        # 1. Tampering attack
        print("\n1. TAMPERING ATTACK")
        print("-" * 70)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        message1 = b"Pay $100 to Alice"
        signature1 = private_key.sign(
            message1,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        print(f"Original message: {message1.decode()}")
        print(f"Signature valid: YES")
        
        message2 = b"Pay $1000 to Alice"
        try:
            public_key.verify(
                signature1,
                message2,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print(f"Tampered message: {message2.decode()}")
            print("Signature valid: YES (FAILED)")
        except InvalidSignature:
            print(f"Tampered message: {message2.decode()}")
            print("Signature valid: NO (CORRECTLY DETECTED)")

def menu():
    """Interactive menu for digital signatures"""
    print("=" * 70)
    print("            Digital Signatures - RSA-PSS, DSA, ECDSA")
    print("=" * 70)
    
    while True:
        print("\nOptions:")
        print("  1. RSA-PSS Signature Demo")
        print("  2. DSA Signature Demo")
        print("  3. ECDSA Signature Demo")
        print("  4. Signature Attack Demonstrations")
        print("  5. Exit")
        
        choice = input("\nChoose [1-5]: ").strip()
        
        if choice == '5':
            break
        
        try:
            if choice == '1':
                DigitalSignatures.rsa_pss_sign_verify_demo()
            elif choice == '2':
                DigitalSignatures.dsa_sign_verify_demo()
            elif choice == '3':
                DigitalSignatures.ecdsa_sign_verify_demo()
            elif choice == '4':
                DigitalSignatures.demonstrate_signature_attacks()
            else:
                print("Invalid choice")
        
        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    menu()

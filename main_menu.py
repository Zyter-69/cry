#!/usr/bin/env python3
"""
CRYPTOGRAPHY COURSE - COMPREHENSIVE IMPLEMENTATION
Main Menu and Navigation System

This project implements all algorithms from the cryptography course:
- TP 1: Classic Ciphers (César, Vigenère, Hill, Affine, PlayFair, OTP)
- TP 2: Symmetric Cryptography (DES, RC4, AES)
- TP 3: Asymmetric Cryptography (DH, RSA, ElGamal, ECC)
- TP 4: Hash Functions (MD5, SHA-256, SHA-512, HMAC)
- TP 5: Digital Signatures (RSA-PSS, DSA, ECDSA)
- TP 6: Secure Communications (TCP/UDP, Bluetooth, Wi-Fi)
"""

import os
import sys
import subprocess

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def print_header(title):
    """Print formatted header"""
    print("\n" + "="*75)
    print(f" {title:^73} ")
    print("="*75)

def print_main_menu():
    """Print main menu"""
    print_header("CRYPTOGRAPHY COURSE - COMPLETE IMPLEMENTATION")
    print("""
    SELECT A TOPIC:
    
    1. TP 1 - CLASSIC CIPHERS
       ├─ César cipher (brute force, frequency analysis)
       ├─ Vigenère cipher (Kasiski test)
       ├─ Hill cipher (2x2, 3x3 matrices)
       ├─ Affine cipher
       ├─ PlayFair cipher
       └─ One-Time Pad (Vernam)
    
    2. TP 2 - SYMMETRIC CRYPTOGRAPHY
       ├─ DES/3DES (ECB/CBC modes)
       ├─ RC4 (stream cipher)
       └─ Support for AES-128/192/256
    
    3. TP 3 - ASYMMETRIC CRYPTOGRAPHY
       ├─ Diffie-Hellman key exchange
       ├─ RSA encryption/decryption
       ├─ ElGamal encryption
       └─ Elliptic Curve Cryptography (ECDH, ECDSA)
    
    4. TP 4 - HASH FUNCTIONS
       ├─ MD5 (128-bit)
       ├─ SHA-256 (256-bit)
       ├─ SHA-512 (512-bit)
       └─ HMAC-SHA256
    
    5. TP 5 - DIGITAL SIGNATURES
       ├─ RSA-PSS signatures
       ├─ DSA signatures
       └─ ECDSA signatures
    
    6. TP 6 - SECURE COMMUNICATIONS
       └─ Examples and explanations for secure communications
      
    7. COMPREHENSIVE TEST SUITE
       └─ Run all algorithm tests
    
    8. EXIT
    """)

def tp1_menu():
    """TP 1 - Classic Ciphers Menu"""
    while True:
        print_header("TP 1 - CLASSIC CIPHERS")
        print("""
    1. César Cipher
    2. Vigenère Cipher
    3. Hill Cipher
    4. Affine Cipher
    5. PlayFair Cipher
    6. One-Time Pad (Vernam)
    7. Back to Main Menu
        """)
        
        choice = input("Choose [1-7]: ").strip()
        
        if choice == '1':
            run_algorithm("TP1", "cesar.py")
        elif choice == '2':
            run_algorithm("TP1", "vigenere.py")
        elif choice == '3':
            run_algorithm("TP1", "hill.py")
        elif choice == '4':
            run_algorithm("TP1", "affine.py")
        elif choice == '5':
            run_algorithm("TP1", "playFair.py")
        elif choice == '6':
            run_algorithm("TP1", "otp.py")
        elif choice == '7':
            return
        else:
            print("Invalid choice. Please try again.")

def tp2_menu():
    """TP 2 - Symmetric Cryptography Menu"""
    while True:
        print_header("TP 2 - SYMMETRIC CRYPTOGRAPHY")
        print("""
    1. DES Cipher (ECB/CBC modes)
    2. RC4 Cipher
    3. Back to Main Menu
        """)
        
        choice = input("Choose [1-3]: ").strip()
        
        if choice == '1':
            run_algorithm("TP2", "des.py")
        elif choice == '2':
            run_algorithm("TP2", "rc4.py")
        elif choice == '3':
            return
        else:
            print("Invalid choice. Please try again.")

def tp3_menu():
    """TP 3 - Asymmetric Cryptography Menu"""
    while True:
        print_header("TP 3 - ASYMMETRIC CRYPTOGRAPHY")
        print("""
    1. Diffie-Hellman Key Exchange
    2. RSA Encryption
    3. ElGamal Encryption
    4. Elliptic Curve Cryptography (ECDH/ECDSA)
    5. Back to Main Menu
        """)
        
        choice = input("Choose [1-5]: ").strip()
        
        if choice == '1':
            run_algorithm("TP3", "diffie_hellman.py")
        elif choice == '2':
            run_algorithm("TP3", "rsa.py")
        elif choice == '3':
            run_algorithm("TP3", "elgamal.py")
        elif choice == '4':
            run_algorithm("TP3", "ecc.py")
        elif choice == '5':
            return
        else:
            print("Invalid choice. Please try again.")

def tp4_menu():
    """TP 4 - Hash Functions Menu"""
    while True:
        print_header("TP 4 - HASH FUNCTIONS")
        print("""
    1. MD5
    2. SHA-256
    3. SHA-512
    4. Back to Main Menu
        """)
        
        choice = input("Choose [1-4]: ").strip()
        
        if choice == '1':
            run_algorithm("TP4", "MD5.py")
        elif choice == '2':
            run_algorithm("TP4", "SHA256.py")
        elif choice == '3':
            run_algorithm("TP4", "SHA512.py")
        elif choice == '4':
            return
        else:
            print("Invalid choice. Please try again.")

def tp5_menu():
    """TP 5 - Digital Signatures Menu"""
    while True:
        print_header("TP 5 - DIGITAL SIGNATURES")
        print("""
    1. Digital Signatures (RSA-PSS, DSA, ECDSA)
    2. Back to Main Menu
        """)
        
        choice = input("Choose [1-2]: ").strip()
        
        if choice == '1':
            run_algorithm("TP5", "digital_signatures.py")
        elif choice == '2':
            return
        else:
            print("Invalid choice. Please try again.")

def tp6_menu():
    """TP 6 - Secure Communications Menu"""
    while True:
        print_header("TP 6 - SECURE COMMUNICATIONS")
        print("""
    1. Examples and explanations for secure communications
    2. Back to Main Menu
        """)
        
        choice = input("Choose [1-2]: ").strip()
        
        if choice == '1':
            print("Examples and explanations for secure communications...")
            input("Press Enter to continue...")
        elif choice == '2':
            return
        else:
            print("Invalid choice. Please try again.")

def run_algorithm(subfolder, filename):
    """Run an algorithm script"""
    filepath = os.path.join(os.path.dirname(__file__), subfolder, filename)
    
    if not os.path.exists(filepath):
        print(f"\nError: {filepath} not found!")
        input("Press Enter to continue...")
        return
    
    try:
        # Replace spaces in folder name for subprocess
        filepath_safe = filepath.replace(" ", "_")
        if not os.path.exists(filepath_safe) and " " in filepath:
            # Use original path if spaces exist
            subprocess.run([sys.executable, filepath])
        else:
            subprocess.run([sys.executable, filepath])
    except Exception as e:
        print(f"\nError running {filename}: {e}")
        input("Press Enter to continue...")

def main():
    """Main menu loop"""
    while True:
        clear_screen()
        print_main_menu()
        
        choice = input("Choose [1-8]: ").strip()
        
        if choice == '1':
            tp1_menu()
        elif choice == '2':
            tp2_menu()
        elif choice == '3':
            tp3_menu()
        elif choice == '4':
            tp4_menu()
        elif choice == '5':
            tp5_menu()
        elif choice == '6':
            tp6_menu()
        elif choice == '7':
            print_header("RUNNING COMPREHENSIVE TEST SUITE")
            print("\nStarting tests...")
            run_algorithm(".", "test_all.py")
        elif choice == '8':
            print_header("GOODBYE")
            print("\nThank you for learning cryptography!")
            print("Remember: Always use production-grade libraries for real applications.")
            break
        else:
            print("Invalid choice. Please try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
        sys.exit(0)

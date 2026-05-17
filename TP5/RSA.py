import random
import math
from calculateInverse import cal_iverse 
import time

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generatePublicExponent(phi):
    e = 65537  # Common choice for e
    if e >= phi or gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2
    return e

def generate_prime():
    x = random.randint(100, 1000)
    while not is_prime(x):
        x = random.randint(100, 1000)
    return x

def hash(message):
    # Simple hash function for demonstration (not secure)
    return sum(ord(c) for c in message)


def sign(d, n, message):
    message = hash(message) % n
    s = pow(message, d, n)
    print(f"Message hash: {message}")
    print(f"Signature: {s}")
    
    
def verify(e, n, message, signature):
    message = hash(message) % n
    s_ver = pow(signature, e, n)
    print(f"Message hash: {message}")
    print(f"Signature verification result: {s_ver}")
    if s_ver == message:
        print("Signature is valid.")
    else:
        print("Signature is invalid.")


def generate_keys():
    print("select a prime number")
    while True:
        try:
            p = int(input("Enter prime p (leave blank for random): ").strip())
            if p == '':
                p = generate_prime()
                break
            if is_prime(p):
                break
            else:
                print("Warning: The number entered might not be prime. Please enter a valid prime number.")
        except ValueError:
            print("Invalid input. Please enter a valid prime number or leave blank for random generation.")
            
        print("select another prime number")
    while True:
        try:
            q = int(input("Enter prime q (leave blank for random): ").strip()) 
            if q == '':
                q = generate_prime()
                while q == p:
                    q = generate_prime()
                break
            if is_prime(q):
                if q != p:
                    break
                else:
                    print("Warning: q must be different from p. Please enter a different prime number.")
            else:
                print("Warning: The number entered might not be prime. Please enter a valid prime number.")
        except ValueError:
                print("Invalid input. Please enter a valid prime number or leave blank for random generation.")
        
        
    n = p * q
    phi = (p - 1) * (q - 1)
    e  = generatePublicExponent(phi)
    
    d = cal_iverse(e, phi)
    
    print(f"Keys generated! p={p}, q={q}")
    print(f"Public key (e, n): ({e}, {n})")
    print(f"Private key (d, n): ({d}, {n})")

    return

def main():
    
    print("Welcome to the RSA digital signature Program!")
    while True:
        print("select an option:")
        print("1. Generate keys")
        print("2. Sign a message ")
        print("3. Verify a signature")
        print("4. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            generate_keys()
            pass
        elif choice == "2":
            print("do you have the keys or do you want to generate new keys ? 1 for yes and 2 for no : ")
            while True:
                x = int(input())
                if x == 1:
                    print("Please enter the private key (d) and modulus (n):")
                    while True:
                        try:
                            d = int(input("d: "))
                            n = int(input("n: "))
                            break
                        except ValueError:
                            print("Invalid input. Please enter integers for d and n.")
                    print("Enter the message to sign:")
                    while True:
                        message = input()
                        if message:
                            break
                        else:
                            print("Message cannot be empty. Please enter a valid message.")
                            
                    sign (d, n  , message)
                    break
                elif x == 2:
                    generate_keys()
                    break
                else:
                    print("Invalid input. Please enter 1 or 2.")
            pass
        elif choice == "3":
            # Call the signature verification function
            print("Please enter the public key (e) and modulus (n):")
            while True:
                try:
                    e = int(input("e: "))
                    n = int(input("n: "))
                    break
                except ValueError:
                    print("Invalid input. Please enter integers for e and n.")
            print("Enter the message to verify:")
            while True:
                message = input()
                if message:
                    break
                else:
                    print("Message cannot be empty. Please enter a valid message.")
            print("Enter the signature to verify:")
            while True:
                try:
                    signature = int(input("Signature: "))
                    break
                except ValueError:
                    print("Invalid input. Please enter an integer for the signature.")
            verify(e, n, message, signature)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
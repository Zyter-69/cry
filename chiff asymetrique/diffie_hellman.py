import random

def is_prime(n: int, k=5) -> bool:
    """Fermat primality test"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def menu() -> None:
    print("=" * 50)
    print("          Diffie-Hellman Key Exchange")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("  1. Perform Key Exchange")
        print("  2. Exit")
        choice = input("\nChoose [1-2]: ").strip()

        if choice == '2':
            print("Exiting...")
            break

        if choice != '1':
            print("Invalid choice. Please enter 1 or 2.")
            continue

        try:
            p_str = input("Enter prime number (p): ").strip()
            g_str = input("Enter primitive root modulo p (g): ").strip()
            
            if not p_str or not g_str:
                print("Error: p and g cannot be empty.")
                continue

            p = int(p_str)
            g = int(g_str)

            if not is_prime(p):
                print("Warning: p does not appear to be a prime number based on Fermat test.")

            print("\n--- Alice's Side ---")
            aPrivateKey = int(input("Enter Alice's private key (a): "))
            A = pow(g, aPrivateKey, p)
            print(f"Alice's Public Key (A) = {A}")

            print("\n--- Bob's Side ---")
            bPrivateKey = int(input("Enter Bob's private key (b): "))
            B = pow(g, bPrivateKey, p)
            print(f"Bob's Public Key (B) = {B}")

            print("\n--- Exchange & Shared Secret ---")
            aliceSharedSecret = pow(B, aPrivateKey, p)
            bobSharedSecret = pow(A, bPrivateKey, p)

            print(f"Alice computes shared secret: B^a mod p = {aliceSharedSecret}")
            print(f"Bob computes shared secret: A^b mod p = {bobSharedSecret}")

            if aliceSharedSecret == bobSharedSecret:
                print("\nSuccess! Both parties have the identical shared secret.")
            else:
                print("\nError! Shared secrets do not match.")

        except ValueError:
            print("\nError: Please enter valid integers.")
        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    menu()

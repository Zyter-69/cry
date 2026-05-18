from TP3 import rsa
def main():
    
    print("Welcome to the RSA digital signature Program!")
    p=rsa.generate_prime()
    q=rsa.generate_prime()
    public_key , private_key = rsa.generate_keys(p, q)
    print(f"Your public key is: {public_key}")
    print(f"Your private key is: {private_key}")
    while True:
        print("select an option:")
        print("1. Generate new keys")
        print("2. Sign a message ")
        print("3. Verify a signature")
        print("4. Exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            p=rsa.generate_prime()
            q=rsa.generate_prime()
            public_key , private_key = rsa.generate_keys(p, q)
            print(f"Your new public key is: {public_key}")
            print(f"Your new private key is: {private_key}")
        elif choice == "2":
            print(rsa.encrypt(input("Enter the message to sign: "), private_key))
        elif choice == "3":
            signature = eval(input("Enter the signature to verify: "))
            message = input("Enter the original message: ")
            if rsa.decrypt(signature, public_key) == message:
                print("this text is signed by you!")
            else:
                print("this text is not signed by you!")
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
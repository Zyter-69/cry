import math


VALID_A = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]


def mod_inverse(a: int, m: int) -> int:
    if math.gcd(a, m) != 1:
        raise ValueError(
            f"No inverse: gcd({a}, {m}) != 1.\n"
            f"Valid values for a: {VALID_A}"
        )

    steps = []
    dividend, divisor = m, a
    while divisor != 0:
        q = dividend // divisor
        r = dividend % divisor
        steps.append((dividend, divisor, q, r))
        dividend, divisor = divisor, r

    steps = steps[:-1]
    if not steps:
        return 1
    
    d1, d2, q, _ = steps[-1]
    coeff = {d1: 1, d2: -q}
    for d1, d2, q, remainder in reversed(steps[:-1]):
        if remainder in coeff:
            c = coeff.pop(remainder)
            coeff[d1] = coeff.get(d1, 0) + c
            coeff[d2] = coeff.get(d2, 0) + c * (-q)
    return coeff[a] % m


def validate_keys(a: int, b: int) -> None:
    if math.gcd(a, 26) != 1:
        raise ValueError(
            f"Key 'a' = {a} is not coprime with 26.\n"
            f"Valid values: {VALID_A}"
        )
    if not (0 <= b <= 25):
        b= b % 26


def encrypt(plaintext: str, a: int, b: int) -> str:
    validate_keys(a, b)
    result = []
    for ch in plaintext:
        if ch.isalpha():
            x = ord(ch.lower()) - ord('a')
            encrypted = (a * x + b) % 26
            letter = chr(encrypted + ord('a'))
            result.append(letter.upper() if ch.isupper() else letter)
        else:
            result.append(ch)
    return ''.join(result)


def decrypt(ciphertext: str, a: int, b: int) -> str:
    validate_keys(a, b)
    a_inv = mod_inverse(a, 26)
    result = []
    for ch in ciphertext:
        if ch.isalpha():
            y = ord(ch.lower()) - ord('a')
            decrypted = (a_inv * (y - b)) % 26
            letter = chr(decrypted + ord('a'))
            result.append(letter.upper() if ch.isupper() else letter)
        else:
            result.append(ch)
    return ''.join(result)


def show_alphabet_mapping(a: int, b: int) -> None:
    validate_keys(a, b)
    plain  = ''.join(chr(i + ord('a')) for i in range(26))
    cipher = ''.join(chr((a * i + b) % 26 + ord('a')) for i in range(26))
    print(f"\nAlphabet mapping (a={a}, b={b}):")
    print(f"  Plain : {plain}")
    print(f"  Cipher: {cipher}")


def menu() -> None:
    print("=" * 50)
    print("       Affine Cipher — Encrypt / Decrypt")
    print("=" * 50)
    print(f"Valid values for key a: {VALID_A}")
    print()

    while True:
        print("\nOptions:")
        print("  1. Encrypt a message")
        print("  2. Decrypt a message")
        print("  3. Show alphabet mapping")
        print("  4. Exit")
        choice = input("\nChoose [1-4]: ").strip()

        if choice == '4':
            print("Exiting...")
            break

        if choice not in ('1', '2', '3'):
            print("Invalid choice. Please enter 1, 2, 3, or 4.")
            continue

        try:
            a = int(input("Enter key a: ").strip())
            b = int(input("Enter key b: ").strip())

            if choice == '3':
                show_alphabet_mapping(a, b)
                continue

            text = input("Enter text: ")

            if choice == '1':
                result = encrypt(text, a, b)
                print(f"\nEncrypted: {result}")
            else:
                result = decrypt(text, a, b)
                print(f"\nDecrypted: {result}")

        except ValueError as e:
            print(f"\nError: {e}")



if __name__ == "__main__":
    menu()
from calculateInverse import cal_iverse


def isInteger(s):
    try:
        int(s)
        return True
    except ValueError:
        return False


def charToNum(char):
    return ord(char) - ord('a')


def numToChar(num):
    return chr(num + ord('a'))


def matrix_det_2x2(key):
    a, b, c, d = key[0], key[1], key[2], key[3]
    return (a * d - b * c) % 26


def matrix_inverse_2x2(key):
    a, b, c, d = key[0], key[1], key[2], key[3]
    det = (a * d - b * c) % 26
    det_inv = cal_iverse(det, 26)
    if det_inv is None:
        return None
    inv = [
        (det_inv * d) % 26,
        (det_inv * (-b)) % 26,
        (det_inv * (-c)) % 26,
        (det_inv * a) % 26,
    ]
    return inv


def matrix_det_3x3(key):
    m = key
    det = (m[0] * (m[4] * m[8] - m[5] * m[7])
         - m[1] * (m[3] * m[8] - m[5] * m[6])
         + m[2] * (m[3] * m[7] - m[4] * m[6])) % 26
    return det


def matrix_inverse_3x3(key):
    m = key
    det = matrix_det_3x3(key)
    det_inv = cal_iverse(det, 26)
    if det_inv is None:
        return None

    adj = [
        (m[4] * m[8] - m[5] * m[7]) % 26,
        (m[2] * m[7] - m[1] * m[8]) % 26,
        (m[1] * m[5] - m[2] * m[4]) % 26,
        (m[5] * m[6] - m[3] * m[8]) % 26,
        (m[0] * m[8] - m[2] * m[6]) % 26,
        (m[2] * m[3] - m[0] * m[5]) % 26,
        (m[3] * m[7] - m[4] * m[6]) % 26,
        (m[1] * m[6] - m[0] * m[7]) % 26,
        (m[0] * m[4] - m[1] * m[3]) % 26,
    ]

    inv = [(det_inv * x) % 26 for x in adj]
    return inv


def read_key(n):
    """Read and validate a space-separated key for an (n+1)x(n+1) matrix."""
    size = (n + 1) * (n + 1)   # 4 for 2x2, 9 for 3x3
    dim  = n + 1                # 2 or 3

    while True:
        raw = input(f"Enter {size} key numbers separated by spaces: ").strip()
        parts = raw.split()

        if not all(isInteger(p) for p in parts):
            print("Invalid input. Please enter only integers.")
            continue

        numbers = list(map(int, parts))

        if len(numbers) != size:
            print(f"Invalid key length. Please enter exactly {size} numbers for a {dim}x{dim} matrix.")
            continue

        return numbers


def print_matrix(key, dim):
    for i in range(dim):
        print("  " + "  ".join(str(key[i * dim + j]) for j in range(dim)))


def decrypt():
    print("Enter the matrix size\n 1: 2x2\n 2: 3x3")
    while True:
        try:
            n = int(input("Choice: "))
            if n in (1, 2):
                break
        except ValueError:
            pass
        print("Invalid. Please enter 1 or 2.")

    dim = n + 1
    key = read_key(n)

    print("Key matrix:")
    print_matrix(key, dim)

    if n == 1:
        inv_key = matrix_inverse_2x2(key)
    else:
        inv_key = matrix_inverse_3x3(key)

    if inv_key is None:
        print("Error: The matrix is not invertible modulo 26.")
        return

    print("Inverse matrix:")
    print_matrix(inv_key, dim)

    text = input("Enter the text to decrypt: ").replace(" ", "").lower()

    decrypted = []
    i = 0
    if n == 1:
        while i < len(text):
            a, b = charToNum(text[i]), charToNum(text[i + 1])
            decrypted.append(numToChar((a * inv_key[0] + b * inv_key[1]) % 26))
            decrypted.append(numToChar((a * inv_key[2] + b * inv_key[3]) % 26))
            i += 2
    else:
        while i < len(text):
            a, b, c = charToNum(text[i]), charToNum(text[i + 1]), charToNum(text[i + 2])
            decrypted.append(numToChar((a * inv_key[0] + b * inv_key[1] + c * inv_key[2]) % 26))
            decrypted.append(numToChar((a * inv_key[3] + b * inv_key[4] + c * inv_key[5]) % 26))
            decrypted.append(numToChar((a * inv_key[6] + b * inv_key[7] + c * inv_key[8]) % 26))
            i += 3

    print("Decrypted text:", "".join(decrypted))


def encrypt():
    print("Enter the matrix size\n 1: 2x2\n 2: 3x3")
    while True:
        try:
            n = int(input("Choice: "))
            if n in (1, 2):
                break
        except ValueError:
            pass
        print("Invalid. Please enter 1 or 2.")

    dim = n + 1
    key = read_key(n)

    print("Key matrix:")
    print_matrix(key, dim)

    text = input("Enter the text to encrypt: ").replace(" ", "").lower()

    # Padding
    if n == 1:
        if len(text) % 2 != 0:
            text += 'x'
    else:
        while len(text) % 3 != 0:
            text += 'x'

    encrypted = []
    i = 0
    if n == 1:
        while i < len(text):
            a, b = charToNum(text[i]), charToNum(text[i + 1])
            encrypted.append(numToChar((a * key[0] + b * key[1]) % 26))
            encrypted.append(numToChar((a * key[2] + b * key[3]) % 26))
            i += 2
    else:
        while i < len(text):
            a, b, c = charToNum(text[i]), charToNum(text[i + 1]), charToNum(text[i + 2])
            encrypted.append(numToChar((a * key[0] + b * key[1] + c * key[2]) % 26))
            encrypted.append(numToChar((a * key[3] + b * key[4] + c * key[5]) % 26))
            encrypted.append(numToChar((a * key[6] + b * key[7] + c * key[8]) % 26))
            i += 3

    print("Encrypted text:", "".join(encrypted))


def main():
    print("Welcome to the Hill Cipher!")
    while True:
        print("\n1. Encrypt\n2. Decrypt\n3. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            encrypt()
        elif choice == '2':
            decrypt()
        elif choice == '3':
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
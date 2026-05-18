import os
# --- DES Tables ---
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

S_BOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# --- Helper Functions ---
def string_to_bits(text):
    bits = []
    for char in text:
        binval = bin(ord(char))[2:].zfill(8)
        bits.extend([int(b) for b in binval])
    return bits

def bits_to_string(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(''.join(map(str, byte)), 2)))
    return ''.join(chars)

def bits_to_hex(bits):
    s = ''.join(map(str, bits))
    return f"{int(s, 2):0{len(s)//4}X}"

def hex_to_bits(hex_str: str) -> list:
    bits = []
    for char in hex_str:
        binval = bin(int(char, 16))[2:].zfill(4)
        bits.extend([int(b) for b in binval])
    return bits

def pad_bits(bits):
    # Padding to make multiple of 64
    padding_len = 64 - (len(bits) % 64)
    if padding_len != 64:
        bits.extend([0] * padding_len)
    return bits

def permute(bits, table):
    return [bits[i - 1] for i in table]

def split_half(bits):
    return bits[:len(bits)//2], bits[len(bits)//2:]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

# --- Key Generation ---
def generate_round_keys(key_bits):
    key_bits = permute(key_bits, PC1)
    C, D = split_half(key_bits)
    keys = []
    for shift in SHIFTS:
        C = left_shift(C, shift)
        D = left_shift(D, shift)
        keys.append(permute(C + D, PC2))
    return keys

# --- Feistel Function ---
def feistel(R, K):
    E_R = permute(R, E)
    X = xor(E_R, K)
    S_out = []
    for i in range(8):
        row = (X[i*6] << 1) + X[i*6+5]
        col = (X[i*6+1] << 3) + (X[i*6+2] << 2) + (X[i*6+3] << 1) + X[i*6+4]
        val = S_BOX[i][row][col]
        S_out.extend([int(b) for b in bin(val)[2:].zfill(4)])
    return permute(S_out, P)

# --- DES Main Block Process ---
def des_block(block, round_keys):
    block = permute(block, IP)
    L, R = split_half(block)
    for K in round_keys:
        L, R = R, xor(L, feistel(R, K))
    return permute(R + L, FP)

# --- Encrypt/Decrypt Functions ---
def encrypt(text: str, hex_key: str) -> str:
    key_bits = hex_to_bits(hex_key)
    if len(key_bits) != 64:
        raise ValueError("Key must be 16 hex digits (64 bits).")
        
    round_keys = generate_round_keys(key_bits)
    text_bits = pad_bits(string_to_bits(text))
    
    cipher_bits = []
    for i in range(0, len(text_bits), 64):
        cipher_bits.extend(des_block(text_bits[i:i+64], round_keys))
        
    return bits_to_hex(cipher_bits)

def decrypt(hex_cipher: str, hex_key: str) -> str:
    key_bits = hex_to_bits(hex_key)
    if len(key_bits) != 64:
        raise ValueError("Key must be 16 hex digits (64 bits).")
        
    round_keys = generate_round_keys(key_bits)
    # Reverse keys for decryption
    round_keys.reverse()
    
    cipher_bits = hex_to_bits(hex_cipher)
    plain_bits = []
    for i in range(0, len(cipher_bits), 64):
        plain_bits.extend(des_block(cipher_bits[i:i+64], round_keys))
        
    # We may have trailing null characters due to padding. We can strip them.
    return bits_to_string(plain_bits).rstrip('\x00')

def menu():
    print("=" * 50)
    print("      Data Encryption Standard (DES)")
    print("=" * 50)

    while True:
        print("\nOptions:")
        print("  1. Encrypt a message")
        print("  2. Decrypt a message")
        print("  3. Exit")
        choice = input("\nChoose [1-3]: ").strip()

        if choice == '3':
            print("Exiting...")
            break

        if choice not in ('1', '2'):
            print("Invalid choice.")
            continue

        try:
            if choice == '1':
                key = os.urandom(8)
                hex_key = key.hex()
                print("ur key is " + hex_key)
                text = input("Enter plain-text message: ")
                cipher_hex = encrypt(text, hex_key)
                print(f"Encrypted message (HEX): {cipher_hex}")

            elif choice == '2':
                hex_key = input("Enter 16-digit hex key: ").strip().upper()
                if len(hex_key) != 16 or not all(c in "0123456789ABCDEF" for c in hex_key):
                    print("Error: Key must be 16 hexadecimal characters.")
                    continue
                cipher_hex = input("Enter encrypted message (HEX): ").strip().upper()
                plain_string = decrypt(cipher_hex, hex_key)
                print(f"Decrypted message: {plain_string}")

        except Exception as e:
            print(f"\nError: {e}")

if __name__ == "__main__":
    menu()

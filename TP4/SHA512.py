"""
SHA-512 (Secure Hash Algorithm 512-bit)
NIST FIPS 180-4 Implementation
Produces 512-bit (64-byte) hash output
Uses 64-bit words and 80 rounds (vs SHA-256 with 32-bit words and 64 rounds)
"""

import struct


# SHA-512 Constants - First 64 bits of fractional parts of cube roots of first 80 primes
K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa7b2, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0ebb3c88b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c0851074cca, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
]


def rightrotate_64(n, d):
    """Right rotate a 64-bit number"""
    return ((n >> d) | (n << (64 - d))) & 0xffffffffffffffff


def rightshift_64(n, d):
    """Right shift a 64-bit number"""
    return n >> d


def sha512_process_chunk(chunk, h):
    """Process a single 1024-bit chunk"""
    w = list(struct.unpack('>16Q', chunk))
    
    # Extend the sixteen 64-bit words into eighty 64-bit words
    for i in range(16, 80):
        s0 = rightrotate_64(w[i-15], 1) ^ rightrotate_64(w[i-15], 8) ^ rightshift_64(w[i-15], 7)
        s1 = rightrotate_64(w[i-2], 19) ^ rightrotate_64(w[i-2], 61) ^ rightshift_64(w[i-2], 6)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffffffffffff)
    
    # Initialize working variables
    a, b, c, d, e, f, g, h_val = h
    
    # Compression function main loop (80 rounds)
    for i in range(80):
        S1 = rightrotate_64(e, 14) ^ rightrotate_64(e, 34) ^ rightrotate_64(e, 39)
        ch = (e & f) ^ ((~e & 0xffffffffffffffff) & g)
        temp1 = (h_val + S1 + ch + K[i] + w[i]) & 0xffffffffffffffff
        S0 = rightrotate_64(a, 28) ^ rightrotate_64(a, 34) ^ rightrotate_64(a, 39)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffffffffffff
        
        h_val = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffffffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffffffffffff
    
    # Add compressed chunk to current hash value
    h[0] = (h[0] + a) & 0xffffffffffffffff
    h[1] = (h[1] + b) & 0xffffffffffffffff
    h[2] = (h[2] + c) & 0xffffffffffffffff
    h[3] = (h[3] + d) & 0xffffffffffffffff
    h[4] = (h[4] + e) & 0xffffffffffffffff
    h[5] = (h[5] + f) & 0xffffffffffffffff
    h[6] = (h[6] + g) & 0xffffffffffffffff
    h[7] = (h[7] + h_val) & 0xffffffffffffffff


def SHA512(message):
    """
    Compute SHA-512 hash of message
    
    Args:
        message: string or bytes
        
    Returns:
        hex digest string (128 characters)
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Initialize hash values (first 64 bits of fractional parts of square roots of first 8 primes)
    h = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
         0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179]
    
    # Pre-processing: adding padding bits
    ml = len(message) * 8
    msg = bytearray(message)
    msg.append(0x80)
    
    while (len(msg) % 128) != 112:
        msg.append(0x00)
    
    msg += struct.pack('>Q', 0)  # Higher 64 bits (for messages < 2^64 bits)
    msg += struct.pack('>Q', ml)  # Lower 64 bits
    
    # Process message in successive 1024-bit chunks
    for chunk_start in range(0, len(msg), 128):
        sha512_process_chunk(bytes(msg[chunk_start:chunk_start + 128]), h)
    
    # Produce final hash value
    return ''.join(f'{x:016x}' for x in h)


def menu():
    """Interactive menu for SHA-512"""
    print("=" * 70)
    print("              SHA-512 Hash Function Implementation")
    print("=" * 70)
    
    while True:
        print("\nOptions:")
        print("  1. Hash a message")
        print("  2. Hash a file")
        print("  3. Compare with another hash")
        print("  4. Exit")
        
        choice = input("\nChoose [1-4]: ").strip()
        
        if choice == '4':
            break
        
        try:
            if choice == '1':
                message = input("Enter message: ")
                result = SHA512(message)
                print(f"\nSHA-512: {result}")
            
            elif choice == '2':
                filepath = input("Enter file path: ")
                with open(filepath, 'rb') as f:
                    result = SHA512(f.read())
                print(f"\nFile: {filepath}")
                print(f"SHA-512: {result}")
            
            elif choice == '3':
                message = input("Enter message: ")
                hash_result = SHA512(message)
                expected = input("Enter expected hash: ").lower()
                
                match = "✓ MATCH" if hash_result == expected else "✗ NO MATCH"
                print(f"\nComputed: {hash_result}")
                print(f"Expected: {expected}")
                print(f"Result:   {match}")
            
            else:
                print("Invalid choice")
        
        except FileNotFoundError:
            print("File not found!")
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    menu()

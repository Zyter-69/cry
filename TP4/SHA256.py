"""
SHA-256 (Secure Hash Algorithm 256-bit)
NIST FIPS 180-4 Implementation
Produces 256-bit (32-byte) hash output
"""

import struct


# SHA-256 Constants - First 32 bits of fractional parts of cube roots of first 64 primes
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


def rightrotate(n, d):
    """Right rotate a 32-bit number"""
    return ((n >> d) | (n << (32 - d))) & 0xffffffff


def rightshift(n, d):
    """Right shift a 32-bit number"""
    return n >> d


def sha256_process_chunk(chunk, h):
    """Process a single 512-bit chunk"""
    w = list(struct.unpack('>16I', chunk))
    
    # Extend the sixteen 32-bit words into eighty 32-bit words
    for i in range(16, 64):
        s0 = rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ rightshift(w[i-15], 3)
        s1 = rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ rightshift(w[i-2], 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xffffffff)
    
    # Initialize working variables
    a, b, c, d, e, f, g, h_val = h
    
    # Compression function main loop
    for i in range(64):
        S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25)
        ch = (e & f) ^ ((~e & 0xffffffff) & g)
        temp1 = (h_val + S1 + ch + K[i] + w[i]) & 0xffffffff
        S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff
        
        h_val = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff
    
    # Add compressed chunk to current hash value
    h[0] = (h[0] + a) & 0xffffffff
    h[1] = (h[1] + b) & 0xffffffff
    h[2] = (h[2] + c) & 0xffffffff
    h[3] = (h[3] + d) & 0xffffffff
    h[4] = (h[4] + e) & 0xffffffff
    h[5] = (h[5] + f) & 0xffffffff
    h[6] = (h[6] + g) & 0xffffffff
    h[7] = (h[7] + h_val) & 0xffffffff


def SHA256(message):
    """
    Compute SHA-256 hash of message
    
    Args:
        message: string or bytes
        
    Returns:
        hex digest string (64 characters)
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Initialize hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    
    # Pre-processing: adding padding bits
    ml = len(message) * 8
    msg = bytearray(message)
    msg.append(0x80)
    
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    
    msg += struct.pack('>Q', ml)
    
    # Process message in successive 512-bit chunks
    for chunk_start in range(0, len(msg), 64):
        sha256_process_chunk(bytes(msg[chunk_start:chunk_start + 64]), h)
    
    # Produce final hash value
    return ''.join(f'{x:08x}' for x in h)


def menu():
    """Interactive menu for SHA-256"""
    print("=" * 70)
    print("              SHA-256 Hash Function Implementation")
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
                result = SHA256(message)
                print(f"\nSHA-256: {result}")
            
            elif choice == '2':
                filepath = input("Enter file path: ")
                with open(filepath, 'rb') as f:
                    result = SHA256(f.read())
                print(f"\nFile: {filepath}")
                print(f"SHA-256: {result}")
            
            elif choice == '3':
                message = input("Enter message: ")
                hash_result = SHA256(message)
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

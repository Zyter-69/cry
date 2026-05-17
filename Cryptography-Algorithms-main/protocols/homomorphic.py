"""
protocols/homomorphic.py
------------------------
Paillier Partially Homomorphic Encryption

Property: Enc(a) * Enc(b) mod n² = Enc(a + b)
           Enc(a)^k mod n²       = Enc(a * k)

This allows addition (and scalar multiplication) on encrypted data
without decrypting it — a fundamental property of homomorphic encryption.

Key sizes: 512-bit primes → 1024-bit n (educational)
           For real use: 2048-bit primes → 4096-bit n
"""

import os
from utils.math_utils import gcd, lcm, mod_inverse
from utils.primes import generate_prime


class Paillier:
    """
    Paillier cryptosystem with homomorphic addition.
    
    Usage:
        p = Paillier(bits=512)
        ct_a = p.encrypt(10)
        ct_b = p.encrypt(25)
        ct_sum = p.add_ciphertexts(ct_a, ct_b)
        print(p.decrypt(ct_sum))  # → 35
    """

    def __init__(self, bits: int = 512):
        """Generate Paillier keypair."""
        print(f"Generating {bits}-bit Paillier parameters...")
        while True:
            prime_p = generate_prime(bits)
            prime_q = generate_prime(bits)
            if prime_p != prime_q and gcd(prime_p * prime_q, (prime_p - 1) * (prime_q - 1)) == 1:
                break

        self.n = prime_p * prime_q
        self.n_sq = self.n ** 2

        # λ = lcm(p-1, q-1)
        self._lambda = lcm(prime_p - 1, prime_q - 1)

        # g = n + 1 (simplified choice, always works)
        self.g = self.n + 1

        # μ = (L(g^λ mod n²))^(-1) mod n
        # where L(x) = (x - 1) / n
        gl = pow(self.g, self._lambda, self.n_sq)
        self._mu = mod_inverse(self._L(gl), self.n)

        print(f"n  = {hex(self.n)[:20]}...  ({self.n.bit_length()} bits)")

    def _L(self, x: int) -> int:
        """L function: L(x) = (x - 1) / n."""
        return (x - 1) // self.n

    def encrypt(self, m: int) -> int:
        """
        Encrypt integer m (0 ≤ m < n).
        C = g^m * r^n mod n²  where r is a random coprime to n.
        """
        if not (0 <= m < self.n):
            raise ValueError(f"Message must be in [0, n). Got {m}")
        while True:
            r = int.from_bytes(os.urandom(self.n.bit_length() // 8), 'big') % self.n
            if gcd(r, self.n) == 1:
                break
        return (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq

    def decrypt(self, c: int) -> int:
        """Decrypt ciphertext c back to integer m."""
        cl = pow(c, self._lambda, self.n_sq)
        return (self._L(cl) * self._mu) % self.n

    # ── Homomorphic Operations ────────────────────────────────────────────────

    def add_ciphertexts(self, c1: int, c2: int) -> int:
        """
        Homomorphic addition.
        Enc(a) * Enc(b) mod n² = Enc(a + b)
        """
        return (c1 * c2) % self.n_sq

    def multiply_by_scalar(self, c: int, k: int) -> int:
        """
        Homomorphic scalar multiplication.
        Enc(a)^k mod n² = Enc(a * k)
        """
        return pow(c, k, self.n_sq)

    def subtract_ciphertexts(self, c1: int, c2: int) -> int:
        """
        Homomorphic subtraction.
        Enc(a - b) = Enc(a) * Enc(b)^(-1) mod n²
                   = Enc(a) * Enc(n - b) mod n²
        """
        c2_inv = pow(c2, -1, self.n_sq)  # modular inverse in n²
        return (c1 * c2_inv) % self.n_sq


if __name__ == "__main__":
    p = Paillier(bits=256)  # Small for demo speed

    a, b = 42, 17
    ca = p.encrypt(a)
    cb = p.encrypt(b)

    print(f"\na = {a}, b = {b}")
    print(f"Enc(a) = {hex(ca)[:20]}...")
    print(f"Enc(b) = {hex(cb)[:20]}...")

    # Homomorphic addition
    c_sum = p.add_ciphertexts(ca, cb)
    print(f"\nDec(Enc(a) * Enc(b)) = {p.decrypt(c_sum)}  (expected {a+b})")

    # Scalar multiplication
    k = 5
    c_mul = p.multiply_by_scalar(ca, k)
    print(f"Dec(Enc(a)^{k})       = {p.decrypt(c_mul)}  (expected {a*k})")

    # Subtraction
    c_sub = p.subtract_ciphertexts(ca, cb)
    print(f"Dec(Enc(a) - Enc(b)) = {p.decrypt(c_sub)}  (expected {a-b})")

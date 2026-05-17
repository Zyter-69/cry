"""
utils/primes.py
---------------
Large prime generation for cryptographic use (256-bit and above).
Uses Miller-Rabin primality test + sympy for verified large primes.
"""

import random
import sympy


def is_prime_miller_rabin(n: int, rounds: int = 20) -> bool:
    """Miller-Rabin primality test. `rounds` iterations → error prob < 4^(-rounds)."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int = 256) -> int:
    """Generate a random prime of exactly `bits` bits using sympy (guaranteed prime)."""
    return sympy.randprime(2 ** (bits - 1), 2 ** bits)


def generate_safe_prime(bits: int = 256) -> int:
    """Generate a safe prime p = 2q + 1 where q is also prime (used in DH, ElGamal)."""
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if sympy.isprime(p):
            return p


def generate_prime_pair(bits: int = 1024) -> tuple[int, int]:
    """Generate two distinct primes p, q of roughly bits/2 each (for RSA)."""
    half = bits // 2
    p = generate_prime(half)
    q = generate_prime(half)
    while q == p:
        q = generate_prime(half)
    return p, q


def find_primitive_root(p: int) -> int:
    """Find a primitive root (generator) mod p for a safe prime p."""
    if p == 2:
        return 1
    p1 = 2
    p2 = (p - 1) // 2

    for g in range(2, p):
        if pow(g, (p - 1) // p1, p) != 1 and pow(g, (p - 1) // p2, p) != 1:
            return g
    raise ValueError(f"No primitive root found for p={p}")

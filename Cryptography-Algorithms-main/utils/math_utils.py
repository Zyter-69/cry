"""
utils/math_utils.py
-------------------
Core mathematical primitives used across all cipher implementations.
"""

import math
import random


def gcd(a: int, b: int) -> int:
    """Euclidean GCD."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (gcd, x, y) where a*x + b*y = gcd."""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a: int, m: int) -> int:
    """Modular multiplicative inverse of a mod m. Raises ValueError if not coprime."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} has no inverse mod {m} (not coprime)")
    return x % m


def fast_pow(base: int, exp: int, mod: int) -> int:
    """Fast modular exponentiation: base^exp mod mod."""
    return pow(base, exp, mod)  # Python built-in is already optimized


def is_coprime(a: int, b: int) -> bool:
    return gcd(a, b) == 1


def lcm(a: int, b: int) -> int:
    return abs(a * b) // gcd(a, b)


def euler_totient(p: int, q: int) -> int:
    """Euler's totient for n = p*q where p, q are prime."""
    return (p - 1) * (q - 1)


def carmichael_lambda(p: int, q: int) -> int:
    """Carmichael's lambda for n = p*q (used in modern RSA)."""
    return lcm(p - 1, q - 1)

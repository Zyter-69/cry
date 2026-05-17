"""
utils/converter.py
------------------
Text ↔ bytes ↔ hex ↔ int conversion helpers used across modules.
"""


def text_to_bytes(text: str) -> bytes:
    return text.encode("utf-8")


def bytes_to_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def int_to_bytes(n: int, length: int = None) -> bytes:
    byte_len = length or ((n.bit_length() + 7) // 8)
    return n.to_bytes(byte_len, byteorder="big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")


def text_to_int(text: str) -> int:
    return bytes_to_int(text_to_bytes(text))


def int_to_text(n: int) -> str:
    return bytes_to_text(int_to_bytes(n))


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))

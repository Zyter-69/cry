import math
import struct
import hashlib
def pad(msg):
    msg_bytes = msg.encode('utf-8')
    length = len(msg_bytes) * 8
    msg_bytes += b'\x80'
    while len(msg_bytes) % 64 != 56:
        msg_bytes += b'\x00'
    msg_bytes += struct.pack('<Q', length) 
    return msg_bytes

def split(msg_bytes):
    return [msg_bytes[i:i+64] for i in range(0, len(msg_bytes), 64)]

def FF(a, b, c, d, M, s, i):
    F = (b & c) | ((~b & 0xFFFFFFFF) & d)          
    ti = int((2**32) * abs(math.sin(i + 1))) & 0xFFFFFFFF
    x = (a + F + M + ti) & 0xFFFFFFFF               
    rotated = ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF
    new_a = (b + rotated) & 0xFFFFFFFF              
    return new_a, b, c, d

def GG(a, b, c, d, M, s, i):
    G = (b & d) | (c & (~d & 0xFFFFFFFF))   
    ti = int((2**32) * abs(math.sin(i + 1))) & 0xFFFFFFFF
    x = (a + G + M + ti) & 0xFFFFFFFF
    rotated = ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF
    new_a = (b + rotated) & 0xFFFFFFFF
    return new_a, b, c, d

def HH(a, b, c, d, M, s, i):
    H = b ^ c ^ d                           
    ti = int((2**32) * abs(math.sin(i + 1))) & 0xFFFFFFFF
    x = (a + H + M + ti) & 0xFFFFFFFF
    rotated = ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF
    new_a = (b + rotated) & 0xFFFFFFFF
    return new_a, b, c, d

def II(a, b, c, d, M, s, i):
    I = c ^ (b | (~d & 0xFFFFFFFF))          
    ti = int((2**32) * abs(math.sin(i + 1))) & 0xFFFFFFFF
    x = (a + I + M + ti) & 0xFFFFFFFF
    rotated = ((x << s) | (x >> (32 - s))) & 0xFFFFFFFF
    new_a = (b + rotated) & 0xFFFFFFFF
    return new_a, b, c, d


def MD5(msg):
    msg_bytes = pad(msg)
    blocks = split(msg_bytes)
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476
    for block in blocks:
        a, b, c, d = A, B, C, D

        M = list(struct.unpack('<16I', block))
        
        for j in range(0, 16, 4):
            a, b, c, d = FF(a, b, c, d, M[j],   7,  j)
            d, a, b, c = FF(d, a, b, c, M[j+1], 12, j+1)
            c, d, a, b = FF(c, d, a, b, M[j+2], 17, j+2)
            b, c, d, a = FF(b, c, d, a, M[j+3], 22, j+3)

        i=1
        for j in range(0, 16, 4):
            a, b, c, d = GG(a, b, c, d, M[i],   5,  j+16)
            i=(i+5)%16
            d, a, b, c = GG(d, a, b, c, M[i],  9, j+1+16)
            i=(i+5)%16
            c, d, a, b = GG(c, d, a, b, M[i], 14, j+2+16)
            i=(i+5)%16
            b, c, d, a = GG(b, c, d, a, M[i], 20, j+3+16)
            i=(i+5)%16
        i=5
        for j in range(0, 16, 4):
            a, b, c, d = HH(a, b, c, d, M[i],   4,  j+32)
            i=(i+3)%16
            d, a, b, c = HH(d, a, b, c, M[i], 11, j+1+32)
            i=(i+3)%16
            c, d, a, b = HH(c, d, a, b, M[i], 16, j+2+32)
            i=(i+3)%16
            b, c, d, a = HH(b, c, d, a, M[i], 23, j+3+32)
            i=(i+3)%16
        i=0
        for j in range(0, 16, 4):
            a, b, c, d = II(a, b, c, d, M[i],   6,  j+48)
            i=(i+7)%16
            d, a, b, c = II(d, a, b, c, M[i], 10, j+1+48)
            i=(i+7)%16
            c, d, a, b = II(c, d, a, b, M[i], 15, j+2+48)
            i=(i+7)%16
            b, c, d, a = II(b, c, d, a, M[i], 21, j+3+48)
            i=(i+7)%16
        A = (A + a) & 0xFFFFFFFF
        B = (B + b) & 0xFFFFFFFF
        C = (C + c) & 0xFFFFFFFF
        D = (D + d) & 0xFFFFFFFF
        
    return struct.pack('<4I', A, B, C, D).hex()

hash_lib = hashlib.md5(b"test md5").hexdigest()
notre_hash = MD5("test md5")
print("Hash de la bibliothèque : ", hash_lib)
print("Notre hash : ", notre_hash)
if(hash_lib == notre_hash):
    print("Les deux hash sont identiques.")
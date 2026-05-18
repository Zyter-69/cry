#!/usr/bin/env python3
"""Test individual AES transformations"""

from aes import (SBOX, ISBOX, sub_bytes, inv_sub_bytes, 
                 shift_rows, inv_shift_rows, mix_columns, inv_mix_columns)

# Test 1: SubBytes and InvSubBytes
print("=" * 70)
print("Test 1: SubBytes and InvSubBytes")
print("=" * 70)

state = bytearray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
print(f"Original: {state.hex()}")

sub_bytes(state)
print(f"After SubBytes: {state.hex()}")

inv_sub_bytes(state)
print(f"After InvSubBytes: {state.hex()}")
print(f"Match: {state.hex() == '000f0e0d0c0b0a090807060504030201'}")

# Test 2: ShiftRows and InvShiftRows
print("\n" + "=" * 70)
print("Test 2: ShiftRows and InvShiftRows")
print("=" * 70)

state = bytearray([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
original = state.hex()
print(f"Original: {original}")

shift_rows(state)
print(f"After ShiftRows: {state.hex()}")

inv_shift_rows(state)
print(f"After InvShiftRows: {state.hex()}")
print(f"Match: {state.hex() == original}")

# Test 3: MixColumns and InvMixColumns
print("\n" + "=" * 70)
print("Test 3: MixColumns and InvMixColumns")
print("=" * 70)

state = bytearray([0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c,
                    0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6, 0xc6, 0xc6])
original = state.hex()
print(f"Original: {original}")

mix_columns(state)
print(f"After MixColumns: {state.hex()}")

inv_mix_columns(state)
print(f"After InvMixColumns: {state.hex()}")
print(f"Match: {state.hex() == original}")

# Test SBOX/ISBOX consistency
print("\n" + "=" * 70)
print("Test 4: SBOX and ISBOX Consistency")
print("=" * 70)

all_match = True
for i in range(256):
    sbox_val = SBOX[i]
    isbox_val = ISBOX[sbox_val]
    if isbox_val != i:
        print(f"Mismatch at index {i}: SBOX[{i}] = {sbox_val}, ISBOX[{sbox_val}] = {isbox_val}, expected {i}")
        all_match = False

print(f"SBOX/ISBOX consistent: {all_match}")

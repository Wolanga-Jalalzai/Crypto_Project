"""
des.py — A from-scratch implementation of the Data Encryption Standard (DES)
=============================================================================
Project   : DES Encryption Demonstrator
Student   : Wolanga Jalalzai (AIU24102344), BCS2B
Course    : CCS2243 — Cryptography Essential

This module implements DES exactly as specified in FIPS PUB 46-3, working at
the bit level so every stage of the algorithm (permutations, key schedule,
Feistel rounds, S-box substitution) is visible and can be traced. No
cryptographic library is used for the core cipher — only Python's standard
library. This is intentional: the assignment requires the student to
demonstrate understanding of the cryptographic process itself, not just
call a black-box function.

Supported:
  - Single-block DES encryption/decryption (64-bit block, 56-bit effective key)
  - ECB and CBC modes of operation
  - PKCS#7 padding
  - A "trace" mode that returns the full internal state after every round,
    used by des_gui.py to visualise the algorithm and by test_des.py to
    verify against known intermediate values.

References:
  National Institute of Standards and Technology. (1999). Data Encryption
    Standard (DES) (FIPS PUB 46-3). U.S. Department of Commerce.
  Stallings, W. (2017). Cryptography and Network Security: Principles and
    Practice (7th ed.). Pearson.
"""

from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import List

# ---------------------------------------------------------------------------
# 1. STANDARD DES TABLES (FIPS 46-3)
# ---------------------------------------------------------------------------

# Initial Permutation
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (Inverse of IP)
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion table: 32 bits -> 48 bits
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permutation applied after S-box substitution
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# Permuted Choice 1: 64-bit key -> 56 bits
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2: 56 bits -> 48-bit round key
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Per-round left-shift schedule for the 28-bit C/D halves
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# The eight S-boxes (each maps 6 bits -> 4 bits)
S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

BLOCK_SIZE = 8  # bytes (64 bits)
KEY_SIZE = 8     # bytes (64 bits, 56 effective)


# ---------------------------------------------------------------------------
# 2. BIT-LEVEL HELPERS
# ---------------------------------------------------------------------------

def bytes_to_bits(data: bytes) -> List[int]:
    """Convert a bytes object into a list of bits (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a list of bits (MSB first) back into a bytes object."""
    if len(bits) % 8 != 0:
        raise ValueError("Bit list length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)


def permute(bits: List[int], table: List[int]) -> List[int]:
    """Apply a DES permutation/selection table (1-indexed) to a bit list."""
    return [bits[i - 1] for i in table]


def xor_bits(a: List[int], b: List[int]) -> List[int]:
    return [x ^ y for x, y in zip(a, b)]


def left_rotate(bits: List[int], n: int) -> List[int]:
    return bits[n:] + bits[:n]


# ---------------------------------------------------------------------------
# 3. KEY SCHEDULE
# ---------------------------------------------------------------------------

def generate_round_keys(key8: bytes) -> List[List[int]]:
    """
    Derive the 16 x 48-bit round keys (K1..K16) from an 8-byte (64-bit) key.
    Every 8th bit of the input key is a parity bit and is dropped by PC-1,
    leaving 56 effective key bits.
    """
    if len(key8) != KEY_SIZE:
        raise ValueError(f"DES key must be exactly {KEY_SIZE} bytes (64 bits), "
                          f"got {len(key8)} bytes")
    key_bits = bytes_to_bits(key8)
    key56 = permute(key_bits, PC1)
    C, D = key56[:28], key56[28:]

    round_keys = []
    for shift in SHIFT_SCHEDULE:
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        round_keys.append(permute(C + D, PC2))
    return round_keys


# ---------------------------------------------------------------------------
# 4. FEISTEL (F) FUNCTION
# ---------------------------------------------------------------------------

def s_box_substitute(bits48: List[int]) -> List[int]:
    """Split 48 bits into eight 6-bit chunks and substitute via S-boxes -> 32 bits."""
    out = []
    for i in range(8):
        chunk = bits48[i * 6:(i + 1) * 6]
        row = (chunk[0] << 1) | chunk[5]           # outer bits -> row (0-3)
        col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]  # inner 4 bits -> col (0-15)
        val = S_BOXES[i][row][col]
        out.extend([(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1])
    return out


def feistel_f(R: List[int], round_key: List[int]) -> List[int]:
    """The DES round (Feistel) function: expand, XOR with key, S-box, permute."""
    expanded = permute(R, E)              # 32 -> 48
    xored = xor_bits(expanded, round_key)  # 48-bit XOR
    substituted = s_box_substitute(xored)  # 48 -> 32
    return permute(substituted, P)         # final P permutation


# ---------------------------------------------------------------------------
# 5. SINGLE-BLOCK ENCRYPT / DECRYPT (with optional trace)
# ---------------------------------------------------------------------------

@dataclass
class RoundTrace:
    round_no: int
    L: str
    R: str
    round_key: str
    f_output: str


@dataclass
class BlockTrace:
    plaintext_bits: str = ""
    after_ip: str = ""
    rounds: List[RoundTrace] = field(default_factory=list)
    pre_output_swap: str = ""
    ciphertext_bits: str = ""


def _bits_str(bits: List[int]) -> str:
    return "".join(str(b) for b in bits)


def des_encrypt_block(block8: bytes, round_keys: List[List[int]], trace: BlockTrace = None) -> bytes:
    """Encrypt exactly one 64-bit (8-byte) block using the 16 round keys."""
    if len(block8) != BLOCK_SIZE:
        raise ValueError(f"DES block must be exactly {BLOCK_SIZE} bytes")

    bits = bytes_to_bits(block8)
    if trace is not None:
        trace.plaintext_bits = _bits_str(bits)

    bits = permute(bits, IP)
    if trace is not None:
        trace.after_ip = _bits_str(bits)

    L, R = bits[:32], bits[32:]
    for i in range(16):
        f_out = feistel_f(R, round_keys[i])
        newR = xor_bits(L, f_out)
        if trace is not None:
            trace.rounds.append(RoundTrace(
                round_no=i + 1,
                L=_bits_str(L), R=_bits_str(newR),
                round_key=_bits_str(round_keys[i]),
                f_output=_bits_str(f_out),
            ))
        L, R = R, newR

    if trace is not None:
        trace.pre_output_swap = _bits_str(R + L)

    preoutput = R + L  # final swap (no swap after round 16)
    ciphertext_bits = permute(preoutput, FP)
    if trace is not None:
        trace.ciphertext_bits = _bits_str(ciphertext_bits)

    return bits_to_bytes(ciphertext_bits)


def des_decrypt_block(block8: bytes, round_keys: List[List[int]], trace: BlockTrace = None) -> bytes:
    """Decrypt one 64-bit block. Identical structure to encryption but with
    round keys applied in reverse order (K16 .. K1) — the property that makes
    DES's Feistel structure self-inverting."""
    return des_encrypt_block(block8, list(reversed(round_keys)), trace)


# ---------------------------------------------------------------------------
# 6. PADDING (PKCS#7)
# ---------------------------------------------------------------------------

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# 7. MODES OF OPERATION: ECB and CBC
# ---------------------------------------------------------------------------

def encrypt_ecb(plaintext: bytes, key8: bytes) -> bytes:
    round_keys = generate_round_keys(key8)
    padded = pkcs7_pad(plaintext)
    out = bytearray()
    for i in range(0, len(padded), BLOCK_SIZE):
        out += des_encrypt_block(padded[i:i + BLOCK_SIZE], round_keys)
    return bytes(out)


def decrypt_ecb(ciphertext: bytes, key8: bytes) -> bytes:
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a multiple of the block size")
    round_keys = generate_round_keys(key8)
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        out += des_decrypt_block(ciphertext[i:i + BLOCK_SIZE], round_keys)
    return bytes(pkcs7_unpad(bytes(out)))


def encrypt_cbc(plaintext: bytes, key8: bytes, iv8: bytes = None) -> bytes:
    """Returns IV (8 bytes) prepended to ciphertext."""
    if iv8 is None:
        iv8 = os.urandom(BLOCK_SIZE)
    if len(iv8) != BLOCK_SIZE:
        raise ValueError(f"IV must be exactly {BLOCK_SIZE} bytes")
    round_keys = generate_round_keys(key8)
    padded = pkcs7_pad(plaintext)
    out = bytearray(iv8)
    prev = iv8
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = des_encrypt_block(xored, round_keys)
        out += enc
        prev = enc
    return bytes(out)


def decrypt_cbc(ciphertext: bytes, key8: bytes) -> bytes:
    """Expects IV (8 bytes) prepended to ciphertext, as produced by encrypt_cbc."""
    if len(ciphertext) < BLOCK_SIZE or (len(ciphertext) - BLOCK_SIZE) % BLOCK_SIZE != 0:
        raise ValueError("Invalid CBC ciphertext length")
    round_keys = generate_round_keys(key8)
    iv8, body = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]
    out = bytearray()
    prev = iv8
    for i in range(0, len(body), BLOCK_SIZE):
        block = body[i:i + BLOCK_SIZE]
        dec = des_decrypt_block(block, round_keys)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(pkcs7_unpad(bytes(out)))


# ---------------------------------------------------------------------------
# 8. CONVENIENCE / DEMO ENTRY POINT
# ---------------------------------------------------------------------------

def encrypt_text(plaintext: str, key_hex: str, mode: str = "ECB", iv_hex: str = None) -> str:
    """High-level helper used by the GUI: text in, hex ciphertext out."""
    key8 = bytes.fromhex(key_hex.strip())
    data = plaintext.encode("utf-8")
    if mode.upper() == "ECB":
        ct = encrypt_ecb(data, key8)
    elif mode.upper() == "CBC":
        iv8 = bytes.fromhex(iv_hex.strip()) if iv_hex else None
        ct = encrypt_cbc(data, key8, iv8)
    else:
        raise ValueError("mode must be 'ECB' or 'CBC'")
    return ct.hex()


def decrypt_text(cipher_hex: str, key_hex: str, mode: str = "ECB") -> str:
    key8 = bytes.fromhex(key_hex.strip())
    ct = bytes.fromhex(cipher_hex.strip())
    if mode.upper() == "ECB":
        pt = decrypt_ecb(ct, key8)
    elif mode.upper() == "CBC":
        pt = decrypt_cbc(ct, key8)
    else:
        raise ValueError("mode must be 'ECB' or 'CBC'")
    return pt.decode("utf-8", errors="replace")


if __name__ == "__main__":
    # Quick manual smoke test using the classic FIPS 46-3 example
    key = bytes.fromhex("133457799BBCDFF1")
    pt = bytes.fromhex("0123456789ABCDEF")
    rks = generate_round_keys(key)
    ct = des_encrypt_block(pt, rks)
    print("Plaintext :", pt.hex().upper())
    print("Key       :", key.hex().upper())
    print("Ciphertext:", ct.hex().upper(), " (expected 85E813540F0AB405)")
    back = des_decrypt_block(ct, rks)
    print("Decrypted :", back.hex().upper())
    assert back == pt
    print("Round-trip OK")

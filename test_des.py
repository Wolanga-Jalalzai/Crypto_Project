"""
test_des.py — Test suite for the from-scratch DES implementation (des.py)
============================================================================
Project: DES Encryption Demonstrator | Wolanga Jalalzai (AIU24102344) BCS2B

Covers:
  1. Known-Answer Tests (KATs) against official FIPS 46-3 / NIST test vectors
  2. Round-trip correctness (encrypt -> decrypt == original) for random data
  3. Edge cases: empty message, single-byte message, exact multiple of block
     size, non-ASCII (UTF-8) text, weak/semi-weak keys
  4. ECB vs CBC behavioural difference (identical plaintext blocks)
  5. Negative/error-handling tests (wrong key length, tampered ciphertext,
     invalid padding)

Run with:  python3 -m pytest test_des.py -v
       or: python3 test_des.py            (falls back to a plain runner)
"""

import os
import sys
import time
import unittest

import des


# ---------------------------------------------------------------------------
# 1. KNOWN-ANSWER TESTS (KAT) — official FIPS test vectors
# ---------------------------------------------------------------------------
class TestKnownAnswer(unittest.TestCase):
    """These vectors are widely published in FIPS 46-3 and NIST Special
    Publication 800-17 and are the standard way to validate a from-scratch
    DES implementation."""

    def test_fips_example_vector(self):
        key = bytes.fromhex("133457799BBCDFF1")
        pt = bytes.fromhex("0123456789ABCDEF")
        expected_ct = bytes.fromhex("85E813540F0AB405")
        rks = des.generate_round_keys(key)
        ct = des.des_encrypt_block(pt, rks)
        self.assertEqual(ct.hex().upper(), expected_ct.hex().upper())
        # and it must decrypt back correctly
        self.assertEqual(des.des_decrypt_block(ct, rks), pt)

    def test_all_zero_key_and_plaintext(self):
        key = bytes(8)
        pt = bytes(8)
        expected_ct = bytes.fromhex("8CA64DE9C1B123A7")
        rks = des.generate_round_keys(key)
        ct = des.des_encrypt_block(pt, rks)
        self.assertEqual(ct.hex().upper(), expected_ct.hex().upper())

    def test_all_one_bits(self):
        key = bytes.fromhex("FFFFFFFFFFFFFFFF")
        pt = bytes.fromhex("FFFFFFFFFFFFFFFF")
        expected_ct = bytes.fromhex("7359B2163E4EDC58")
        rks = des.generate_round_keys(key)
        ct = des.des_encrypt_block(pt, rks)
        self.assertEqual(ct.hex().upper(), expected_ct.hex().upper())

    def test_nist_variable_plaintext_sample(self):
        # NIST SP 800-17 "Variable Plaintext Known Answer Test", first entry
        key = bytes.fromhex("0101010101010101")
        pt = bytes.fromhex("8000000000000000")
        expected_ct = bytes.fromhex("95F8A5E5DD31D900")
        rks = des.generate_round_keys(key)
        ct = des.des_encrypt_block(pt, rks)
        self.assertEqual(ct.hex().upper(), expected_ct.hex().upper())


# ---------------------------------------------------------------------------
# 2. ROUND-TRIP CORRECTNESS
# ---------------------------------------------------------------------------
class TestRoundTrip(unittest.TestCase):

    def test_random_blocks_round_trip(self):
        for _ in range(200):
            key = os.urandom(8)
            pt = os.urandom(8)
            rks = des.generate_round_keys(key)
            ct = des.des_encrypt_block(pt, rks)
            self.assertEqual(des.des_decrypt_block(ct, rks), pt)

    def test_ecb_round_trip_various_lengths(self):
        key = os.urandom(8)
        for length in [0, 1, 7, 8, 9, 16, 63, 64, 100]:
            data = os.urandom(length)
            ct = des.encrypt_ecb(data, key)
            self.assertEqual(des.decrypt_ecb(ct, key), data)

    def test_cbc_round_trip_various_lengths(self):
        key = os.urandom(8)
        for length in [0, 1, 7, 8, 9, 16, 63, 64, 100]:
            data = os.urandom(length)
            ct = des.encrypt_cbc(data, key)
            self.assertEqual(des.decrypt_cbc(ct, key), data)

    def test_text_helper_round_trip(self):
        key_hex = "133457799BBCDFF1"
        message = "Cryptography Essential (CCS2243) — DES Demo ✅ 加密测试"
        ct_hex = des.encrypt_text(message, key_hex, mode="ECB")
        recovered = des.decrypt_text(ct_hex, key_hex, mode="ECB")
        self.assertEqual(recovered, message)


# ---------------------------------------------------------------------------
# 3. EDGE CASES
# ---------------------------------------------------------------------------
class TestEdgeCases(unittest.TestCase):

    def test_empty_message(self):
        key = os.urandom(8)
        ct = des.encrypt_ecb(b"", key)
        self.assertEqual(len(ct), des.BLOCK_SIZE)  # one full padding block
        self.assertEqual(des.decrypt_ecb(ct, key), b"")

    def test_message_exact_multiple_of_block_size_still_pads(self):
        # PKCS#7 always adds a full padding block when input is already a
        # multiple of block size, to keep padding unambiguous.
        key = os.urandom(8)
        data = os.urandom(16)  # exactly two blocks
        ct = des.encrypt_ecb(data, key)
        self.assertEqual(len(ct), 24)  # 16 + one padding block
        self.assertEqual(des.decrypt_ecb(ct, key), data)

    def test_single_byte_message(self):
        key = os.urandom(8)
        ct = des.encrypt_ecb(b"A", key)
        self.assertEqual(des.decrypt_ecb(ct, key), b"A")

    def test_weak_key_des_weak_key_1(self):
        # 0x0101010101010101 is one of DES's four documented weak keys:
        # encrypting twice with it returns the original plaintext.
        weak_key = bytes.fromhex("0101010101010101")
        pt = os.urandom(8)
        rks = des.generate_round_keys(weak_key)
        once = des.des_encrypt_block(pt, rks)
        twice = des.des_encrypt_block(once, rks)
        self.assertEqual(twice, pt)

    def test_wrong_key_length_rejected(self):
        with self.assertRaises(ValueError):
            des.generate_round_keys(b"short")

    def test_ciphertext_not_multiple_of_block_size_rejected(self):
        with self.assertRaises(ValueError):
            des.decrypt_ecb(b"1234567", os.urandom(8))

    def test_tampered_ciphertext_detected_via_bad_padding(self):
        key = os.urandom(8)
        ct = bytearray(des.encrypt_ecb(b"Hello DES", key))
        ct[-1] ^= 0xFF  # flip bits in the last (padding) byte after decryption
        with self.assertRaises(ValueError):
            des.decrypt_ecb(bytes(ct), key)


# ---------------------------------------------------------------------------
# 4. MODE-OF-OPERATION BEHAVIOUR (ECB vs CBC)
# ---------------------------------------------------------------------------
class TestModesBehaviour(unittest.TestCase):

    def test_ecb_leaks_repeated_block_patterns(self):
        key = os.urandom(8)
        block = b"SAMEBLOK"          # exactly 8 bytes
        data = block * 4              # 4 identical plaintext blocks
        ct = des.encrypt_ecb(data, key)
        cipher_blocks = [ct[i:i + 8] for i in range(0, 32, 8)]
        # ECB weakness: identical plaintext blocks -> identical ciphertext blocks
        self.assertEqual(len(set(cipher_blocks)), 1)

    def test_cbc_hides_repeated_block_patterns(self):
        key = os.urandom(8)
        block = b"SAMEBLOK"
        data = block * 4
        ct = des.encrypt_cbc(data, key)
        body = ct[8:]  # strip IV
        cipher_blocks = [body[i:i + 8] for i in range(0, 32, 8)]
        # CBC strength: identical plaintext blocks -> DIFFERENT ciphertext blocks
        self.assertEqual(len(set(cipher_blocks)), 4)

    def test_cbc_different_iv_gives_different_ciphertext(self):
        key = os.urandom(8)
        data = b"Same plaintext message, twice."
        ct1 = des.encrypt_cbc(data, key, iv8=os.urandom(8))
        ct2 = des.encrypt_cbc(data, key, iv8=os.urandom(8))
        self.assertNotEqual(ct1, ct2)
        self.assertEqual(des.decrypt_cbc(ct1, key), data)
        self.assertEqual(des.decrypt_cbc(ct2, key), data)


# ---------------------------------------------------------------------------
# 5. PERFORMANCE (lightweight, informational — printed, not asserted)
# ---------------------------------------------------------------------------
class TestPerformance(unittest.TestCase):

    def test_throughput_report(self):
        key = os.urandom(8)
        data = os.urandom(1024 * 100)  # 100 KB
        start = time.perf_counter()
        ct = des.encrypt_ecb(data, key)
        enc_time = time.perf_counter() - start

        start = time.perf_counter()
        des.decrypt_ecb(ct, key)
        dec_time = time.perf_counter() - start

        kb = len(data) / 1024
        print(f"\n[Performance] Encrypted {kb:.0f} KB in {enc_time:.4f}s "
              f"({kb / enc_time:.1f} KB/s) — pure-Python, educational build.")
        print(f"[Performance] Decrypted {kb:.0f} KB in {dec_time:.4f}s "
              f"({kb / dec_time:.1f} KB/s).")
        self.assertLess(enc_time, 30, "Sanity bound only — not a hard requirement")


if __name__ == "__main__":
    unittest.main(verbosity=2)

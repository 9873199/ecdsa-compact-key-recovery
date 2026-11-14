# -*- coding: utf-8 -*-
"""
Tests for the recoverable compact signature interface
(:func:`SigningKey.sign_digest_recoverable_compact`,
:func:`VerifyingKey.verify_digest_recoverable_compact` and
:func:`VerifyingKey.from_recoverable_compact_signature`).

To avoid the implementation attesting to itself, the expected values here
are computed with a small, independent, affine-coordinate secp256k1
implementation (see the module level helpers below) that shares no code
with the library, and the results are cross-checked against the classic
:func:`VerifyingKey.verify_digest` interface.
"""

from __future__ import print_function

import hashlib

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from six import int2byte, indexbytes

from .keys import SigningKey, VerifyingKey, BadSignatureError, BadDigestError
from .curves import SECP256k1, NIST256p
from .util import string_to_number, number_to_string, sigencode_string
from . import rfc6979

# ---------------------------------------------------------------------------
# Independent secp256k1 implementation (affine coordinates, Fermat inverse)
# used only to compute expected values for the tests.
# ---------------------------------------------------------------------------

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _pt_add(p1, p2):
    """Add two affine points; the point at infinity is None."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * pow(2 * y1, _P - 2, _P) % _P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % _P, _P - 2, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pt_mul(k, point):
    """Multiply an affine point by an integer; None is the infinity."""
    result = None
    addend = point
    k %= _N
    while k:
        if k & 1:
            result = _pt_add(result, addend)
        addend = _pt_add(addend, addend)
        k >>= 1
    return result


def _pt_neg(point):
    if point is None:
        return None
    return (point[0], (-point[1]) % _P)


def _sqrt_mod(a):
    """Modular square root, or None if a is not a quadratic residue."""
    y = pow(a, (_P + 1) // 4, _P)  # secp256k1 prime is 3 mod 4
    if (y * y - a) % _P != 0:
        return None
    return y


def _independent_recover(rec_id, r, s, e):
    """Recover the public key point, returns affine tuple or None."""
    x = r + (rec_id >> 1) * _N
    if x >= _P:
        return None
    y = _sqrt_mod((pow(x, 3, _P) + 7) % _P)
    if y is None:
        return None
    if (y & 1) != (rec_id & 1):
        y = _P - y
    sR = _pt_mul(s, (x, y))
    eG = _pt_mul(e, _G)
    return _pt_mul(pow(r, _N - 2, _N), _pt_add(sR, _pt_neg(eG)))


def _vk_point(vk):
    """Public point of a VerifyingKey as an affine tuple."""
    point = vk.pubkey.point
    return (point.x(), point.y())


# ---------------------------------------------------------------------------
# Fixed test key and digest (generated offline for these tests only)
# ---------------------------------------------------------------------------

_SECEXP = 0x9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60
_DIGEST = hashlib.sha256(
    b"python-ecdsa recoverable compact test vector"
).digest()
# signature produced by the implementation under test for the above key and
# digest, verified here against the independent implementation
_FROZEN_SIG = bytes(
    bytearray.fromhex(
        "0009ca3b99a87f7647978033eb301ccd5a3bcbf4216866c7b366f28e3dd4c24e14"
        "314ded2a5077e48a480dc635ec7d088df62b1274df10d4d96fdde0a09b5f3ee9"
    )
)
_FROZEN_PUB_COMPRESSED = bytes(
    bytearray.fromhex(
        "028db55b05db86c0b1786ca49f095d76344c9e6056b2f02701a7e7f3c20aabfd91"
    )
)


def _make_key():
    return SigningKey.from_secret_exponent(
        _SECEXP, curve=SECP256k1, hashfunc=hashlib.sha256
    )


class TestSignRecoverableCompact(unittest.TestCase):
    def setUp(self):
        self.sk = _make_key()
        self.vk = self.sk.get_verifying_key()
        self.digest = _DIGEST

    def test_format_and_low_s(self):
        sig = self.sk.sign_digest_recoverable_compact(self.digest)
        self.assertEqual(len(sig), 65)
        rec_id = indexbytes(sig, 0)
        self.assertIn(rec_id, (0, 1, 2, 3))
        r = string_to_number(sig[1:33])
        s = string_to_number(sig[33:65])
        self.assertGreaterEqual(r, 1)
        self.assertLess(r, _N)
        self.assertGreaterEqual(s, 1)
        self.assertLessEqual(s, _N // 2)

    def test_deterministic(self):
        sig1 = self.sk.sign_digest_recoverable_compact(self.digest)
        sig2 = self.sk.sign_digest_recoverable_compact(self.digest)
        self.assertEqual(sig1, sig2)

    def test_uses_rfc6979_path(self):
        # r (and s up to the low-S normalisation) must match the existing
        # deterministic RFC6979 signing path
        sig = self.sk.sign_digest_recoverable_compact(self.digest)
        classic = self.sk.sign_digest_deterministic(
            self.digest, sigencode=sigencode_string
        )
        r = string_to_number(sig[1:33])
        s = string_to_number(sig[33:65])
        r_classic = string_to_number(classic[:32])
        s_classic = string_to_number(classic[32:])
        self.assertEqual(r, r_classic)
        self.assertIn(s, (s_classic, _N - s_classic))

    def test_recid_matches_independent_ephemeral_point(self):
        # derive the same RFC6979 nonce and compute k*G with the
        # independent implementation, then check the recovery id bits
        k = rfc6979.generate_k(_N, _SECEXP, hashlib.sha256, self.digest)
        Rx, Ry = _pt_mul(k, _G)
        sig = self.sk.sign_digest_recoverable_compact(self.digest)
        rec_id = indexbytes(sig, 0)
        s = string_to_number(sig[33:65])
        r = string_to_number(sig[1:33])
        self.assertEqual(r, Rx % _N)
        # the raw RFC6979 signature may be high-S; the implementation must
        # have flipped the parity bit together with s
        classic = self.sk.sign_digest_deterministic(
            self.digest, sigencode=sigencode_string
        )
        s_raw = string_to_number(classic[32:])
        expected_recid = (Ry & 1) | (2 if Rx >= _N else 0)
        if s_raw > _N // 2:
            self.assertEqual(s, _N - s_raw)
            expected_recid ^= 1
        else:
            self.assertEqual(s, s_raw)
        self.assertEqual(rec_id, expected_recid)

    def test_digest_length_enforced(self):
        for bad in (b"", b"\x01" * 31, b"\x01" * 33, b"\x01" * 64):
            with self.assertRaises(BadDigestError):
                self.sk.sign_digest_recoverable_compact(bad)

    def test_other_curve_rejected(self):
        sk = SigningKey.generate(curve=NIST256p)
        with self.assertRaises(ValueError):
            sk.sign_digest_recoverable_compact(self.digest)


class TestVerifyAndRecoverCompact(unittest.TestCase):
    def setUp(self):
        self.sk = _make_key()
        self.vk = self.sk.get_verifying_key()
        self.digest = _DIGEST
        self.sig = self.sk.sign_digest_recoverable_compact(self.digest)

    def test_roundtrip(self):
        self.assertTrue(
            self.vk.verify_digest_recoverable_compact(self.sig, self.digest)
        )

    def test_recover_roundtrip(self):
        vk2 = VerifyingKey.from_recoverable_compact_signature(
            self.sig, self.digest
        )
        self.assertEqual(vk2, self.vk)
        self.assertEqual(vk2.to_string(), self.vk.to_string())

    def test_independent_recovery_matches(self):
        # recover the key with the independent implementation and compare
        # against the library's public point
        rec_id = indexbytes(self.sig, 0)
        r = string_to_number(self.sig[1:33])
        s = string_to_number(self.sig[33:65])
        e = string_to_number(self.digest)
        expected = _independent_recover(rec_id, r, s, e)
        self.assertIsNotNone(expected)
        self.assertEqual(expected, _vk_point(self.vk))

    def test_cross_check_classic_verify(self):
        # the r||s part of the compact signature must pass the classic
        # verification interface
        self.assertTrue(self.vk.verify_digest(self.sig[1:], self.digest))

    def test_tampered_recovery_id_rejected(self):
        rec_id = indexbytes(self.sig, 0)
        for bad_id in range(4):
            if bad_id == rec_id:
                continue
            bad = int2byte(bad_id) + self.sig[1:]
            with self.assertRaises(BadSignatureError):
                self.vk.verify_digest_recoverable_compact(bad, self.digest)

    def test_tampered_r_rejected(self):
        bad = bytearray(self.sig)
        bad[20] ^= 0x01
        with self.assertRaises(BadSignatureError):
            self.vk.verify_digest_recoverable_compact(bytes(bad), self.digest)

    def test_tampered_s_rejected(self):
        bad = bytearray(self.sig)
        bad[40] ^= 0x01
        with self.assertRaises(BadSignatureError):
            self.vk.verify_digest_recoverable_compact(bytes(bad), self.digest)

    def test_different_digest_rejected(self):
        other = hashlib.sha256(b"different message").digest()
        with self.assertRaises(BadSignatureError):
            self.vk.verify_digest_recoverable_compact(self.sig, other)
        # recovery with a different digest must also yield a different key
        vk2 = VerifyingKey.from_recoverable_compact_signature(self.sig, other)
        self.assertNotEqual(vk2.to_string(), self.vk.to_string())

    def test_high_s_rejected(self):
        rec_id = indexbytes(self.sig, 0)
        r = string_to_number(self.sig[1:33])
        s = string_to_number(self.sig[33:65])
        s_high = _N - s
        # the high-S variant with the parity bit flipped is a valid ECDSA
        # signature for the same key (classic interface accepts it)...
        raw_high = self.sig[1:33] + number_to_string(s_high, _N)
        self.assertTrue(self.vk.verify_digest(raw_high, self.digest))
        # ...and independently recovers the same key with the flipped bit
        e = string_to_number(self.digest)
        self.assertEqual(
            _independent_recover(rec_id ^ 1, r, s_high, e),
            _vk_point(self.vk),
        )
        # but the compact interface rejects high-S
        high_sig = int2byte(rec_id ^ 1) + raw_high
        with self.assertRaises(BadSignatureError):
            self.vk.verify_digest_recoverable_compact(high_sig, self.digest)

    def test_s_flip_without_recid_flip_recovers_other_key(self):
        # sanity check of the independent implementation: negating s
        # without flipping the parity bit must recover a different key
        rec_id = indexbytes(self.sig, 0)
        r = string_to_number(self.sig[1:33])
        s = string_to_number(self.sig[33:65])
        e = string_to_number(self.digest)
        other = _independent_recover(rec_id, r, _N - s, e)
        self.assertIsNotNone(other)
        self.assertNotEqual(other, _vk_point(self.vk))

    def test_malformed_signature_lengths(self):
        for bad in (
            b"",
            self.sig[:1],
            self.sig[:64],
            self.sig + b"\x00",
            self.sig * 2,
        ):
            with self.assertRaises(BadSignatureError):
                self.vk.verify_digest_recoverable_compact(bad, self.digest)
            with self.assertRaises(BadSignatureError):
                VerifyingKey.from_recoverable_compact_signature(
                    bad, self.digest
                )

    def test_malformed_digest_lengths(self):
        for bad in (b"", self.digest[:31], self.digest + b"\x00"):
            with self.assertRaises(BadDigestError):
                self.vk.verify_digest_recoverable_compact(self.sig, bad)
            with self.assertRaises(BadDigestError):
                VerifyingKey.from_recoverable_compact_signature(self.sig, bad)

    def test_recovery_id_out_of_range(self):
        for bad_id in (4, 5, 27, 255):
            bad = int2byte(bad_id) + self.sig[1:]
            with self.assertRaises(BadSignatureError):
                self.vk.verify_digest_recoverable_compact(bad, self.digest)

    def test_r_s_out_of_range(self):
        r = self.sig[1:33]
        s = self.sig[33:65]
        zero = b"\x00" * 32
        n_enc = number_to_string(_N, _N)
        for bad_r, bad_s in (
            (zero, s),
            (n_enc, s),
            (r, zero),
            (r, n_enc),
        ):
            bad = self.sig[:1] + bad_r + bad_s
            with self.assertRaises(BadSignatureError):
                self.vk.verify_digest_recoverable_compact(bad, self.digest)

    def test_other_curve_rejected(self):
        vk = SigningKey.generate(curve=NIST256p).get_verifying_key()
        with self.assertRaises(ValueError):
            vk.verify_digest_recoverable_compact(self.sig, self.digest)


class TestRecoveryIdBranches(unittest.TestCase):
    """Tests for the x = r + j*n branches and edge cases of recovery."""

    def setUp(self):
        self.digest = _DIGEST
        self.e = string_to_number(self.digest)

    def _vk_from_affine(self, point):
        enc = (
            b"\x04"
            + number_to_string(point[0], _N)
            + number_to_string(point[1], _N)
        )
        return VerifyingKey.from_string(
            enc, curve=SECP256k1, hashfunc=hashlib.sha256
        )

    def _find_r_with_curve_point(self, j, start=1):
        """Smallest r >= start with x = r + j*n on the curve, x < p."""
        r = start
        while True:
            x = r + j * _N
            if x >= _P:
                raise ValueError("no such r")
            if _sqrt_mod((pow(x, 3, _P) + 7) % _P) is not None:
                return r
            r += 1

    def test_x_equals_r_plus_n_branch(self):
        # synthetically construct signatures whose ephemeral point uses
        # the x = r + n branch (recovery ids 2 and 3); the expected public
        # keys are computed with the independent implementation
        for rec_id in (2, 3):
            r = self._find_r_with_curve_point(j=1)
            x = r + _N
            self.assertLess(x, _P)
            y = _sqrt_mod((pow(x, 3, _P) + 7) % _P)
            if (y & 1) != (rec_id & 1):
                y = _P - y
            s = 0x12345  # arbitrary, well below n/2
            # the key that this signature belongs to
            point = _pt_mul(
                pow(r, _N - 2, _N),
                _pt_add(_pt_mul(s, (x, y)), _pt_neg(_pt_mul(self.e, _G))),
            )
            self.assertIsNotNone(point)
            vk = self._vk_from_affine(point)
            sig = (
                int2byte(rec_id)
                + number_to_string(r, _N)
                + number_to_string(s, _N)
            )
            # the new interfaces must accept and recover the key
            self.assertTrue(
                vk.verify_digest_recoverable_compact(sig, self.digest)
            )
            vk2 = VerifyingKey.from_recoverable_compact_signature(
                sig, self.digest
            )
            self.assertEqual(vk2.to_string(), vk.to_string())
            # cross-check with the classic verification interface
            self.assertTrue(vk.verify_digest(sig[1:], self.digest))
            # and the library recovery must agree with the independent one
            self.assertEqual(
                _independent_recover(rec_id, r, s, self.e), _vk_point(vk2)
            )

    def test_x_outside_field_rejected(self):
        # with j = 1 and r close to n, x = r + n exceeds the field prime
        r = _N - 1
        self.assertGreaterEqual(r + _N, _P)
        s = 0x12345
        sig = int2byte(2) + number_to_string(r, _N) + number_to_string(s, _N)
        with self.assertRaises(BadSignatureError):
            VerifyingKey.from_recoverable_compact_signature(sig, self.digest)

    def test_x_not_on_curve_rejected(self):
        # find an r whose x = r has no curve point
        r = 1
        while _sqrt_mod((pow(r, 3, _P) + 7) % _P) is not None:
            r += 1
        s = 0x12345
        sig = int2byte(0) + number_to_string(r, _N) + number_to_string(s, _N)
        with self.assertRaises(BadSignatureError):
            VerifyingKey.from_recoverable_compact_signature(sig, self.digest)

    def test_recovered_infinity_rejected(self):
        # craft a signature with s*R = e*G so that the recovered public
        # key is the point at infinity: pick a nonce k, set R = k*G and
        # s = e * k^-1 mod n
        k = 2
        while True:
            Rx, Ry = _pt_mul(k, _G)
            r = Rx % _N
            if r == 0:
                k += 1
                continue
            rec_id = (Ry & 1) | (2 if Rx >= _N else 0)
            s = self.e * pow(k, _N - 2, _N) % _N
            if 1 <= s <= _N // 2:
                break
            k += 1
        # confirm with the independent implementation that the recovery
        # really hits the point at infinity
        self.assertIsNone(_independent_recover(rec_id, r, s, self.e))
        sig = (
            int2byte(rec_id)
            + number_to_string(r, _N)
            + number_to_string(s, _N)
        )
        with self.assertRaises(BadSignatureError):
            VerifyingKey.from_recoverable_compact_signature(sig, self.digest)


class TestFrozenVector(unittest.TestCase):
    """Regression vector frozen at test-creation time."""

    def test_vector(self):
        sk = _make_key()
        vk = sk.get_verifying_key()
        self.assertEqual(vk.to_string("compressed"), _FROZEN_PUB_COMPRESSED)
        sig = sk.sign_digest_recoverable_compact(_DIGEST)
        self.assertEqual(sig, _FROZEN_SIG)
        # the frozen signature must verify and recover the frozen key
        self.assertTrue(
            vk.verify_digest_recoverable_compact(_FROZEN_SIG, _DIGEST)
        )
        vk2 = VerifyingKey.from_recoverable_compact_signature(
            _FROZEN_SIG, _DIGEST
        )
        self.assertEqual(vk2.to_string("compressed"), _FROZEN_PUB_COMPRESSED)
        # and it must check out against the independent implementation
        rec_id = indexbytes(_FROZEN_SIG, 0)
        r = string_to_number(_FROZEN_SIG[1:33])
        s = string_to_number(_FROZEN_SIG[33:65])
        self.assertEqual(
            _independent_recover(rec_id, r, s, string_to_number(_DIGEST)),
            _vk_point(vk),
        )


class TestOldInterfacesUnaffected(unittest.TestCase):
    def setUp(self):
        self.sk = _make_key()
        self.vk = self.sk.get_verifying_key()
        self.digest = _DIGEST

    def test_old_recovery_interface(self):
        # the pre-existing public key recovery interface must keep working
        # with the same r||s values the compact format carries
        sig = self.sk.sign_digest_recoverable_compact(self.digest)
        vks = VerifyingKey.from_public_key_recovery_with_digest(
            sig[1:], self.digest, SECP256k1, hashfunc=hashlib.sha256
        )
        self.assertIn(self.vk.to_string(), [k.to_string() for k in vks])

    def test_classic_sign_verify_unaffected(self):
        sig = self.sk.sign_digest_deterministic(self.digest)
        self.assertTrue(self.vk.verify_digest(sig, self.digest))


if __name__ == "__main__":
    unittest.main()

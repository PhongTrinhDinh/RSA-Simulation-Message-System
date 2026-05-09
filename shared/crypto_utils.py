"""
crypto_utils.py — Module tiện ích mật mã RSA cho Sandbox OTT.

Cung cấp:
- Sinh cặp khóa RSA với nhiều chế độ (standard, small-d, small-e, close-primes, common-modulus)
- Mã hóa / Giải mã hỗ trợ 3 padding modes: OAEP, PKCS1_v1.5, none (textbook RSA)
- Serialize / Deserialize khóa PEM
- Fingerprint SHA-256 cho public key
"""

import os
import math
import hashlib
import random
from typing import Optional, Tuple, Dict, Any

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Util.number import (
    getPrime, inverse, GCD, bytes_to_long, long_to_bytes, isPrime
)
import gmpy2


# ──────────────────────────────────────────────
# Key Generation
# ──────────────────────────────────────────────

def generate_rsa_keypair(
    key_bits: int = 2048,
    e: int = 65537,
    prime_gap: str = "normal",
) -> Dict[str, Any]:
    """
    Sinh cặp khóa RSA với nhiều chế độ khác nhau.

    Args:
        key_bits: Độ dài khóa (bit)
        e: Số mũ công khai
        prime_gap: "normal" hoặc "small" (p, q gần nhau → dễ bị Fermat factoring)

    Returns:
        Dict chứa n, e, d, p, q, key_bits, pem_public, pem_private
    """

    if prime_gap == "small":
        # Factor-vulnerable: p, q gần nhau
        p, q, n, d = _generate_close_prime_key(key_bits, e)

    else:
        # Standard RSA
        half_bits = key_bits // 2
        while True:
            p = getPrime(half_bits)
            q = getPrime(half_bits)
            if p == q:
                continue
            phi_n = (p - 1) * (q - 1)
            if GCD(e, phi_n) == 1:
                break
        n = p * q
        d = int(inverse(e, phi_n))

    # Tạo RSA key object
    key = RSA.construct((n, e, d, p, q))

    return {
        "n": n,
        "e": e,
        "d": d,
        "p": p,
        "q": q,
        "key_bits": key_bits,
        "pem_public": key.publickey().export_key("PEM").decode(),
        "pem_private": key.export_key("PEM").decode(),
        "fingerprint": key_fingerprint(key.publickey().export_key("PEM").decode()),
    }


def _generate_close_prime_key(key_bits: int, e: int) -> Tuple[int, int, int, int]:
    """Sinh khóa RSA với p, q gần nhau (Factor-vulnerable qua Fermat)."""
    import sympy
    half_bits = key_bits // 2

    p = getPrime(half_bits)
    # Tìm q là số nguyên tố kế tiếp gần p
    q = int(sympy.nextprime(p))

    n = p * q
    phi_n = (p - 1) * (q - 1)

    while GCD(e, phi_n) != 1:
        e += 2
    d = int(inverse(e, phi_n))

    return p, q, n, d


# ──────────────────────────────────────────────
# Encryption / Decryption
# ──────────────────────────────────────────────

def encrypt(plaintext: bytes, public_key_pem: str, padding: str = "OAEP") -> bytes:
    """
    Mã hóa RSA với padding mode được chỉ định.

    Args:
        plaintext: Dữ liệu cần mã hóa
        public_key_pem: Public key dạng PEM
        padding: "OAEP", "PKCS1_v1.5", hoặc "none"

    Returns:
        Ciphertext bytes
    """
    key = RSA.import_key(public_key_pem)

    if padding == "OAEP":
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(plaintext)

    elif padding == "PKCS1_v1.5":
        cipher = PKCS1_v1_5.new(key)
        return cipher.encrypt(plaintext)

    elif padding == "none":
        # Textbook RSA — không có padding
        m = bytes_to_long(plaintext)
        if m >= key.n:
            raise ValueError("Plaintext quá lớn cho modulus n")
        c = pow(m, key.e, key.n)
        return long_to_bytes(c)

    else:
        raise ValueError(f"Padding không hợp lệ: {padding}")


def decrypt(ciphertext: bytes, private_key_pem: str, padding: str = "OAEP") -> bytes:
    """
    Giải mã RSA với padding mode được chỉ định.

    Args:
        ciphertext: Dữ liệu mã hóa
        private_key_pem: Private key dạng PEM
        padding: "OAEP", "PKCS1_v1.5", hoặc "none"

    Returns:
        Plaintext bytes

    Raises:
        ValueError: Nếu giải mã thất bại (padding error, etc.)
    """
    key = RSA.import_key(private_key_pem)

    if padding == "OAEP":
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(ciphertext)

    elif padding == "PKCS1_v1.5":
        cipher = PKCS1_v1_5.new(key)
        sentinel = os.urandom(32)
        result = cipher.decrypt(ciphertext, sentinel)
        if result == sentinel:
            raise ValueError("PKCS1_v1.5 padding check failed")
        return result

    elif padding == "none":
        c = bytes_to_long(ciphertext)
        m = pow(c, key.d, key.n)
        return long_to_bytes(m)

    else:
        raise ValueError(f"Padding không hợp lệ: {padding}")


def decrypt_with_padding_oracle(
    ciphertext: bytes,
    private_key_pem: str,
    expose_padding_error: bool = False,
) -> Dict[str, Any]:
    """
    Giải mã PKCS1_v1.5 với phản hồi lỗi chi tiết (Padding Oracle).

    Khi expose_padding_error=True, trả về lỗi phân biệt rõ ràng
    giữa PADDING_INVALID và DECRYPTION_FAILED — đây là lỗ hổng
    cố ý cho Bleichenbacher attack.
    """
    key = RSA.import_key(private_key_pem)

    try:
        c = bytes_to_long(ciphertext)
        m = pow(c, key.d, key.n)
        plaintext_bytes = long_to_bytes(m, key.size_in_bytes())

        # Kiểm tra PKCS#1 v1.5 padding format: 0x00 0x02 [PS] 0x00 [M]
        if len(plaintext_bytes) < 11:
            if expose_padding_error:
                return {"success": False, "error_code": "PADDING_INVALID",
                        "detail": "Message too short for PKCS#1 v1.5"}
            return {"success": False, "error_code": "DECRYPTION_FAILED",
                    "detail": "Decryption failed"}

        if plaintext_bytes[0:2] != b'\x00\x02':
            if expose_padding_error:
                return {"success": False, "error_code": "PADDING_INVALID",
                        "detail": "PKCS1_v1.5 padding bytes incorrect"}
            return {"success": False, "error_code": "DECRYPTION_FAILED",
                    "detail": "Decryption failed"}

        # Tìm separator 0x00 sau padding string PS
        sep_idx = plaintext_bytes.index(b'\x00', 2) if b'\x00' in plaintext_bytes[2:] else -1
        if sep_idx < 10:  # PS phải ≥ 8 bytes
            if expose_padding_error:
                return {"success": False, "error_code": "PADDING_INVALID",
                        "detail": "Padding string PS too short"}
            return {"success": False, "error_code": "DECRYPTION_FAILED",
                    "detail": "Decryption failed"}

        message = plaintext_bytes[sep_idx + 1:]
        return {"success": True, "plaintext": message}

    except Exception as ex:
        return {"success": False, "error_code": "DECRYPTION_FAILED",
                "detail": str(ex)}


# ──────────────────────────────────────────────
# Raw RSA Operations (cho CCA Oracle)
# ──────────────────────────────────────────────

def raw_decrypt(ciphertext_int: int, d: int, n: int) -> int:
    """Textbook RSA decryption: m = c^d mod n"""
    return pow(ciphertext_int, d, n)


def raw_encrypt(plaintext_int: int, e: int, n: int) -> int:
    """Textbook RSA encryption: c = m^e mod n"""
    return pow(plaintext_int, e, n)


# ──────────────────────────────────────────────
# Key Utilities
# ──────────────────────────────────────────────

def key_fingerprint(public_key_pem: str) -> str:
    """Tính SHA-256 fingerprint của public key PEM."""
    return hashlib.sha256(public_key_pem.encode()).hexdigest()


def pem_to_components(public_key_pem: str) -> Dict[str, int]:
    """Trích xuất n, e từ public key PEM."""
    key = RSA.import_key(public_key_pem)
    return {"n": key.n, "e": key.e}


def components_to_pem(n: int, e: int) -> str:
    """Tạo PEM public key từ n, e."""
    key = RSA.construct((n, e))
    return key.publickey().export_key("PEM").decode()


def truncate_number(num: int, max_digits: int = 20) -> str:
    """Rút gọn số lớn cho hiển thị UI."""
    s = str(num)
    if len(s) <= max_digits:
        return s
    return f"{s[:max_digits//2]}...{s[-max_digits//2:]} ({len(s)} digits)"

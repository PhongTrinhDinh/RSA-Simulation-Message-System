"""
cca_oracle.py — Chosen-Ciphertext Attack (CCA) khai thác tính nhân tính RSA.
Textbook RSA: Dec(c1 * c2) = Dec(c1) * Dec(c2) mod n.
"""
import time
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes


def cca_attack(ciphertext_int: int, e: int, n: int, oracle_fn=None):
    """
    CCA Attack khai thác tính nhân tính (multiplicative homomorphism) của RSA.

    oracle_fn(c) → trả về plaintext_int (raw decrypt) khi server expose raw decrypt.

    Ý tưởng:
    - Chọn r ngẫu nhiên, tính c' = c * r^e mod n
    - Gửi c' đến oracle, nhận m' = c'^d mod n = m*r mod n
    - Tính m = m' * r^(-1) mod n
    """
    start = time.time()
    steps = []

    if oracle_fn is None:
        return {"success": False, "error": "Cần oracle function (raw decrypt endpoint)"}

    # Chọn r ngẫu nhiên
    r = random.randint(2, n - 1)
    while r % n == 0:
        r = random.randint(2, n - 1)

    steps.append({"step": "choose_r", "r_bits": r.bit_length()})

    # Tính c' = c * r^e mod n
    r_e = pow(r, e, n)
    c_prime = (ciphertext_int * r_e) % n
    steps.append({"step": "compute_c_prime", "c_prime_bits": c_prime.bit_length()})

    # Gửi c' đến oracle
    m_prime = oracle_fn(c_prime)
    if m_prime is None:
        return {"success": False, "error": "Oracle trả về None",
                "duration_ms": int((time.time() - start) * 1000)}

    steps.append({"step": "oracle_response", "m_prime_bits": m_prime.bit_length()})

    # Tính m = m' * r^(-1) mod n
    r_inv = pow(r, -1, n)
    m = (m_prime * r_inv) % n
    steps.append({"step": "recover_m", "m": m})

    result = {
        "success": True, "plaintext_int": m,
        "duration_ms": int((time.time() - start) * 1000),
        "steps": steps,
    }
    try:
        result["plaintext"] = long_to_bytes(m).decode('utf-8', errors='replace')
    except:
        result["plaintext"] = str(m)

    return result

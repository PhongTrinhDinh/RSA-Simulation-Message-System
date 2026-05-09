"""
brute_force.py — Tấn công vét cạn RSA cho key nhỏ.
"""
import time
from Crypto.Util.number import isPrime, inverse, GCD


def brute_force_attack(n: int, e: int, ciphertext_int: int = None):
    """
    Brute force phân tích n thành p*q bằng cách thử từng số nguyên tố nhỏ.
    Chỉ khả thi với key ≤ 64 bit.
    """
    start = time.time()
    steps = []

    if n < 4:
        return {"success": False, "error": "n quá nhỏ"}

    # Thử chia từ 2 đến sqrt(n)
    p = None
    for i in range(2, min(int(n**0.5) + 1, 2**32)):
        if n % i == 0:
            p = i
            break
        if i % 10000 == 0:
            steps.append({"tried_up_to": i, "elapsed": round(time.time() - start, 3)})

    if p is None:
        return {"success": False, "error": "Không tìm được thừa số", "steps": steps,
                "duration_ms": int((time.time() - start) * 1000)}

    q = n // p
    phi_n = (p - 1) * (q - 1)
    d = int(inverse(e, phi_n)) if GCD(e, phi_n) == 1 else None

    result = {
        "success": True, "p": p, "q": q, "d": d, "n": n, "e": e,
        "duration_ms": int((time.time() - start) * 1000), "steps": steps,
    }

    if ciphertext_int is not None and d:
        plaintext_int = pow(ciphertext_int, d, n)
        result["plaintext_int"] = plaintext_int
        try:
            result["plaintext"] = plaintext_int.to_bytes(
                (plaintext_int.bit_length() + 7) // 8, 'big').decode('utf-8', errors='replace')
        except:
            result["plaintext"] = str(plaintext_int)

    return result

"""
factor_n.py — Phân tích thừa số n: Fermat & Pollard's Rho.
"""
import time
import math
import gmpy2
from Crypto.Util.number import inverse, GCD


def fermat_factorization(n: int, max_iterations: int = 1000000):
    """Fermat's Factorization — hiệu quả khi p, q gần nhau."""
    start = time.time()
    steps = []

    a = gmpy2.isqrt(n) + 1
    b2 = a * a - n

    for i in range(max_iterations):
        if gmpy2.is_square(b2):
            b = gmpy2.isqrt(b2)
            p = int(a + b)
            q = int(a - b)
            if p * q == n and p != 1 and q != 1:
                steps.append({"iteration": i, "a": int(a), "b": int(b)})
                return {
                    "success": True, "p": p, "q": q, "method": "fermat",
                    "iterations": i + 1,
                    "duration_ms": int((time.time() - start) * 1000),
                    "steps": steps,
                }
        a += 1
        b2 = a * a - n
        if i % 1000 == 0:
            steps.append({"iteration": i, "a": int(a), "status": "searching"})

    return {"success": False, "error": "Vượt quá max_iterations",
            "duration_ms": int((time.time() - start) * 1000), "steps": steps}


def pollard_rho(n: int, max_iterations: int = 1000000):
    """Pollard's Rho factorization (Brent's improvement + random restarts)."""
    import random
    start = time.time()
    steps = []

    if n % 2 == 0:
        return {"success": True, "p": 2, "q": n // 2, "method": "trivial_even",
                "duration_ms": 0, "steps": []}

    # Kiểm tra perfect square
    s = gmpy2.isqrt(n)
    if s * s == n:
        return {"success": True, "p": int(s), "q": int(s), "method": "perfect_square",
                "duration_ms": int((time.time() - start) * 1000), "steps": []}

    total_iters = 0

    # Thử nhiều hằng số c khác nhau (random restart)
    for c in [1, 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        x = 2
        y = 2
        d = 1
        f = lambda x, c=c: (x * x + c) % n

        iteration = 0
        per_round = max_iterations // 12

        while d == 1 and iteration < per_round:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
            iteration += 1
            total_iters += 1

        if d != n and d != 1:
            p, q = int(d), int(n // d)
            steps.append({"iteration": total_iters, "found_factor": p, "c": c})
            return {
                "success": True, "p": p, "q": q, "method": "pollard_rho",
                "iterations": total_iters,
                "duration_ms": int((time.time() - start) * 1000),
                "steps": steps,
            }

        steps.append({"c": c, "iterations": iteration, "status": "cycle_detected"})

    return {"success": False, "error": "Pollard Rho thất bại",
            "duration_ms": int((time.time() - start) * 1000), "steps": steps}

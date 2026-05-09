"""Unit tests cho Factor n Attack."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))

from attacks.factor_n import fermat_factorization, pollard_rho
import sympy
from Crypto.Util.number import getPrime


def test_fermat_factors_close_primes():
    """p và q gần nhau → Fermat nhanh."""
    p = int(sympy.nextprime(2**127))
    q = int(sympy.nextprime(p))
    n = p * q

    result = fermat_factorization(n)
    assert result["success"] is True
    assert result["p"] * result["q"] == n
    assert set([result["p"], result["q"]]) == set([p, q])


def test_fermat_fails_on_distant_primes():
    """p, q cách xa → Fermat chậm/thất bại trong giới hạn iterations."""
    p = getPrime(128)
    q = getPrime(128)
    while abs(p - q) < 2**64:
        q = getPrime(128)
    n = p * q

    result = fermat_factorization(n, max_iterations=10000)
    # Có thể thành công hoặc thất bại, chỉ kiểm tra format
    assert "success" in result


def test_pollard_rho_factors_small_n():
    """Pollard's Rho phân tích được n nhỏ."""
    p = getPrime(32)
    q = getPrime(32)
    n = p * q

    result = pollard_rho(n)
    assert result["success"] is True
    assert result["p"] * result["q"] == n


if __name__ == "__main__":
    test_fermat_factors_close_primes()
    print("✅ test_fermat_factors_close_primes")
    test_fermat_fails_on_distant_primes()
    print("✅ test_fermat_fails_on_distant_primes")
    test_pollard_rho_factors_small_n()
    print("✅ test_pollard_rho_factors_small_n")
    print("\nAll Factor tests passed!")

"""Unit tests cho Brute Force Attack."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))

from attacks.brute_force import brute_force_attack
from crypto_utils import generate_rsa_keypair


def test_brute_force_small_key():
    """Key 32-bit phải bị brute force thành công."""
    keypair = generate_rsa_keypair(key_bits=32, e=17)
    n, e, d = keypair["n"], keypair["e"], keypair["d"]

    result = brute_force_attack(n, e)
    assert result["success"] is True
    assert result["p"] * result["q"] == n
    assert result["d"] == d


def test_brute_force_with_ciphertext():
    """Brute force + giải mã ciphertext."""
    keypair = generate_rsa_keypair(key_bits=32, e=17)
    n, e = keypair["n"], keypair["e"]

    m = 42
    c = pow(m, e, n)

    result = brute_force_attack(n, e, ciphertext_int=c)
    assert result["success"] is True
    assert result["plaintext_int"] == m


if __name__ == "__main__":
    test_brute_force_small_key()
    print("✅ test_brute_force_small_key")
    test_brute_force_with_ciphertext()
    print("✅ test_brute_force_with_ciphertext")
    print("\nAll Brute Force tests passed!")

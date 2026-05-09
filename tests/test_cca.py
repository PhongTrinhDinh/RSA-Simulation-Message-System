"""Unit tests cho CCA Attack."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'shared'))

from attacks.cca_oracle import cca_attack
from crypto_utils import generate_rsa_keypair


def test_cca_recovers_plaintext():
    """CCA attack phải giải mã được m từ c mà không cần d."""
    # Tạo keypair chuẩn
    keypair = generate_rsa_keypair(key_bits=512)
    n, e, d = keypair["n"], keypair["e"], keypair["d"]

    message = b"SECRET"
    m_int = int.from_bytes(message, 'big')
    c_int = pow(m_int, e, n)

    # Oracle mô phỏng: trả về m_prime = c_prime^d mod n
    def oracle_fn(c_prime):
        return pow(c_prime, d, n)

    result = cca_attack(c_int, e, n, oracle_fn)
    
    assert result["success"] is True
    assert result["plaintext_int"] == m_int
    assert result["plaintext"] == "SECRET"


if __name__ == "__main__":
    test_cca_recovers_plaintext()
    print("✅ test_cca_recovers_plaintext")
    print("\nAll CCA tests passed!")

"""
profiles.py — Attack Profile definitions cho Sandbox OTT.
"""

PROFILES = {
    "safe": {
        "description": "Hệ thống an toàn — RSA chuẩn, không có lỗ hổng",
        "key_bits": 2048, "e": 65537, "padding": "OAEP",
    },
    "brute_force_demo": {
        "description": "Key cực nhỏ để minh họa brute force",
        "key_bits": 32, "e": 17, "padding": "none",
        "note": "Chỉ mang ý nghĩa minh họa độ phức tạp O(2^k)",
    },
    "factor_n_vulnerable": {
        "description": "p và q gần nhau — Fermat Factorization khả thi",
        "key_bits": 512, "prime_gap": "small", "e": 65537,
        "padding": "PKCS1_v1.5",
    },
    "cca_vulnerable": {
        "description": "Textbook RSA không có padding — CCA trực tiếp",
        "key_bits": 1024, "e": 65537, "padding": "none",
        "expose_raw_decrypt": True,
    },
}


def get_profile(name: str) -> dict:
    if name not in PROFILES:
        raise ValueError(f"Profile không tồn tại: {name}. Có: {list(PROFILES.keys())}")
    return PROFILES[name].copy()


def list_profiles() -> list:
    return [{"name": k, "description": v["description"]} for k, v in PROFILES.items()]


def get_profile_key_params(profile_name: str) -> dict:
    """Trích xuất tham số sinh khóa từ profile."""
    p = get_profile(profile_name)
    return {
        "key_bits": p.get("key_bits", 2048),
        "e": p.get("e", 65537),
        "prime_gap": p.get("prime_gap", "normal"),
        "padding": p.get("padding", "OAEP"),
    }

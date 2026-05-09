"""
attacks/__init__.py — Tập hợp các module tấn công RSA.
"""

from .brute_force import brute_force_attack
from .factor_n import fermat_factorization, pollard_rho
from .cca_oracle import cca_attack

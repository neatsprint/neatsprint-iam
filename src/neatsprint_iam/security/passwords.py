"""Argon2id password hashing and policy."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# docs/SECURITY.md §3.1: m=64MB, t=3, p=4
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def password_problems(password: str, *, min_length: int = 10) -> list[str]:
    problems: list[str] = []
    if len(password) < min_length:
        problems.append(f"Password must be at least {min_length} characters.")
    if password.lower() == password:
        problems.append("Password must contain an uppercase letter.")
    if password.upper() == password:
        problems.append("Password must contain a lowercase letter.")
    if not any(ch.isdigit() for ch in password):
        problems.append("Password must contain a digit.")
    return problems

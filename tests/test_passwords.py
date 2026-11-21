from neatsprint_iam.security.passwords import (
    hash_password,
    needs_rehash,
    password_problems,
    verify_password,
)


def test_hash_is_salted_and_verifiable() -> None:
    first = hash_password("CorrectHorse9")
    second = hash_password("CorrectHorse9")
    assert first != second
    assert first.startswith("$argon2id$")
    assert verify_password(first, "CorrectHorse9")
    assert not verify_password(first, "wrong")
    assert not needs_rehash(first)


def test_password_policy() -> None:
    assert password_problems("CorrectHorse9") == []
    problems = password_problems("short")
    assert any("10 characters" in item for item in problems)
    assert password_problems("alllowercase1")
    assert password_problems("ALLUPPERCASE1")
    assert password_problems("NoDigitsHere")

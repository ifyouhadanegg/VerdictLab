import pytest

from app.core.validators import normalize_sha256


def test_normalize_sha256_accepts_uppercase() -> None:
    raw = "A" * 64
    assert normalize_sha256(raw) == "a" * 64


@pytest.mark.parametrize(
    "bad_hash",
    [
        "abc",
        "g" * 64,
        "z" * 64,
        "a" * 63,
        "a" * 65,
    ],
)
def test_normalize_sha256_rejects_invalid_values(bad_hash: str) -> None:
    with pytest.raises(ValueError):
        normalize_sha256(bad_hash)

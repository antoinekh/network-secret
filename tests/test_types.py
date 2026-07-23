from __future__ import annotations

from network_secret.types import Cipher, KeyKind


def _noop_check(a: str, b: str) -> tuple[str, str, bool]:
    return a, b, a == b


def test_keyed_is_false_only_for_none_key_kind():
    keyless = Cipher(
        id="x", vendor="V", name="X", key_kind=KeyKind.NONE,
        encrypt=lambda s: s, decrypt=lambda s: s, check=_noop_check,
    )
    keyed = Cipher(
        id="y", vendor="V", name="Y", key_kind=KeyKind.MASTER_PASSWORD,
        encrypt=lambda s: s, decrypt=lambda s: s, check=_noop_check,
    )
    assert keyless.keyed is False
    assert keyed.keyed is True

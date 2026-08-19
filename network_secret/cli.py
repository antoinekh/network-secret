"""The network-secret command-line interface.

One subcommand per cipher (from the registry). Each subcommand offers
--encrypt / --decrypt / --check, plus a key option for keyed ciphers. The
top level offers --list and --version.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

from .registry import REGISTRY, find
from .types import Cipher, KeyKind

__all__ = ["main"]

_PROMPTS = {
    KeyKind.MASTER_PASSWORD: "Master password: ",
    KeyKind.SHARED_KEY: "Shared key: ",
}


def _build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="network-secret",
        description="Encode, decode, and check network device secrets.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List the supported ciphers and exit",
    )
    sub = parser.add_subparsers(dest="cipher", metavar="CIPHER")

    for cipher in REGISTRY:
        p = sub.add_parser(cipher.id, help=cipher.name, description=cipher.name)
        if cipher.key_kind is KeyKind.MASTER_PASSWORD:
            p.add_argument(
                "-m", "--master", metavar="MASTER",
                help=(
                    "Master password or key used to derive the key. If "
                    f"omitted, read from {cipher.env_var} or prompted for "
                    "without echo."
                ),
            )
        elif cipher.key_kind is KeyKind.SHARED_KEY:
            p.add_argument(
                "-k", "--key", metavar="KEY",
                help=(
                    "Shared AES key (16/24/32 chars). If omitted, read from "
                    f"{cipher.env_var} or prompted for without echo."
                ),
            )
        group = p.add_mutually_exclusive_group(required=True)
        group.add_argument("--encrypt", metavar="PLAINTEXT", help="Encrypt a plaintext value")
        group.add_argument("--decrypt", metavar="CIPHERTEXT", help="Decrypt a secret value")
        group.add_argument(
            "--check", nargs=2, metavar=("SECRET", "VALUE"),
            help="Compare a value against a secret. Exit 0 on match, 1 on mismatch.",
        )
    return parser


def _resolve_key(cipher: Cipher, args: argparse.Namespace) -> str:
    """Resolve a key: explicit flag, then the cipher's env var, then a prompt."""
    flag = args.master if cipher.key_kind is KeyKind.MASTER_PASSWORD else args.key
    if flag is not None:
        return flag
    if cipher.env_var is not None:
        env = os.environ.get(cipher.env_var)
        if env is not None:
            return env
    return getpass.getpass(_PROMPTS[cipher.key_kind])


def _print_check(plain_a: str, plain_b: str, match: bool) -> None:
    print(f"Value 1   : {plain_a!r}")
    print(f"Value 2   : {plain_b!r}")
    print(f"Match     : {'YES' if match else 'NO'}")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list:
        for c in REGISTRY:
            print(f"{c.id:24} {c.vendor:12} {c.name}")
        return 0

    if args.cipher is None:
        parser.print_help()
        return 0

    cipher = find(args.cipher)
    assert cipher is not None  # argparse only allows registered ids
    key_args: tuple[str, ...] = (_resolve_key(cipher, args),) if cipher.keyed else ()

    try:
        if args.encrypt is not None:
            print(cipher.encrypt(args.encrypt, *key_args))
        elif args.decrypt is not None:
            print(cipher.decrypt(args.decrypt, *key_args))
        else:  # --check
            plain_a, plain_b, match = cipher.check(args.check[0], args.check[1], *key_args)
            _print_check(plain_a, plain_b, match)
            return 0 if match else 1
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

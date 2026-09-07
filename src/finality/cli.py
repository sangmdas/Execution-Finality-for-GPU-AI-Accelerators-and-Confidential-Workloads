from __future__ import annotations

import argparse
import json
import logging
import os
import time
from pathlib import Path

from .keys import load_private, load_public, write_keypair
from .profile import EATPolicy, candidate_act, issue_test_eat
from .replay import ReplayStore
from .service import EFVConfig, GatewayConfig, efv_handler, gateway_handler, serve
from .util import b64e


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"required environment variable is absent: {name}")
    return value


def _bytes_env(name: str) -> bytes:
    return _required_env(name).encode("utf-8")


def _common() -> tuple[str, str, str]:
    return (os.getenv("FINALITY_AUTHORITY", "payments.example"), os.getenv("FINALITY_PATH", "/transfer"), os.getenv("FINALITY_AUDIENCE", "urn:example:finality-sink:payments"))


def command_keys(args: argparse.Namespace) -> None:
    write_keypair(args.private, args.public)


def command_eat(args: argparse.Namespace) -> None:
    token = issue_test_eat(load_private(args.private), args.kid.encode(), args.issuer, args.workload, bytes.fromhex(args.measurement), os.urandom(24))
    print(b64e(token))


def command_efv(args: argparse.Namespace) -> None:
    authority, path, audience = _common()
    eat_kid = _bytes_env("EAT_KID")
    handle_kid = _bytes_env("HANDLE_KID")
    config = EFVConfig(
        eat_keys={eat_kid: load_public(_required_env("EAT_PUBLIC_KEY"))},
        eat_policy=EATPolicy(_required_env("EAT_ISSUER"), bytes.fromhex(_required_env("EAT_MEASUREMENT_HEX"))),
        verifier_id=os.getenv("VERIFIER_ID", "urn:example:verifier:reference"),
        signing_key=load_private(_required_env("HANDLE_PRIVATE_KEY")),
        signing_kid=handle_kid,
        authority=authority,
        path=path,
        audience=audience,
        max_amount=int(os.getenv("MAX_AMOUNT", "10000")),
        handle_ttl=int(os.getenv("HANDLE_TTL_SECONDS", "30")),
    )
    serve(args.address, args.port, efv_handler(config))


def command_gateway(args: argparse.Namespace) -> None:
    authority, path, audience = _common()
    handle_kid = _bytes_env("HANDLE_KID")
    store = ReplayStore(_required_env("REPLAY_DATABASE"))
    config = GatewayConfig({handle_kid: load_public(_required_env("HANDLE_PUBLIC_KEY"))}, store, authority, path, audience)
    try:
        serve(args.address, args.port, gateway_handler(config))
    finally:
        store.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="finality")
    parser.add_argument("--log-level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    commands = parser.add_subparsers(dest="command", required=True)
    keys = commands.add_parser("generate-keys")
    keys.add_argument("--private", required=True)
    keys.add_argument("--public", required=True)
    keys.set_defaults(func=command_keys)
    eat = commands.add_parser("issue-test-eat")
    eat.add_argument("--private", required=True)
    eat.add_argument("--kid", required=True)
    eat.add_argument("--issuer", required=True)
    eat.add_argument("--workload", required=True)
    eat.add_argument("--measurement", required=True, help="hex-encoded measurement")
    eat.set_defaults(func=command_eat)
    for name, func, default_port in (("serve-efv", command_efv, 8081), ("serve-gateway", command_gateway, 8080)):
        service = commands.add_parser(name)
        service.add_argument("--address", default="127.0.0.1")
        service.add_argument("--port", type=int, default=default_port)
        service.set_defaults(func=func)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    args.func(args)


if __name__ == "__main__":
    main()


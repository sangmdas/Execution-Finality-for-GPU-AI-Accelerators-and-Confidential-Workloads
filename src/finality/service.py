"""Dependency-light EFV and Finality Sink HTTP services."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .profile import EATPolicy, FinalityError, MAX_BODY, appraise_eat, candidate_act, issue_handle, validate_transfer_policy, verify_handle
from .replay import ReplayStore
from .util import b64d, b64e

LOG = logging.getLogger("finality")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class _Handler(BaseHTTPRequestHandler):
    server_version = "FinalityReference/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info("http", extra={"client": self.client_address[0], "message": fmt % args})

    def send_json(self, status: int, value: Any) -> None:
        body = _json_bytes(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self, limit: int) -> bytes:
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError as exc:
            raise FinalityError("invalid Content-Length") from exc
        if size < 0 or size > limit:
            raise FinalityError("missing or excessive Content-Length")
        body = self.rfile.read(size)
        if len(body) != size:
            raise FinalityError("truncated request body")
        return body


@dataclass(frozen=True)
class EFVConfig:
    eat_keys: dict[bytes, Ed25519PublicKey]
    eat_policy: EATPolicy
    verifier_id: str
    signing_key: Ed25519PrivateKey
    signing_kid: bytes
    authority: str
    path: str
    audience: str
    max_amount: int = 10_000
    handle_ttl: int = 30


def efv_handler(config: EFVConfig) -> type[_Handler]:
    class EFVHandler(_Handler):
        def do_GET(self) -> None:
            if self.path == "/healthz":
                self.send_json(HTTPStatus.OK, {"status": "ok"})
            else:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != "/v1/execution-handles":
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                request = json.loads(self.read_body((MAX_BODY * 4 // 3) + 64 * 1024))
                required = {"eat", "method", "authority", "path", "body", "audience", "transaction_id"}
                if not isinstance(request, dict) or set(request) != required:
                    raise FinalityError("request fields do not match profile")
                eat = b64d(request["eat"])
                body = b64d(request["body"], MAX_BODY)
                if request["authority"] != config.authority or request["path"] != config.path or request["audience"] != config.audience:
                    raise FinalityError("operation is outside configured profile")
                validate_transfer_policy(body, config.max_amount)
                act = candidate_act(request["method"], request["authority"], request["path"], body, request["audience"], request["transaction_id"])
                workload, context = appraise_eat(eat, config.eat_keys, config.eat_policy, config.verifier_id)
                handle = issue_handle(config.signing_key, config.signing_kid, act, workload, context, config.handle_ttl)
                self.send_json(HTTPStatus.CREATED, {"execution_handle": b64e(handle), "expires_in": config.handle_ttl})
            except FinalityError as exc:
                LOG.warning("EFV rejected request: %s", exc)
                self.send_json(HTTPStatus.FORBIDDEN, {"error": exc.code})
            except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
                LOG.warning("EFV malformed request: %s", exc)
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            except Exception:
                LOG.exception("EFV internal error")
                self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
    return EFVHandler


@dataclass(frozen=True)
class GatewayConfig:
    handle_keys: dict[bytes, Ed25519PublicKey]
    replay_store: ReplayStore
    authority: str
    path: str
    audience: str
    clock_skew: int = 5


def gateway_handler(config: GatewayConfig) -> type[_Handler]:
    class GatewayHandler(_Handler):
        def do_GET(self) -> None:
            if self.path == "/healthz":
                self.send_json(HTTPStatus.OK, {"status": "ok"})
            else:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path != config.path:
                self.send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            try:
                token_text = self.headers.get("X-Execution-Handle")
                tx = self.headers.get("X-Transaction-ID", "")
                if not token_text:
                    raise FinalityError("missing execution handle")
                body = self.read_body(MAX_BODY)
                act = candidate_act("POST", config.authority, config.path, body, config.audience, tx)
                handle = verify_handle(b64d(token_text), config.handle_keys, act, clock_skew=config.clock_skew)
                scope = config.audience + ":" + handle[3]
                config.replay_store.effectuate(scope, handle[8], handle[7], tx, body)
                self.send_json(HTTPStatus.OK, {"status": "committed", "transaction_id": tx})
            except FinalityError as exc:
                LOG.warning("Finality Sink rejected request: %s", exc)
                self.send_json(HTTPStatus.FORBIDDEN, {"error": exc.code})
            except (ValueError, KeyError, TypeError) as exc:
                LOG.warning("Finality Sink malformed request: %s", exc)
                self.send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request"})
            except Exception:
                LOG.exception("Finality Sink internal error")
                self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal_error"})
    return GatewayHandler


def serve(address: str, port: int, handler: type[_Handler]) -> None:
    server = ThreadingHTTPServer((address, port), handler)
    server.daemon_threads = True
    LOG.info("listening on %s:%d", address, port)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()

"""Experimental CandidateAct, EAT profile, and Execution Handle logic."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from . import cbor, cose

PROFILE_VERSION = 1
MAX_BODY = 1_048_576
TX_RE = re.compile(r"^[A-Za-z0-9._~-]{16,128}$")


class FinalityError(ValueError):
    code = "invalid_request"


class AttestationRejected(FinalityError):
    code = "attestation_rejected"


class AuthorizationRejected(FinalityError):
    code = "authorization_rejected"


class ActMismatch(FinalityError):
    code = "act_mismatch"


class ExpiredHandle(FinalityError):
    code = "expired_handle"


class ReplayDetected(FinalityError):
    code = "replay_detected"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _normalized_authority(value: str) -> str:
    authority = value.strip().lower()
    if not authority or any(ch in authority for ch in "/?#@ "):
        raise FinalityError("invalid authority")
    return authority


def _normalized_path(value: str) -> str:
    if not value.startswith("/") or "?" in value or "#" in value or ".." in value.split("/"):
        raise FinalityError("path must be normalized and absolute")
    return value


def candidate_act(method: str, authority: str, path: str, body: bytes, audience: str, transaction_id: str) -> dict[int, Any]:
    if len(body) > MAX_BODY:
        raise FinalityError("body exceeds profile limit")
    method = method.upper()
    if method != "POST":
        raise FinalityError("experimental profile permits POST only")
    if not TX_RE.fullmatch(transaction_id):
        raise FinalityError("invalid transaction identifier")
    if not audience or len(audience) > 256:
        raise FinalityError("invalid audience")
    return {1: PROFILE_VERSION, 2: method, 3: _normalized_authority(authority), 4: _normalized_path(path), 5: sha256(body), 6: audience, 7: transaction_id}


def act_digest(act: dict[int, Any]) -> bytes:
    return sha256(cbor.dumps(act))


@dataclass(frozen=True)
class EATPolicy:
    issuer: str
    measurement: bytes
    max_age_seconds: int = 300


def issue_test_eat(private_key: Ed25519PrivateKey, kid: bytes, issuer: str, workload_id: str, measurement: bytes, nonce: bytes, now: int | None = None, lifetime: int = 300) -> bytes:
    now = int(time.time()) if now is None else now
    claims = {1: issuer, 4: now + lifetime, 6: now, 10: nonce, 256: sha256(workload_id.encode()), 1001: workload_id, 1002: measurement, 1003: "secure-boot"}
    return cose.sign1(cbor.dumps(claims), private_key, kid)


def appraise_eat(token: bytes, keys: dict[bytes, Ed25519PublicKey], policy: EATPolicy, verifier_id: str, now: int | None = None) -> tuple[str, bytes]:
    now = int(time.time()) if now is None else now
    payload, _ = cose.verify1(token, keys)
    claims = cbor.loads(payload)
    required = {1, 4, 6, 10, 256, 1001, 1002, 1003}
    if not isinstance(claims, dict) or not required.issubset(claims):
        raise AttestationRejected("missing required EAT claims")
    if claims[1] != policy.issuer or claims[1002] != policy.measurement or claims[1003] != "secure-boot":
        raise AttestationRejected("EAT appraisal policy failed")
    if not isinstance(claims[6], int) or not isinstance(claims[4], int) or claims[6] > now + 30 or now > claims[4] or now - claims[6] > policy.max_age_seconds:
        raise AttestationRejected("EAT freshness policy failed")
    workload_id = claims[1001]
    if not isinstance(workload_id, str) or not workload_id:
        raise AttestationRejected("invalid workload identity claim")
    appraisal = cbor.dumps({1: "affirming", 2: claims[1], 3: claims[256], 4: claims[1002], 5: claims[6], 6: claims[4]})
    return workload_id, sha256(verifier_id.encode() + appraisal)


def validate_transfer_policy(body: bytes, max_amount: int = 10_000) -> None:
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationRejected("body is not valid UTF-8 JSON") from exc
    expected_order = ["destination", "amount", "currency"]
    if not isinstance(value, dict) or list(value) != expected_order or set(value) != set(expected_order):
        raise AuthorizationRejected("body does not match the fixed PoC schema and member order")
    if not isinstance(value["destination"], str) or not value["destination"]:
        raise AuthorizationRejected("invalid destination")
    if isinstance(value["amount"], bool) or not isinstance(value["amount"], int) or not 0 < value["amount"] <= max_amount:
        raise AuthorizationRejected("amount outside policy")
    if value["currency"] != "USD":
        raise AuthorizationRejected("currency outside policy")
    canonical = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()
    if canonical != body:
        raise AuthorizationRejected("body is not in the fixed canonical JSON form")


def issue_handle(private_key: Ed25519PrivateKey, kid: bytes, act: dict[int, Any], workload_id: str, attestation_context_id: bytes, ttl_seconds: int = 30, now: int | None = None, nonce: bytes | None = None) -> bytes:
    import secrets
    now = int(time.time()) if now is None else now
    if not 1 <= ttl_seconds <= 300:
        raise FinalityError("handle TTL must be 1..300 seconds")
    nonce = secrets.token_bytes(24) if nonce is None else nonce
    if len(nonce) < 16:
        raise FinalityError("nonce must contain at least 128 bits")
    payload = {1: PROFILE_VERSION, 2: act_digest(act), 3: workload_id, 4: attestation_context_id, 5: act[6], 6: now, 7: now + ttl_seconds, 8: nonce, 9: act[7]}
    return cose.sign1(cbor.dumps(payload), private_key, kid)


def verify_handle(token: bytes, keys: dict[bytes, Ed25519PublicKey], act: dict[int, Any], now: int | None = None, clock_skew: int = 5) -> dict[int, Any]:
    now = int(time.time()) if now is None else now
    payload, _ = cose.verify1(token, keys)
    handle = cbor.loads(payload)
    required = {1, 2, 3, 4, 5, 6, 7, 8, 9}
    if not isinstance(handle, dict) or set(handle) != required or handle[1] != PROFILE_VERSION:
        raise FinalityError("invalid execution-handle claims")
    if handle[5] != act[6] or handle[9] != act[7]:
        raise ActMismatch("audience or transaction mismatch")
    if not isinstance(handle[6], int) or not isinstance(handle[7], int) or now + clock_skew < handle[6] or now > handle[7]:
        raise ExpiredHandle("handle outside validity interval")
    if handle[2] != act_digest(act):
        raise ActMismatch("candidate act digest mismatch")
    if not isinstance(handle[8], bytes) or len(handle[8]) < 16:
        raise FinalityError("invalid nonce")
    return handle

from __future__ import annotations

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from finality import cbor
from finality.profile import EATPolicy, act_digest, appraise_eat, candidate_act, issue_handle, issue_test_eat
from finality.util import b64e


def private_from_byte(value: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([value]) * 32)


now = 1_800_000_000
eat_key = private_from_byte(1)
handle_key = private_from_byte(2)
measurement = bytes.fromhex("11" * 32)
eat = issue_test_eat(eat_key, b"eat-vector-1", "urn:example:attester", "ai-agent-47", measurement, bytes.fromhex("22" * 24), now)
workload, context = appraise_eat(eat, {b"eat-vector-1": eat_key.public_key()}, EATPolicy("urn:example:attester", measurement), "urn:example:verifier", now)
body = b'{"destination":"account-B","amount":100,"currency":"USD"}'
act = candidate_act("POST", "payments.example", "/transfer", body, "urn:example:finality-sink:payments", "tx-0123456789abcdef")
handle = issue_handle(handle_key, b"efv-vector-1", act, workload, context, now=now, nonce=bytes.fromhex("33" * 24))
output = {
    "profile": 1,
    "fixed_time": now,
    "body_utf8": body.decode(),
    "candidate_act_cbor_hex": cbor.dumps(act).hex(),
    "act_digest_hex": act_digest(act).hex(),
    "eat_base64url": b64e(eat),
    "execution_handle_base64url": b64e(handle),
    "eat_public_key_pem": eat_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    "handle_public_key_pem": handle_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    "expected_results": {
        "V1_exact_unused_handle": "accept_once",
        "V2_missing_handle": "reject",
        "V3_changed_amount": "act_mismatch",
        "V4_changed_destination": "act_mismatch",
        "V5_changed_method_or_path": "reject_or_act_mismatch",
        "V6_expired_handle": "expired_handle",
        "V7_second_use": "replay_detected",
        "V8_wrong_audience": "act_mismatch",
        "V9_modified_signature": "reject",
        "V10_unacceptable_EAT": "no_handle_issued"
    },
}
print(json.dumps(output, indent=2, sort_keys=True))

from __future__ import annotations

import tempfile
import threading
import time
import unittest
import json
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from finality import cbor
from finality.profile import ActMismatch, AttestationRejected, EATPolicy, ExpiredHandle, ReplayDetected, appraise_eat, candidate_act, issue_handle, issue_test_eat, validate_transfer_policy, verify_handle
from finality.replay import ReplayStore
from finality.service import EFVConfig, GatewayConfig, efv_handler, gateway_handler
from finality.util import b64e


BODY = b'{"destination":"account-B","amount":100,"currency":"USD"}'
AUTHORITY = "payments.example"
PATH = "/transfer"
AUDIENCE = "urn:example:finality-sink:payments"
TX = "tx-0123456789abcdef"


class FinalityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = int(time.time())
        self.eat_private = Ed25519PrivateKey.generate()
        self.handle_private = Ed25519PrivateKey.generate()
        self.eat_kid = b"eat-1"
        self.handle_kid = b"efv-1"
        self.measurement = bytes.fromhex("11" * 32)
        self.eat = issue_test_eat(self.eat_private, self.eat_kid, "urn:test:attester", "ai-agent-47", self.measurement, bytes.fromhex("22" * 24), self.now)
        workload, context = appraise_eat(self.eat, {self.eat_kid: self.eat_private.public_key()}, EATPolicy("urn:test:attester", self.measurement), "urn:test:verifier", self.now)
        self.act = candidate_act("POST", AUTHORITY, PATH, BODY, AUDIENCE, TX)
        self.handle = issue_handle(self.handle_private, self.handle_kid, self.act, workload, context, now=self.now, nonce=bytes.fromhex("33" * 24))
        self.keys = {self.handle_kid: self.handle_private.public_key()}

    def test_v1_valid_request_commits_once(self) -> None:
        handle = verify_handle(self.handle, self.keys, self.act, self.now)
        with tempfile.NamedTemporaryFile() as db:
            store = ReplayStore(db.name)
            store.effectuate(AUDIENCE + ":ai-agent-47", handle[8], handle[7], TX, BODY, self.now)
            self.assertEqual(store.effect_count(), 1)
            with self.assertRaises(ReplayDetected):
                store.effectuate(AUDIENCE + ":ai-agent-47", handle[8], handle[7], TX, BODY, self.now)
            self.assertEqual(store.effect_count(), 1)
            store.close()

    def test_v3_amount_substitution_rejected(self) -> None:
        body = b'{"destination":"account-B","amount":100000,"currency":"USD"}'
        changed = candidate_act("POST", AUTHORITY, PATH, body, AUDIENCE, TX)
        with self.assertRaises(ActMismatch):
            verify_handle(self.handle, self.keys, changed, self.now)

    def test_v4_destination_substitution_rejected(self) -> None:
        body = b'{"destination":"account-C","amount":100,"currency":"USD"}'
        changed = candidate_act("POST", AUTHORITY, PATH, body, AUDIENCE, TX)
        with self.assertRaises(ActMismatch):
            verify_handle(self.handle, self.keys, changed, self.now)

    def test_v5_path_substitution_rejected(self) -> None:
        changed = candidate_act("POST", AUTHORITY, "/admin/transfer", BODY, AUDIENCE, TX)
        with self.assertRaises(ActMismatch):
            verify_handle(self.handle, self.keys, changed, self.now)

    def test_v6_expired_handle_rejected(self) -> None:
        with self.assertRaises(ExpiredHandle):
            verify_handle(self.handle, self.keys, self.act, self.now + 60)

    def test_v8_audience_substitution_rejected(self) -> None:
        changed = candidate_act("POST", AUTHORITY, PATH, BODY, "urn:other:sink", TX)
        with self.assertRaises(ActMismatch):
            verify_handle(self.handle, self.keys, changed, self.now)

    def test_v9_signature_modification_rejected(self) -> None:
        changed = self.handle[:-1] + bytes([self.handle[-1] ^ 1])
        with self.assertRaises(ValueError):
            verify_handle(changed, self.keys, self.act, self.now)

    def test_v10_unacceptable_measurement_rejected(self) -> None:
        with self.assertRaises(AttestationRejected):
            appraise_eat(self.eat, {self.eat_kid: self.eat_private.public_key()}, EATPolicy("urn:test:attester", bytes.fromhex("44" * 32)), "urn:test:verifier", self.now)

    def test_noncanonical_json_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate_transfer_policy(b'{ "destination": "account-B", "amount": 100, "currency": "USD" }')

    def test_cbor_rejects_nonminimal_integer(self) -> None:
        with self.assertRaises(ValueError):
            cbor.loads(b"\x18\x01")

    def test_end_to_end_http_and_replay(self) -> None:
        with tempfile.NamedTemporaryFile() as db:
            store = ReplayStore(db.name)
            efv_config = EFVConfig(
                {self.eat_kid: self.eat_private.public_key()},
                EATPolicy("urn:test:attester", self.measurement),
                "urn:test:verifier",
                self.handle_private,
                self.handle_kid,
                AUTHORITY,
                PATH,
                AUDIENCE,
            )
            gateway_config = GatewayConfig(self.keys, store, AUTHORITY, PATH, AUDIENCE)
            efv_server = ThreadingHTTPServer(("127.0.0.1", 0), efv_handler(efv_config))
            gateway_server = ThreadingHTTPServer(("127.0.0.1", 0), gateway_handler(gateway_config))
            threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (efv_server, gateway_server)]
            for thread in threads:
                thread.start()
            try:
                request_body = json.dumps({
                    "eat": b64e(self.eat), "method": "POST", "authority": AUTHORITY,
                    "path": PATH, "body": b64e(BODY), "audience": AUDIENCE,
                    "transaction_id": TX,
                }, separators=(",", ":")).encode()
                request = urllib.request.Request(f"http://127.0.0.1:{efv_server.server_port}/v1/execution-handles", data=request_body, headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(request, timeout=2) as response:
                    token = json.loads(response.read())["execution_handle"]
                    self.assertEqual(response.status, 201)
                missing = urllib.request.Request(f"http://127.0.0.1:{gateway_server.server_port}{PATH}", data=BODY, headers={"Content-Type": "application/json", "X-Transaction-ID": TX})
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(missing, timeout=2)
                self.assertEqual(rejected.exception.code, 403)
                self.assertEqual(store.effect_count(), 0)
                changed_tx = urllib.request.Request(f"http://127.0.0.1:{gateway_server.server_port}{PATH}", data=BODY, headers={"Content-Type": "application/json", "X-Execution-Handle": token, "X-Transaction-ID": "tx-fedcba9876543210"})
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(changed_tx, timeout=2)
                self.assertEqual(rejected.exception.code, 403)
                self.assertEqual(store.effect_count(), 0)
                headers = {"Content-Type": "application/json", "X-Execution-Handle": token, "X-Transaction-ID": TX}
                request = urllib.request.Request(f"http://127.0.0.1:{gateway_server.server_port}{PATH}", data=BODY, headers=headers)
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
                self.assertEqual(store.effect_count(), 1)
                with self.assertRaises(urllib.error.HTTPError) as rejected:
                    urllib.request.urlopen(request, timeout=2)
                self.assertEqual(rejected.exception.code, 403)
                self.assertEqual(store.effect_count(), 1)
            finally:
                efv_server.shutdown(); gateway_server.shutdown()
                efv_server.server_close(); gateway_server.server_close()
                store.close()


if __name__ == "__main__":
    unittest.main()

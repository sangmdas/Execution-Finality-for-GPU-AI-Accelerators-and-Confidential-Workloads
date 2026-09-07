# Attestation-Bound Execution Finality Reference Implementation

This repository is a runnable, vendor-neutral implementation of the minimal experimental profile in `draft-das-rats-attestation-bnd-execution-finality-01`.

It demonstrates one bounded claim: an attested workload can obtain authorization for one exact HTTP operation, and the Finality Sink rejects a missing handle, modified arguments, changed target, expired handle, invalid signature, or replay.

This is security-oriented reference code, not a certified payment product. The protected effect is an atomic commit to a local SQLite effects table; no real funds move.

## Security flow

1. An Attester issues a COSE_Sign1 EAT for an identified workload.
2. The Execution-Finality Validator verifies and appraises that EAT.
3. The EFV evaluates the exact canonical payment request.
4. The EFV signs an act-bound COSE_Sign1 Execution Handle.
5. The gateway reconstructs the CandidateAct from the received request.
6. The gateway verifies signature, audience, transaction, time, act digest, and nonce.
7. It atomically consumes the nonce and records the protected effect.

The EAT and handle signing keys are separate. An EAT is appraisal input and cannot be presented to the gateway as execution authority.

## Implemented profile

- RFC 8949 deterministic CBOR subset with strict decoding
- RFC 9052 COSE_Sign1
- Ed25519 / COSE `alg=-8`
- EAT/CWT claims plus private experimental claims for workload and measurement
- SHA-256 CandidateAct binding
- fixed canonical JSON body for the deliberately narrow `/transfer` operation
- SQLite WAL replay/effect store with `synchronous=FULL`
- bounded request and token sizes
- short-lived handles and clock-skew checking
- non-diagnostic external denial responses with internal structured reasons

## Run tests

The only runtime dependency is `cryptography`.

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
python scripts/generate_vectors.py > test-vectors.json
python scripts/benchmark.py
```

## Run the two services

Generate independent EAT and EFV key pairs:

```bash
finality generate-keys --private eat-private.pem --public eat-public.pem
finality generate-keys --private handle-private.pem --public handle-public.pem
```

Set configuration. Private keys must be readable only by the corresponding service account in a deployment.

```bash
export EAT_KID=eat-1
export HANDLE_KID=efv-1
export EAT_ISSUER=urn:example:attester
export EAT_MEASUREMENT_HEX=1111111111111111111111111111111111111111111111111111111111111111
export EAT_PUBLIC_KEY="$PWD/eat-public.pem"
export HANDLE_PRIVATE_KEY="$PWD/handle-private.pem"
export HANDLE_PUBLIC_KEY="$PWD/handle-public.pem"
export REPLAY_DATABASE="$PWD/finality.sqlite3"
```

Start the EFV and gateway in separate terminals:

```bash
finality serve-efv --port 8081
finality serve-gateway --port 8080
```

Issue a test EAT:

```bash
EAT=$(finality issue-test-eat --private eat-private.pem --kid eat-1 --issuer urn:example:attester --workload ai-agent-47 --measurement "$EAT_MEASUREMENT_HEX")
```

The EFV request body carries base64url-encoded EAT and exact HTTP body bytes. Obtain an execution handle:

```bash
BODY='{"destination":"account-B","amount":100,"currency":"USD"}'
BODY_B64=$(printf %s "$BODY" | base64 | tr '+/' '-_' | tr -d '=\n')
TX=tx-0123456789abcdef
curl --fail-with-body http://127.0.0.1:8081/v1/execution-handles \
  -H 'Content-Type: application/json' \
  --data "{\"eat\":\"$EAT\",\"method\":\"POST\",\"authority\":\"payments.example\",\"path\":\"/transfer\",\"body\":\"$BODY_B64\",\"audience\":\"urn:example:finality-sink:payments\",\"transaction_id\":\"$TX\"}"
```

Extract `execution_handle` and submit the exact operation:

```bash
curl --fail-with-body http://127.0.0.1:8080/transfer \
  -H "X-Execution-Handle: $HANDLE" \
  -H "X-Transaction-ID: $TX" \
  -H 'Content-Type: application/json' \
  --data-binary "$BODY"
```

Changing `amount`, `destination`, path, audience, or transaction ID makes the handle unusable. Sending the same handle a second time is rejected.

## Production integration boundaries

The core verifier is designed for embedding, but deployment still requires site-specific work:

- terminate TLS at a hardened ingress or add TLS to the service process;
- place the downstream effect behind the Finality Sink with no bypass route;
- use an HSM/KMS-backed EFV key rather than a filesystem private key;
- replace the experimental EAT claim profile with the deployment's registered EAT profile;
- use a replicated transactional store if more than one gateway instance can commit the same consequence;
- connect logs, metrics, rate limiting, authorization policy, key rotation, backup, and incident response;
- perform threat modeling, dependency review, fuzzing, penetration testing, and independent cryptographic review.

## What this code proves—and does not prove

It proves executable feasibility for the narrow profile and supplies reproducible negative tests and byte-level vectors. It does not prove patent novelty, IETF adoption, universal applicability, hyperscale performance, or suitability for real financial processing.


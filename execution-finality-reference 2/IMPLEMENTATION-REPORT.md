# Implementation Report

Date: 2026-09-04 UTC

Implemented profile: `draft-das-rats-attestation-bnd-execution-finality-01`, Minimal Vendor-Neutral Proof-of-Concept Profile.

## Verified behavior

- deterministic CBOR encoding and strict decoding;
- COSE_Sign1 creation and verification using Ed25519;
- signed EAT issuance, verification, freshness checking, and measurement appraisal;
- act-bound Execution Handle issuance;
- Finality Sink reconstruction of CandidateAct from the received HTTP operation;
- rejection of argument, destination, path, audience, expiry, signature, and attestation substitutions;
- atomic nonce consumption and protected test-effect commit;
- rejection of a second HTTP submission using the same handle;
- deterministic byte-level vector generation.

## Test result

`python -m unittest discover -s tests -v`: 11 tests passed.

This includes an end-to-end test that starts the EFV and gateway on local TCP ports, obtains a handle over HTTP, commits the exact authorized request, and confirms that replay is rejected without a second committed effect.

## Measurements

The accompanying `benchmark-results.txt` is generated on the execution environment used for this build. It is evidence for this implementation and machine only. It is not a hyperscaler, DPU, SmartNIC, or production-capacity claim.

The microbenchmark separates EAT appraisal, CandidateAct construction, handle issuance, and handle verification. SQLite effect-commit latency and HTTP end-to-end latency are not included in the current microbenchmark and must not be inferred from these results.

## Limitations before production deployment

- The EAT profile uses private experimental claims and a local test Attester.
- The EFV signing key is file-backed; production deployment should use HSM/KMS isolation.
- The service expects TLS termination and rate limiting at a hardened ingress.
- SQLite provides the atomic PoC effect boundary on one node; distributed deployments require a shared transactional consequence store.
- The fixed JSON serialization is intentionally narrow and must not be generalized without a canonicalization specification.
- Independent security and cryptographic review has not yet occurred.


# Security Policy

Do not deploy this repository as a real payment processor without independent security review.

Report vulnerabilities privately to the repository owner before public disclosure. Include the affected revision, reproduction steps, impact, and suggested remediation when available.

Security invariants:

- the protected backend must have no route that bypasses the Finality Sink;
- EFV and EAT signing keys must be distinct;
- private signing keys must not enter source control or container images;
- the gateway must reconstruct CandidateAct fields from the received operation;
- nonce consumption and the protected effect must share one atomic commit boundary;
- authorization failures must fail closed;
- changes to CBOR, COSE, canonicalization, replay, or time validation require test-vector regeneration and review.


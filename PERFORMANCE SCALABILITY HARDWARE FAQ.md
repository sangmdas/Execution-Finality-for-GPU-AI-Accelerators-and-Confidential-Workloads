# Performance, Scalability, and Hardware-Enforcement FAQ

## Purpose and Scope

This document provides a repository-independent framework for interpreting performance, scalability, persistence, networking, and hardware-enforcement claims in execution-finality, authorization, attestation, privacy, sovereignty, telecommunications, AI-governance, and related reference implementations.

It is intentionally benchmark-neutral.

It does not define a universal latency, throughput, transactions-per-second (TPS), hardware-overhead, or deployment-performance claim for every repository in which it appears.

Different repositories may implement different:

- cryptographic primitives;
- persistence backends;
- replay-prevention mechanisms;
- authorization flows;
- Finality Sink designs;
- process boundaries;
- networking topologies;
- hardware trust mechanisms;
- programming languages;
- concurrency models;
- workload assumptions; and
- benchmark methodologies.

Accordingly, any numerical performance result must be interpreted only within the benchmark boundary in which it was actually measured.

> **Repository-specific benchmark artifacts control.**
>
> If a repository contains measured benchmark reports, JSON/CSV result files, test logs, environment descriptions, benchmark scripts, or implementation-specific performance notes, those materials are authoritative for that repository. This document must not be used to substitute, extrapolate, combine, or transfer benchmark values between repositories.

---

## 1. Does a SQLite-backed reference implementation prove production scalability?

No.

SQLite is often useful in a reference implementation because it provides a simple way to demonstrate:

- atomic state transitions;
- replay prevention;
- consume-once semantics;
- transactional authorization state;
- persistence across process restarts; and
- deterministic failure behavior.

A SQLite-backed implementation can therefore demonstrate that the security and authorization semantics are implementable.

It does not, by itself, demonstrate production-scale concurrency or distributed throughput.

SQLite may serialize some write operations depending on configuration and workload. A reference implementation using SQLite should therefore be interpreted as demonstrating the correctness of the state-transition mechanism unless a separate benchmark explicitly establishes sustained throughput under concurrency.

The architectural requirement is generally not:

> "SQLite must be used."

The requirement is instead that the deployment preserve the relevant security properties, such as:

- atomic verification and consumption;
- replay resistance;
- single-use or bounded-use authorization;
- freshness checking;
- revocation or epoch checking;
- fail-closed behavior;
- durable or appropriately protected state where required; and
- prevention of unauthorized external effectuation.

A production deployment may use another transactional, distributed, replicated, hardware-backed, or purpose-built state mechanism, provided that equivalent security properties are preserved.

### Can a single-writer backend become a bottleneck?

Yes.

Any serialization point can become a throughput bottleneck.

That is an implementation and deployment concern rather than evidence that the underlying execution-finality model requires a globally centralized writer.

Depending on the architecture, scaling approaches may include:

- partitioning state by authority domain, tenant, device, workload, region, or resource;
- sharding replay or consumption state;
- distributing Finality Sinks;
- colocating enforcement with the effect boundary;
- using concurrent transactional storage;
- using hardware-assisted state protection; or
- separating independent authorization domains.

Whether a particular scaling technique is valid depends on whether it preserves the security invariants of the implementation.

### Can a latency measurement be converted directly into TPS?

Not automatically.

For example, dividing one second by a measured per-operation latency may produce a theoretical serialization estimate, but this is not equivalent to a measured sustained throughput benchmark.

Real throughput can be affected by:

- write contention;
- synchronization;
- transaction durability;
- queueing;
- scheduler behavior;
- cryptographic concurrency;
- cache behavior;
- storage latency;
- network latency;
- batching;
- replication;
- garbage collection;
- lock contention; and
- workload distribution.

Therefore, documentation should distinguish among:

- measured latency;
- measured throughput;
- estimated serialization ceiling;
- engineering target; and
- production capacity claim.

These terms are not interchangeable.

---

## 2. Does the architecture require sub-millisecond performance?

No universal latency threshold is required by the architecture.

Some implementations may be designed for sub-millisecond local hot-path enforcement. Others may operate in low milliseconds or substantially longer, depending on the application.

Examples of different environments include:

- local operating-system authorization;
- GPU or accelerator control;
- telecom user-plane enforcement;
- API gateways;
- confidential-computing workloads;
- storage mutation;
- cross-service authorization;
- payment finality;
- cross-region infrastructure;
- industrial control; and
- audit-intensive governance systems.

The relevant question is whether authorization occurs before the consequence becomes externally effective, not whether every implementation completes within one fixed latency budget.

### What does "hot path" mean?

A hot path generally refers to operations required for each candidate effect or for a frequently executed authorization path.

Depending on the implementation, the hot path may include:

- canonicalizing or reconstructing the Candidate Act;
- validating scope;
- validating target or destination;
- checking freshness;
- checking policy state;
- checking revocation or authorization epoch;
- verifying a signature, MAC, proof, or protected authorization object;
- checking replay state;
- consuming a single-use authorization; and
- permitting or denying the external effect.

The exact set of operations varies by repository.

### What is the "cold path"?

The cold path generally contains operations that do not have to be performed for every Candidate Act.

Examples may include:

- device or workload enrollment;
- certificate provisioning;
- remote attestation;
- key establishment;
- policy distribution;
- trust-anchor validation;
- model or workload registration;
- hardware identity establishment;
- session creation;
- authorization-epoch setup; and
- policy-bundle verification.

A design may therefore perform expensive trust establishment infrequently and use a smaller protected authorization path for subsequent acts.

Whether a particular operation can safely be moved off the hot path is implementation-specific.

---

## 3. Does adding a network hop invalidate low-latency results?

No, but network-inclusive results must be distinguished from in-process results.

An in-process benchmark measures a different boundary from:

- localhost IPC;
- localhost HTTP;
- same-host sidecar communication;
- same-rack communication;
- same-availability-zone communication;
- service-mesh traversal;
- replicated database commit;
- cross-region communication; or
- public-WAN communication.

These measurements must not be mixed.

A repository should state clearly whether a benchmark includes or excludes:

- process-boundary overhead;
- serialization/deserialization;
- TLS;
- service mesh;
- remote storage;
- consensus;
- replication;
- remote attestation;
- network round trips; and
- the external consequence itself.

A local benchmark can establish that the enforcement logic itself is inexpensive under the tested conditions.

It does not automatically predict distributed-system latency.

---

## 4. Can benchmark results from one repository be reused in another?

No, unless the implementations and benchmark boundaries are demonstrably equivalent and the documentation explicitly explains the relationship.

Repositories may differ in:

- language;
- cryptography;
- database;
- synchronization;
- network transport;
- threat model;
- number of verification stages;
- signature algorithms;
- persistence guarantees;
- policy complexity;
- concurrency;
- hardware;
- test environment; and
- benchmark instrumentation.

For that reason, a measured result in one repository must not be presented as if it were measured in another repository.

This document deliberately contains no universal numerical benchmark table.

Where numerical results exist, they should remain in repository-specific artifacts such as:

- BENCHMARKS.md;
- LATENCY_AND_FEASIBILITY.md;
- PERFORMANCE.md;
- SYSTEM_ENVIRONMENT.md;
- benchmark JSON or CSV files;
- test logs;
- reproducibility reports; or
- implementation-specific technical notes.

---

## 5. What wording should be used for benchmark claims?

Preferred wording should make the measurement boundary explicit.

Examples of defensible formulations include:

> "The reference implementation measured sub-millisecond local verification under the recorded test conditions."

> "The benchmark measures the software enforcement path only and excludes network, hardware-attestation, replicated-storage, and external-effect latency."

> "This result is an implementation measurement, not a production throughput guarantee."

> "The following figure is an engineering target rather than a measured result."

> "The following throughput figure is derived from a serialization estimate and was not measured as sustained concurrent throughput."

> "Hardware-backed performance has not been measured in this repository."

Avoid wording that silently converts:

- latency into throughput;
- a target into a result;
- a synthetic test into production capacity;
- localhost performance into WAN performance;
- software emulation into hardware measurement; or
- one repository's result into another repository's result.

---

## 6. Does an in-memory benchmark prove persistence performance?

No.

An in-memory replay store or authorization cache measures the performance of the enforcement logic without persistent storage overhead.

A persistent implementation may require additional work such as:

- journal writes;
- fsync or equivalent durability operations;
- transactional locking;
- replicated commit;
- remote-database access;
- consensus;
- write-ahead logging; or
- hardware-protected state transitions.

Therefore, in-memory and persistent benchmarks should be reported separately.

---

## 7. Does "SQLite/WAL" automatically mean every commit was durably synchronized to physical storage?

No.

The presence of SQLite or write-ahead logging alone is not enough to establish the exact durability semantics of every commit.

Durability can depend on:

- SQLite synchronous mode;
- filesystem behavior;
- operating-system caching;
- storage device behavior;
- transaction configuration; and
- deployment environment.

Documentation should not state that every commit performs a durable physical synchronization unless the implementation explicitly configures and verifies that behavior.

Safer terminology is:

> "SQLite/WAL persistent transactional state"

unless stronger durability semantics were actually configured and tested.

---

## 8. Does a reference implementation prove carrier-grade, hyperscale, or real-time deployment readiness?

No.

A reference implementation can demonstrate architecture, interoperability, security semantics, testability, and engineering feasibility.

Carrier-grade, hyperscale, safety-critical, or hard-real-time readiness generally requires additional evidence such as:

- sustained concurrent-load testing;
- tail-latency analysis;
- failure injection;
- multi-node testing;
- replication testing;
- failover;
- packet-rate or transaction-rate testing;
- hardware-specific profiling;
- resource-exhaustion testing;
- fault-tolerance testing;
- availability analysis;
- long-duration soak testing; and
- production deployment evidence.

Unless such testing is explicitly present in the repository, those properties should not be claimed.

---

## 9. Is the Finality Sink necessarily a centralized service?

No.

"Finality Sink" describes a security and effectuation boundary, not necessarily a single machine, process, server, or geographical location.

Depending on the implementation, a Finality Sink may exist:

- inside a process;
- inside an operating-system component;
- inside a device;
- at an API gateway;
- at a storage boundary;
- inside a secure enclave;
- at a GPU or accelerator command boundary;
- inside a telecom network function;
- inside a payment or settlement component;
- at an industrial-control boundary; or
- across a distributed enforcement system.

Multiple Finality Sinks may exist simultaneously for different effect domains.

The important property is that an unauthorized Candidate Act cannot become externally effective merely because it was computed, proposed, queued, or transmitted.

---

## 10. Why separate Candidate Act generation from external effectuation?

Because generation and authority are different security events.

An AI model, application, workload, agent, user-space process, or remote service may generate a proposed operation.

That does not necessarily mean the proposing component should possess unrestricted authority to cause the corresponding external consequence.

An execution-finality architecture can therefore represent an operation as a Candidate Act in a Non-Effective State until the relevant authorization and enforcement conditions are satisfied.

This supports the principle:

> **Computation is not authority.**

The architecture is concerned with controlling the transition from:

proposed or computed operation

to:

externally effective consequence.

---

## 11. Does hardware enforcement require a TEE?

Not necessarily.

The protected enforcement boundary may be implemented using different mechanisms depending on the threat model and platform.

Examples may include:

- trusted execution environments;
- secure enclaves;
- HSMs;
- TPM-backed mechanisms;
- confidential virtual machines;
- protected kernel components;
- hypervisor enforcement;
- SmartNICs;
- DPUs;
- FPGAs;
- GPU security mechanisms;
- dedicated security processors;
- isolated gateway components; or
- hybrid hardware/software enforcement.

The security claim should match the actual implementation.

A software-only reference implementation can demonstrate protocol behavior and security logic, but it should not be described as having measured hardware-enforcement properties unless those properties were actually implemented and tested.

---

## 12. What is the performance cost of a TEE, HSM, TPM, GPU security boundary, or remote attestation?

There is no universal number.

Hardware-enforcement overhead depends on factors including:

- hardware generation;
- firmware;
- driver stack;
- enclave transitions;
- memory protection;
- cryptographic algorithm;
- key location;
- PCIe or interconnect behavior;
- device command path;
- attestation protocol;
- evidence size;
- certificate chain;
- network topology;
- verifier location;
- caching;
- session lifetime; and
- application design.

Accordingly, generic statements such as:

> "TEE overhead is X microseconds"

should be avoided unless tied to a specific measured platform and benchmark.

Repository documentation should instead state one of the following:

- measured on specified hardware;
- measured using a hardware emulator;
- software-only;
- modeled;
- estimated;
- engineering target; or
- not measured.

---

## 13. Must remote attestation occur for every Candidate Act?

Not necessarily.

A common design pattern is to establish trust at a session, epoch, workload, device, or policy boundary and then bind subsequent authorizations to that established state.

For example, a system may:

1. attest a protected execution environment;
2. establish trusted identity and policy state;
3. establish keys or authorization context;
4. bind later Candidate Acts to that context; and
5. invalidate the context when freshness, revocation, state, policy, or epoch conditions change.

This can avoid performing a full remote-attestation exchange for every individual effect.

However, the exact trust-refresh interval is a security decision and must reflect the threat model.

---

## 14. Does caching authorization weaken the architecture?

It can, if caching removes the binding between authorization and the actual effect.

Caching is safer where the cached state remains bound to the required parameters, which may include:

- Candidate Act identity;
- operation type;
- arguments;
- destination;
- resource;
- principal;
- device or workload identity;
- policy version;
- authorization epoch;
- freshness;
- maximum use count;
- expiration;
- jurisdiction;
- purpose; and
- revocation state.

A broad reusable bearer credential is different from a narrowly scoped or non-bearer authorization whose validity can be independently reconstructed at the effect boundary.

Performance optimization must therefore preserve the authorization invariants rather than bypass them.

---

## 15. Does cryptographic verification dominate total latency?

Not necessarily.

Depending on the deployment, total latency may be dominated by:

- database operations;
- network round trips;
- serialization;
- process boundaries;
- replicated commit;
- hardware transitions;
- queueing;
- external service latency;
- policy evaluation;
- signature verification; or
- the external effect itself.

For this reason, benchmark documentation should identify individual stages where practical.

Possible categories include:

- Candidate Act construction;
- policy validation;
- protected authorization issuance;
- proof generation;
- Finality Sink verification;
- replay-state consumption;
- persistence;
- effectuation; and
- end-to-end latency.

---

## 16. Should benchmarks include the external consequence itself?

It depends on the benchmark question.

A security-path benchmark may intentionally stop immediately before an external consequence because the goal is to measure enforcement overhead.

An end-to-end application benchmark may include:

- API response time;
- database mutation;
- payment execution;
- device actuation;
- storage commit;
- network transmission; or
- another real consequence.

Both are valid, but they measure different things.

The benchmark report must clearly state the boundary.

---

## 17. What statistics should be reported?

Where practical, benchmark reporting should include more than a mean.

Useful values include:

- number of measured iterations;
- warm-up count;
- p50;
- p95;
- p99;
- p99.9 where appropriate;
- mean;
- minimum;
- maximum;
- number of independent repetitions; and
- observed outliers.

For throughput testing, useful additional values include:

- concurrency level;
- request rate;
- sustained duration;
- successful operations per second;
- rejected operations per second;
- queue depth;
- resource utilization;
- error rate; and
- tail latency under load.

---

## 18. Why are environment details important?

Performance results are not meaningful without context.

A reproducible benchmark should record, where practical:

- operating system;
- kernel version;
- processor;
- architecture;
- visible CPU count;
- memory;
- runtime version;
- compiler;
- cryptographic library;
- database version;
- storage configuration;
- test command;
- benchmark clock;
- dependency versions; and
- relevant configuration flags.

Virtualized or shared-host environments should also be identified where known.

---

## 19. Can synthetic benchmarks still be useful?

Yes.

Synthetic benchmarks are useful for:

- comparing implementation variants;
- detecting regressions;
- quantifying cryptographic overhead;
- isolating enforcement cost;
- testing replay behavior;
- testing concurrency;
- measuring serialization;
- testing policy-validation paths; and
- establishing reproducible baselines.

Their limitation is that they do not automatically reproduce production workloads.

Documentation should therefore describe a synthetic benchmark as synthetic rather than presenting it as a production deployment result.

---

## 20. How should performance targets be presented?

Targets should be explicitly labeled as targets.

For example:

> "Target: p95 below 1 ms for a local enforcement profile."

is different from:

> "Measured p95: 0.8 ms."

An implementation can legitimately define targets for:

- embedded enforcement;
- accelerator command paths;
- telecom paths;
- API gateways;
- storage operations;
- payment systems;
- regional services; or
- audit-heavy workflows.

But targets must not be reported as measurements unless they were actually achieved in a recorded benchmark.

---

## 21. What should be considered a benchmark collision between repositories?

A benchmark collision occurs when documentation unintentionally suggests that measurements from one implementation apply to another.

Examples include:

- copying a latency table into multiple repositories even though their code differs;
- quoting a SQLite result in a repository that uses in-memory state;
- applying a Python benchmark to a Go or Rust implementation;
- applying a localhost HTTP result to an in-process implementation;
- calling a theoretical throughput calculation a measured TPS figure;
- applying software results to a TEE implementation; or
- combining stages from independently measured benchmark suites into a synthetic "end-to-end" number without explaining that methodology.

This document exists specifically to avoid those collisions.

---

## 22. Repository-Specific Benchmark Precedence Rule

When this file is included in a repository, interpret performance information using the following precedence:

1. Raw benchmark result artifacts generated by the repository's benchmark tooling.
2. Benchmark scripts and test configuration showing what was actually executed.
3. System/environment documentation for the recorded run.
4. Repository-specific benchmark or feasibility report.
5. Repository README statements tied directly to those results.
6. This universal FAQ.

This FAQ provides interpretation principles only.

It does not override repository-specific measurements.

---

## 23. Recommended Repository Documentation Pattern

A repository may use a structure such as:

```text
README.md
docs/
    PERFORMANCE_SCALABILITY_HARDWARE_FAQ.md
    SYSTEM_ENVIRONMENT.md
    LATENCY_AND_FEASIBILITY.md
benchmarks/
    benchmark_results.json
    benchmark_results.csv
    benchmark_runner.*
tests/
    ...
```

Not every repository requires all of these files.

The important point is to keep:

- raw measurements;
- benchmark methodology;
- environment information; and
- explanatory claims

clearly distinguishable.

---

## 24. Recommended Universal Disclaimer

The following statement may be used wherever benchmark interpretation could otherwise become ambiguous:

> Performance figures in this repository apply only to the implementation, benchmark boundary, environment, configuration, and workload explicitly identified by the corresponding benchmark artifact. Results from other execution-finality repositories, drafts, prototypes, or hardware profiles must not be imported into this repository unless independently reproduced or explicitly identified as external comparative data. Targets, estimates, theoretical ceilings, and measured results are reported as separate categories.

---

## 25. Summary

| Question | Correct interpretation |
|---|---|
| Does SQLite prove production scale? | No. It can demonstrate transactional and replay-prevention semantics. |
| Is a latency-derived TPS number measured throughput? | No, unless sustained throughput was separately measured. |
| Does local sub-millisecond performance imply WAN sub-millisecond performance? | No. |
| Can one repository's benchmark be quoted as another's? | No. |
| Does a software reference implementation prove TEE/HSM performance? | No. |
| Must remote attestation run for every act? | Not necessarily. |
| Can trust establishment be amortized? | Often, depending on the threat model. |
| Is Finality Sink necessarily centralized? | No. |
| Are engineering targets benchmark results? | No. |
| What benchmark data controls? | The repository-specific measured artifacts. |

The purpose of performance testing is not to prove that one fixed latency or throughput figure applies universally.

It is to establish, for a clearly defined implementation and deployment boundary, how much overhead is introduced by the mechanism that ensures a proposed operation cannot become an externally effective consequence unless the required authorization conditions have been satisfied.

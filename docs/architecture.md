# Architecture decisions

## ADR-001: Java application with a focused C native core

**Decision:** Spring Boot owns the web application and launches a small C
executable for deterministic security primitives.

**Why:** Java is a strong fit for HTTP integrations, configuration, SQLite,
validation, and application tests. C is a strong fit for reusing my own
SHA-256 work and demonstrating careful parsing and OpenSSL integration. A
subprocess protocol avoids deployment-specific JNI headers and library loading.

**Tradeoff:** Starting a process costs more than an in-process call. The workload
is human-driven and low-throughput, so reliability and portability matter more
than microsecond latency.

## ADR-002: Normalize at the provider boundary

**Decision:** OTX and VirusTotal JSON are converted immediately to
`ProviderReport`.

**Why:** Provider fields, terminology, timestamps, and errors differ. The score,
briefing, history, and dashboard should not need provider-specific conditionals.

**Tradeoff:** Normalization does not expose every field in the primary UI. The
complete raw response remains attached to the report for analyst inspection.

## ADR-003: Deterministic policy before optional AI

**Decision:** Risk scoring and the default briefing are deterministic. AI only
rewrites a compact evidence summary for client readability.

**Why:** A security decision must remain testable and available without a paid
model key. Optional AI cannot change the risk score or erase evidence.

**Tradeoff:** Deterministic prose is less flexible, but it is predictable and
safe under provider or model outages.

## ADR-004: Hash-only local file investigation

**Decision:** Stream the file through the native SHA-256 implementation and send
only its digest to providers.

**Why:** Suspicious files may contain confidential client data. Hash lookup gives
useful reputation information without transferring content.

**Tradeoff:** Unknown files will not receive a new sandbox analysis.

## ADR-005: Hash-chain history plus signed portable exports

**Decision:** Link local history rows with SHA-256 and sign exported reports with
RSA-PSS/SHA-256.

**Why:** The chain detects local snapshot modification and the signature lets a
recipient verify that a portable report came from this instance.

**Tradeoff:** The hash chain is not an external immutable ledger. Private-key
protection and rotation remain deployment responsibilities.

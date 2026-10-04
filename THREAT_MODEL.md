# Threat model — kola

A witnessed organism rewrites its chain — detectable via attestation pinning. A forger fabricates attestations — impossible without the witness's key. A witness lies about what it saw — its signed journal is itself hash-chained and auditable. A truncated history shrinks before audit — pinned head + sequence numbers make gaps visible.

## What this crate guarantees

- Signed attestations bind a subject's chain identity, sequence, and tip hash at a point in time.
- The witness journal is append-only hash-chained; reordering or deletion is detectable.
- Audits replay entirely offline — no trust in either organism required.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.

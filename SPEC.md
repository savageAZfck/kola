# SPEC — kola (cross-organism witnessing)

## Identity

`Identity` is an ed25519 signing key. `public_key()` is the hex-encoded
verifying key; `seed()`/`from_bytes()` persist it as 32 raw bytes.

## Journal

`WitnessJournal` is an append-only hash-chained log owned by one
identity. Entries commit to the previous entry hash; `verify()` checks
linkage and every embedded signature.

## Attestation

```json
{
  "id": "sha256 of canonical body",
  "witness": "pubkey — who attests",
  "subject": "pubkey — whose chain is pinned",
  "chain_id": "e.g. ledger",
  "seq": 128,
  "tip_hash": "chain head at seq",
  "ts": 0,
  "signature": "ed25519 over canonical body"
}
```

The signed body covers every field above except `signature`.

## Exchange

`exchange(a, b, head_a, head_b)` produces the mutual pair — A attests
B's head and B attests A's. Both are recorded in each party's journal.

## Audit

`audit_against_history(journal, subject, chain_id, seq→tip map)` replays
a presented history against recorded attestations and returns
`{ checked, confirmed[], contradicted[] }`. A contradiction means the
subject's current chain disagrees with what the witness pinned —
rewriting attested history is detectable by construction.

## Invariants

- Attestations are immutable once committed.
- A journal cannot attest its own head for a subject (witness ≠ subject).
- Verification requires no network and no trust in either party.

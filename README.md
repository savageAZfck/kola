# kola

**Cross-organism witnessing — sovereign agents mutually notarize each other's hash-chained ledgers.**

Named for the Lakota *kola* — a sworn ally who vouches for you.

## The problem

Every audit chain on crates.io is self-signed. The holder of the signing key can rewrite history and re-sign — a chain that attests only to itself proves *consistency*, not *honesty*. `kola` closes the gap: two organisms periodically sign each other's chain tips into their own hash-chained witness journals. After that, neither side can rewrite attested ground without the other's journal contradicting it — **even the owner can't forge the past.**

## What it gives you

- `ChainHead` — chain-agnostic notarizable tip (chain id, seq, tip hash). Works over any append-only hash chain.
- `Attestation` — Ed25519-signed "I saw your chain at this head at this time," verifiable offline.
- `WitnessJournal` — hash-chained record of every attestation issued *and* received. Dropping a past attestation breaks your own chain.
- `exchange()` — mutual notarization in one call.
- `audit_against_history()` — replay a presented history against a journal: returns confirmed/contradicted attestations, catching rewrites, truncations, and forks.
- Journal heads are themselves notarizable — *witnesses of witnesses*.

## Try it

```bash
cargo run --example witness
cargo test
```

## Design invariants

- Attestations sign the *head digest* (chain id + seq + tip hash) — the witness never sees chain contents, only the commitment.
- Both directions recorded: issued attestations prove what you vouched for; received attestations prove who vouched for you.
- Unilateral: no consensus protocol, no network requirement — a journal is a file.

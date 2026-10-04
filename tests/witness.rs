use kola::*;
use std::collections::BTreeMap;

fn real_head(chain: &str, seq: u64, tip: &str) -> ChainHead {
    let mut h = tip.to_string();
    while h.len() < 64 {
        h.push('0');
    }
    ChainHead::new(chain, seq, &h[..64])
}

#[test]
fn attest_and_verify() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut jb = WitnessJournal::new(b.public_key());
    let h = real_head("ledger", 10, "deadbeef");
    let att = jb.attest(&b, &a.public_key(), &h).unwrap();
    att.verify().unwrap();
    assert_eq!(att.witness, b.public_key());
    assert_eq!(att.subject, a.public_key());
}

#[test]
fn mutual_exchange_records_both_sides() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ja = WitnessJournal::new(a.public_key());
    let mut jb = WitnessJournal::new(b.public_key());
    let ha = real_head("ledger", 7, "aaaa");
    let hb = real_head("ledger", 9, "bbbb");
    let (for_a, for_b) = exchange(&a, &mut ja, &b, &mut jb, &ha, &hb).unwrap();
    // Each journal holds two events: one issued, one received.
    assert_eq!(ja.events.len(), 2);
    assert_eq!(jb.events.len(), 2);
    assert_eq!(for_a.head, hb);
    assert_eq!(for_b.head, ha);
    ja.verify().unwrap();
    jb.verify().unwrap();
}

#[test]
fn journal_chain_detects_tamper() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ja = WitnessJournal::new(a.public_key());
    let mut jb = WitnessJournal::new(b.public_key());
    exchange(
        &a,
        &mut ja,
        &b,
        &mut jb,
        &real_head("ledger", 1, "aaaa"),
        &real_head("ledger", 1, "bbbb"),
    )
    .unwrap();
    // Corrupt a stored attestation.
    ja.events[0].attestation.head.seq = 999;
    assert!(ja.verify().is_err());
}

#[test]
fn forged_attestation_rejected() {
    let a = Identity::generate();
    let mut ja = WitnessJournal::new(a.public_key());
    let mut att = Attestation {
        witness: a.public_key(),
        subject: "ff".repeat(32),
        head: real_head("ledger", 3, "cafe"),
        ts: 1,
        signature: "00".repeat(64),
    };
    assert!(ja.record_received(att.clone()).is_err());
    // Sign with a different key — still forged.
    let forger = Identity::generate();
    let fake = {
        let mut jf = WitnessJournal::new(forger.public_key());
        jf.attest(&forger, &a.public_key(), &real_head("ledger", 3, "cafe"))
            .unwrap()
    };
    // A valid signature from a third party is fine to record — witnessing
    // is not restricted to one witness.
    att = fake;
    ja.record_received(att).unwrap();
}

#[test]
fn history_audit_confirms_clean_chain() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut jb = WitnessJournal::new(b.public_key());
    let h = real_head("ledger", 5, "beef");
    jb.attest(&b, &a.public_key(), &h).unwrap();

    let mut history = BTreeMap::new();
    history.insert(5u64, h.tip_hash.clone());
    history.insert(6u64, "ff".repeat(32));

    let report = audit_against_history(&jb, &a.public_key(), "ledger", &history);
    assert_eq!(report.checked, 1);
    assert_eq!(report.confirmed, 1);
    assert!(report.clean());
}

#[test]
fn history_audit_catches_rewrite_and_truncation() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut jb = WitnessJournal::new(b.public_key());
    jb.attest(&b, &a.public_key(), &real_head("ledger", 4, "aaaa"))
        .unwrap();
    jb.attest(&b, &a.public_key(), &real_head("ledger", 8, "bbbb"))
        .unwrap();

    // A rewrote the chain: seq 4 differs, seq 8 truncated away.
    let mut history = BTreeMap::new();
    history.insert(4u64, "11".repeat(32));

    let report = audit_against_history(&jb, &a.public_key(), "ledger", &history);
    assert_eq!(report.checked, 2);
    assert_eq!(report.confirmed, 0);
    assert_eq!(report.contradicted.len(), 2);
}

#[test]
fn journal_head_is_notarizable() {
    let a = Identity::generate();
    let mut ja = WitnessJournal::new(a.public_key());
    assert_eq!(ja.head().seq, 0);
    let b = Identity::generate();
    let mut jb = WitnessJournal::new(b.public_key());
    exchange(
        &a,
        &mut ja,
        &b,
        &mut jb,
        &real_head("ledger", 1, "aaaa"),
        &real_head("ledger", 1, "bbbb"),
    )
    .unwrap();
    // Journal heads can themselves be witnessed — witnesses of witnesses.
    let jh = ja.head();
    jb.attest(&b, &a.public_key(), &jh).unwrap();
    assert_eq!(jb.head().seq, 3);
}

#[test]
fn serialization_roundtrip_verifies() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ja = WitnessJournal::new(a.public_key());
    let mut jb = WitnessJournal::new(b.public_key());
    exchange(
        &a,
        &mut ja,
        &b,
        &mut jb,
        &real_head("ledger", 2, "aaaa"),
        &real_head("ledger", 2, "bbbb"),
    )
    .unwrap();
    let text = journal_to_json(&ja).unwrap();
    let loaded = journal_from_json(&text).unwrap();
    assert_eq!(loaded.events.len(), ja.events.len());
    // Corrupt the serialized form — load must refuse.
    let bad = text.replace("\"seq\": 0", "\"seq\": 9");
    assert!(journal_from_json(&bad).is_err());
}

#[test]
fn witness_cannot_sign_for_someone_elses_journal() {
    let a = Identity::generate();
    let b = Identity::generate();
    let mut ja = WitnessJournal::new(a.public_key());
    // B tries to push an attestation into A's journal using B's key.
    let r = ja.attest(&b, &a.public_key(), &real_head("ledger", 1, "aaaa"));
    assert!(r.is_err());
}

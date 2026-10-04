//! Mutual notarization ceremony between two organisms.
use kola::*;
use std::collections::BTreeMap;

fn real_head(chain: &str, seq: u64, tip: &str) -> ChainHead {
    let mut h = tip.to_string();
    while h.len() < 64 {
        h.push('0');
    }
    ChainHead::new(chain, seq, &h[..64])
}

fn main() {
    let apple_a = Identity::generate();
    let apple_b = Identity::generate();
    let mut journal_a = WitnessJournal::new(apple_a.public_key());
    let mut journal_b = WitnessJournal::new(apple_b.public_key());

    let head_a = real_head("ledger", 128, "a1b2c3");
    let head_b = real_head("ledger", 74, "d4e5f6");

    println!("A tip: seq {} hash {}…", head_a.seq, &head_a.tip_hash[..12]);
    println!("B tip: seq {} hash {}…", head_b.seq, &head_b.tip_hash[..12]);

    let (att_for_a, att_for_b) = exchange(
        &apple_a,
        &mut journal_a,
        &apple_b,
        &mut journal_b,
        &head_a,
        &head_b,
    )
    .expect("exchange");

    println!(
        "\nB notarized A's tip — attestation {}",
        &att_for_b.id()[..12]
    );
    println!(
        "A notarized B's tip — attestation {}",
        &att_for_a.id()[..12]
    );

    journal_a.verify().expect("journal A verifies");
    journal_b.verify().expect("journal B verifies");

    // Later: an auditor replays A's chain and checks it against B's journal.
    let mut presented_history = BTreeMap::new();
    presented_history.insert(128u64, head_a.tip_hash.clone());
    let report = audit_against_history(
        &journal_b,
        &apple_a.public_key(),
        "ledger",
        &presented_history,
    );
    println!(
        "\nAudit of A against B's journal: {} checked, {} confirmed, {} contradicted — {}",
        report.checked,
        report.confirmed,
        report.contradicted.len(),
        if report.clean() { "CLEAN" } else { "TAMPERED" }
    );

    // A rewrites history — B's journal catches it.
    presented_history.insert(128u64, "99".repeat(32));
    let report = audit_against_history(
        &journal_b,
        &apple_a.public_key(),
        "ledger",
        &presented_history,
    );
    println!(
        "After A rewrites its tip:  {} contradicted — {}",
        report.contradicted.len(),
        if report.clean() { "CLEAN" } else { "TAMPERED" }
    );
}

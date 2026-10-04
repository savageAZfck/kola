//! kola — cross-organism witnessing.
//!
//! Named for the Lakota *kola* — a sworn ally who vouches for you.
//!
//! Every sovereign organism keeps its own hash-chained ledger, and every
//! chain is self-signed. That is necessary but not sufficient: the holder
//! of the signing key can, in principle, rewrite history and re-sign the
//! whole chain — a ledger that attests only to itself proves consistency,
//! not honesty.
//!
//! Witnessing closes that gap. Two organisms periodically *notarize each
//! other's chain tips*:
//!
//! 1. A presents its current [`ChainHead`] — chain id, sequence, tip hash.
//! 2. B signs an [`Attestation`] binding that head to B's witness key and
//!    hands it back. B also records the attestation in its own
//!    hash-chained [`WitnessJournal`].
//! 3. A anchors the attestation in its own chain so the witnessed point
//!    is part of A's history too.
//!
//! From then on A cannot rewrite anything at or before that tip without
//! B's journal contradicting it — and B cannot invent a false attestation
//! because each is signed and chained. Mutually assured memory.
//!
//! ```no_run
//! use kola::{Identity, ChainHead, WitnessJournal};
//!
//! let apple_a = Identity::generate();
//! let apple_b = Identity::generate();
//! let mut journal_a = WitnessJournal::new(apple_a.public_key());
//! let mut journal_b = WitnessJournal::new(apple_b.public_key());
//!
//! // A presents its chain tip; B notarizes it.
//! let head = ChainHead::new("ledger-a", 41, "ab12…");
//! let att = journal_b.attest(&apple_b, &apple_a.public_key(), &head).unwrap();
//! journal_a.record_received(att);
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Debug)]
pub enum Error {
    BadHead(String),
    BadSignature(String),
    BadChain(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadHead(m) => write!(f, "invalid chain head: {m}"),
            Error::BadSignature(m) => write!(f, "signature failure: {m}"),
            Error::BadChain(m) => write!(f, "witness chain broken: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("canonical json")
}

// ---------------------------------------------------------------- identity

/// Ed25519 identity for an organism acting as witness or subject.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    /// Build an identity from an existing 32-byte seed.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self::from_seed(*seed)
    }

    /// The raw seed bytes — for 0600 key-file persistence.
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.key.sign(msg).to_bytes())
    }
}

/// Verify a hex signature over `msg` against a hex Ed25519 public key.
pub fn verify_signature(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::BadSignature(format!("pubkey hex: {e}")))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("pubkey not 32 bytes".into()))?,
    )
    .map_err(|e| Error::BadSignature(format!("pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| Error::BadSignature(format!("sig hex: {e}")))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("sig not 64 bytes".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("verification failed".into()))
}

// ---------------------------------------------------------------- chain head

/// The notarizable state of any append-only hash chain: its identity,
/// length, and tip digest. Chain-agnostic — ledgers, treaty books, tape
/// rings, and dream logs can all present a head.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChainHead {
    /// Which chain this head belongs to (e.g. "ledger", "treaty_book").
    pub chain_id: String,
    /// Sequence number / entry count at the tip.
    pub seq: u64,
    /// Hex digest of the tip entry.
    pub tip_hash: String,
}

impl ChainHead {
    pub fn new(chain_id: &str, seq: u64, tip_hash: &str) -> Self {
        ChainHead {
            chain_id: chain_id.to_string(),
            seq,
            tip_hash: tip_hash.to_string(),
        }
    }

    /// SHA-256 of the canonical head — what actually gets attested.
    pub fn digest(&self) -> String {
        sha256_hex(&canonical(&json!({
            "chain_id": self.chain_id,
            "seq": self.seq,
            "tip_hash": self.tip_hash,
        })))
    }

    fn validate(&self) -> Result<(), Error> {
        if self.chain_id.is_empty() {
            return Err(Error::BadHead("empty chain_id".into()));
        }
        if self.tip_hash.len() != 64 || hex::decode(&self.tip_hash).is_err() {
            return Err(Error::BadHead("tip_hash must be 64-char hex".into()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- attestation

/// A signed notarization: "I, witness, saw subject's chain at this head
/// at this time." The witness signs the canonical body; anyone can verify.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attestation {
    /// Witness Ed25519 public key (hex).
    pub witness: String,
    /// Subject organism's public key (hex) — whose chain is attested.
    pub subject: String,
    /// The attested chain head.
    pub head: ChainHead,
    /// Unix seconds when the witness signed.
    pub ts: u64,
    /// Hex signature over the canonical body.
    pub signature: String,
}

impl Attestation {
    fn body(&self) -> Value {
        json!({
            "witness": self.witness,
            "subject": self.subject,
            "head": self.head,
            "ts": self.ts,
        })
    }

    /// Verify the witness signature and basic shape.
    pub fn verify(&self) -> Result<(), Error> {
        self.head.validate()?;
        if self.witness.is_empty() || self.subject.is_empty() {
            return Err(Error::BadSignature("missing party key".into()));
        }
        verify_signature(&self.witness, &canonical(&self.body()), &self.signature)
    }

    /// Content hash — used as the attestation's id in journals.
    pub fn id(&self) -> String {
        sha256_hex(&canonical(&json!({
            "body": self.body(),
            "signature": self.signature,
        })))
    }
}

// ---------------------------------------------------------------- journal

/// A witness event in the journal: either an attestation this organism
/// *issued* for a peer, or one it *received* from a peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessEvent {
    /// "issued" or "received".
    pub direction: String,
    /// The attestation itself.
    pub attestation: Attestation,
    /// Hash of the previous journal entry (genesis: "0"*64).
    pub prev: String,
    /// Hash of this entry's canonical body.
    pub hash: String,
    /// Journal-local sequence.
    pub seq: u64,
}

/// Hash-chained record of every attestation an organism has issued or
/// received. The journal is itself a witness chain: an organism cannot
/// silently drop an attestation it issued without breaking its own chain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessJournal {
    /// This organism's public key (hex).
    pub owner: String,
    /// Ordered witness events.
    pub events: Vec<WitnessEvent>,
}

impl WitnessJournal {
    pub fn new(owner_pubkey: String) -> Self {
        WitnessJournal {
            owner: owner_pubkey,
            events: Vec::new(),
        }
    }

    fn tip(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64))
    }

    fn push(&mut self, direction: &str, attestation: Attestation) -> WitnessEvent {
        let seq = self.events.len() as u64;
        let prev = self.tip();
        let body = canonical(&json!({
            "direction": direction,
            "attestation": attestation,
            "prev": prev,
            "seq": seq,
        }));
        let event = WitnessEvent {
            direction: direction.to_string(),
            attestation,
            prev,
            hash: sha256_hex(&body),
            seq,
        };
        self.events.push(event.clone());
        event
    }

    /// Issue a signed attestation for `subject`'s `head` and record it.
    pub fn attest(
        &mut self,
        me: &Identity,
        subject: &str,
        head: &ChainHead,
    ) -> Result<Attestation, Error> {
        head.validate()?;
        if me.public_key() != self.owner {
            return Err(Error::BadSignature(
                "journal owner does not match signing key".into(),
            ));
        }
        let mut att = Attestation {
            witness: self.owner.clone(),
            subject: subject.to_string(),
            head: head.clone(),
            ts: now_secs(),
            signature: String::new(),
        };
        att.signature = me.sign(&canonical(&att.body()));
        self.push("issued", att.clone());
        Ok(att)
    }

    /// Record an attestation received from a peer (after verifying it).
    pub fn record_received(&mut self, attestation: Attestation) -> Result<(), Error> {
        attestation.verify()?;
        self.push("received", attestation);
        Ok(())
    }

    /// Current journal head — itself notarizable.
    pub fn head(&self) -> ChainHead {
        ChainHead {
            chain_id: "witness_journal".into(),
            seq: self.events.len() as u64,
            tip_hash: self.tip(),
        }
    }

    /// Verify the journal's internal hash chain and every attestation
    /// signature inside it.
    pub fn verify(&self) -> Result<(), Error> {
        let mut prev = "0".repeat(64);
        for (i, ev) in self.events.iter().enumerate() {
            if ev.seq != i as u64 {
                return Err(Error::BadChain(format!("seq gap at {i}")));
            }
            if ev.prev != prev {
                return Err(Error::BadChain(format!("prev mismatch at {i}")));
            }
            let body = canonical(&json!({
                "direction": ev.direction,
                "attestation": ev.attestation,
                "prev": ev.prev,
                "seq": ev.seq,
            }));
            if sha256_hex(&body) != ev.hash {
                return Err(Error::BadChain(format!("hash mismatch at {i}")));
            }
            ev.attestation.verify()?;
            prev = ev.hash.clone();
        }
        Ok(())
    }

    /// The most recent attestation this journal's owner issued for a
    /// given subject chain, if any.
    pub fn latest_issued(&self, subject: &str, chain_id: &str) -> Option<&Attestation> {
        self.events
            .iter()
            .rev()
            .find(|e| {
                e.direction == "issued"
                    && e.attestation.subject == subject
                    && e.attestation.head.chain_id == chain_id
            })
            .map(|e| &e.attestation)
    }
}

// ---------------------------------------------------------------- witnessing

/// Result of checking a subject's (possibly rewritten) history against
/// the attestations a witness holds for it.
#[derive(Debug)]
pub struct AuditReport {
    /// Attestations checked.
    pub checked: usize,
    /// Attestations whose attested head is still consistent with the
    /// presented history (the tip hash appears at the attested seq).
    pub confirmed: usize,
    /// Attestations contradicted by the presented history — the subject
    /// has rewritten, truncated, or forked attested ground.
    pub contradicted: Vec<Attestation>,
}

impl AuditReport {
    pub fn clean(&self) -> bool {
        self.contradicted.is_empty()
    }
}

/// Check a presented chain history against a witness journal.
///
/// `history` maps `seq -> tip_hash` for the subject chain under audit —
/// produced by the auditor replaying the subject's chain entries, or by
/// the subject itself under challenge. For every attestation the journal
/// holds for (`subject`, `chain_id`), the attested tip hash must appear
/// at the attested seq. A missing seq (truncation) or different hash
/// (rewrite/fork) is a contradiction.
pub fn audit_against_history(
    journal: &WitnessJournal,
    subject: &str,
    chain_id: &str,
    history: &BTreeMap<u64, String>,
) -> AuditReport {
    let mut checked = 0usize;
    let mut confirmed = 0usize;
    let mut contradicted = Vec::new();
    for ev in &journal.events {
        if ev.direction != "issued" {
            continue;
        }
        let att = &ev.attestation;
        if att.subject != subject || att.head.chain_id != chain_id {
            continue;
        }
        checked += 1;
        match history.get(&att.head.seq) {
            Some(h) if *h == att.head.tip_hash => confirmed += 1,
            _ => contradicted.push(att.clone()),
        }
    }
    AuditReport {
        checked,
        confirmed,
        contradicted,
    }
}

/// Mutual notarization: two organisms attest each other's heads and each
/// records both attestations (its own as issued, the peer's as received).
/// Returns the pair of attestations exchanged.
pub fn exchange(
    me: &Identity,
    my_journal: &mut WitnessJournal,
    peer: &Identity,
    peer_journal: &mut WitnessJournal,
    my_head: &ChainHead,
    peer_head: &ChainHead,
) -> Result<(Attestation, Attestation), Error> {
    let for_peer = peer_journal.attest(peer, &me.public_key(), my_head)?;
    let for_me = my_journal.attest(me, &peer.public_key(), peer_head)?;
    my_journal.record_received(for_peer.clone())?;
    peer_journal.record_received(for_me.clone())?;
    Ok((for_me, for_peer))
}

/// Serialize a journal to JSON for persistence.
pub fn journal_to_json(journal: &WitnessJournal) -> Result<String, Error> {
    Ok(serde_json::to_string_pretty(journal)?)
}

/// Load a journal from JSON, verifying its chain before trusting it.
pub fn journal_from_json(text: &str) -> Result<WitnessJournal, Error> {
    let journal: WitnessJournal = serde_json::from_str(text)?;
    journal.verify()?;
    Ok(journal)
}

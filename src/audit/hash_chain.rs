//! Hash chaining for tamper-evident records. Each record carries its position (`seq`, from 1),
//! the `record_hash` of the record before it (`prev_hash`, [`GENESIS_HASH`] for the first) and
//! its own `record_hash`, a SHA-256 over its position, `prev_hash` and content. Editing,
//! removing or reordering a record breaks the chain at that record.

use sha2::{Digest, Sha256};

/// `prev_hash` of the first record in a chain.
pub const GENESIS_HASH: &str = "genesis";

/// Field separator of a chain pre-image. `0x1e` (record separator) cannot occur in a hex hash,
/// a label, an id or canonical JSON (which escapes control characters), so two different
/// records cannot collide by shifting a field boundary.
const CHAIN_SEP: char = '\u{1e}';

/// SHA-256 hex of `input`; an empty input hashes to `""`, so an absent field is distinguishable
/// from a present one.
#[must_use]
pub fn hash_hex(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// The `record_hash` of the record at `seq` after `prev_hash` whose content is `fields`.
#[must_use]
pub fn link_hash(
    seq: u64,
    prev_hash: &str,
    fields: &[&str],
) -> String {
    let mut preimage = format!("{seq}{CHAIN_SEP}{prev_hash}");
    for field in fields {
        preimage.push(CHAIN_SEP);
        preimage.push_str(field);
    }
    hash_hex(&preimage)
}

/// A record that is a link of a hash chain.
pub trait Chained {
    fn seq(&self) -> u64;
    fn prev_hash(&self) -> &str;
    fn record_hash(&self) -> &str;
    /// The `record_hash` the record should carry, recomputed from its content and `prev_hash`.
    fn compute_hash(&self) -> String;
}

/// Verifies a chain from its first record. Returns `Err(index)` of the first record that does
/// not follow its predecessor: edited (its `record_hash` no longer matches its content),
/// removed or reordered (its `seq` or `prev_hash` does not follow), or never part of it.
pub fn verify_chain<T: Chained>(records: &[T]) -> Result<(), usize> {
    let mut expected_prev = GENESIS_HASH.to_string();
    for (index, record) in records.iter().enumerate() {
        let expected_seq = index as u64 + 1;
        if record.seq() != expected_seq
            || record.prev_hash() != expected_prev
            || record.record_hash() != record.compute_hash()
        {
            return Err(index);
        }
        expected_prev = record
            .record_hash()
            .to_string();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Link {
        seq: u64,
        prev: String,
        body: String,
        hash: String,
    }

    impl Chained for Link {
        fn seq(&self) -> u64 {
            self.seq
        }
        fn prev_hash(&self) -> &str {
            &self.prev
        }
        fn record_hash(&self) -> &str {
            &self.hash
        }
        fn compute_hash(&self) -> String {
            link_hash(self.seq, &self.prev, &[&self.body])
        }
    }

    fn chain(bodies: &[&str]) -> Vec<Link> {
        let mut prev = GENESIS_HASH.to_string();
        bodies
            .iter()
            .enumerate()
            .map(|(index, body)| {
                let seq = index as u64 + 1;
                let hash = link_hash(seq, &prev, &[body]);
                Link {
                    seq,
                    prev: std::mem::replace(&mut prev, hash.clone()),
                    body: body.to_string(),
                    hash,
                }
            })
            .collect()
    }

    #[test]
    fn an_untouched_chain_verifies_and_an_empty_one_too() {
        assert_eq!(verify_chain(&chain(&["a", "b", "c"])), Ok(()));
        assert_eq!(verify_chain::<Link>(&[]), Ok(()));
    }

    #[test]
    fn an_edit_a_removal_or_a_reorder_is_found_at_the_record_it_breaks() {
        let mut edited = chain(&["a", "b", "c"]);
        edited[1].body = "B".to_string();
        assert_eq!(verify_chain(&edited), Err(1));

        let mut removed = chain(&["a", "b", "c"]);
        removed.remove(1);
        assert_eq!(verify_chain(&removed), Err(1));

        let mut reordered = chain(&["a", "b", "c"]);
        reordered.swap(1, 2);
        assert_eq!(verify_chain(&reordered), Err(1));

        let mut headless = chain(&["a", "b", "c"]);
        headless.remove(0);
        assert_eq!(verify_chain(&headless), Err(0));
    }

    #[test]
    fn a_field_boundary_is_part_of_the_hash() {
        assert_ne!(link_hash(1, GENESIS_HASH, &["ab", "c"]), link_hash(1, GENESIS_HASH, &["a", "bc"]));
        assert_eq!(hash_hex(""), "");
        assert_eq!(hash_hex("x").len(), 64);
    }
}

// Reserved: the Universal Agent Identifier fingerprinting subtree. `types` is
// wired (proxy caller identity, surface context, didwebvh); the dna/fingerprints/
// trust helpers await a wire-or-remove decision, so the subtree keeps a
// documented module-wide allow rather than churn its serde wire types.
#![allow(dead_code)]

pub mod dna;
pub mod fingerprints;
pub mod trust;
pub mod types;

#![allow(dead_code)]

use super::types::{AgentDna, Uai, UaiIdentity};

pub fn attach_uai(
    identity: &mut UaiIdentity,
    uai: Uai,
) {
    identity.uai = Some(uai);
}

pub fn attach_dna(
    identity: &mut UaiIdentity,
    dna: AgentDna,
) {
    identity.dna = Some(dna);
}

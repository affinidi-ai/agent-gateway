#![allow(dead_code)]

use super::types::{TrustComponents, TrustScore};

pub struct TrustComputer;

impl TrustComputer {
    pub fn new() -> Self {
        Self
    }

    pub fn compute(
        &self,
        components: TrustComponents,
    ) -> TrustScore {
        TrustScore::from_components(components)
    }
}

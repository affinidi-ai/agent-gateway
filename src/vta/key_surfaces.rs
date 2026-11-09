//! The gateway's private-key surfaces, and what was decided about each
//! (VTA-14).
//!
//! The epic's goal is "an attacker who takes the gateway cannot sign as us".
//! That claim is only as good as the **least** migrated key, so it cannot be
//! asserted in prose and left to drift — a surface added later would silently
//! falsify it. This module is the enumeration, in code, with the residual
//! exceptions computed from live configuration and reported by
//! `GET /v1/key-management/inventory`.
//!
//! The rule the dispositions follow: a key stays only when moving it would buy
//! nothing, because what it protects is already lost once the host is taken.
//! A TLS key is the clearest case — terminating TLS *is* the gateway's job, so
//! an attacker on the host serves traffic regardless of where the key sits.
//! A credential signing key is the opposite case: it mints artifacts that
//! outlive the compromise and are trusted elsewhere.

use serde::Serialize;

/// What was decided about a key surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    /// Moves to the trust agent. Until it has, it is a residual exception.
    Vta,
    /// Stays on the gateway, deliberately.
    Stays,
    /// Not the gateway's key to move — an operator supplies it.
    OutOfScope,
}

/// Whether a surface is migrated, and if not, how much it matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Holding it lets an attacker mint artifacts others trust, which outlive
    /// the compromise.
    Forgery,
    /// Holding it breaks confidentiality of traffic, but forges nothing.
    Confidentiality,
    /// Holding it matters only while the attacker is already on the host.
    HostBound,
}

/// One private-key surface.
#[derive(Debug, Clone, Serialize)]
pub struct KeySurface {
    /// Stable identifier, safe to assert on in tests and dashboards.
    pub id: &'static str,
    pub name: &'static str,
    pub disposition: Disposition,
    pub severity: Severity,
    /// Where the private half lives today.
    pub location: &'static str,
    /// What an attacker who holds it can produce. Stated concretely, because
    /// "compromise" on its own does not help anyone prioritise.
    pub forgeable: &'static str,
    /// Why the disposition is what it is.
    pub rationale: &'static str,
    /// Whether the key is off this host **right now**. `None` where the answer
    /// depends on deployment configuration this module cannot see.
    pub migrated: Option<bool>,
}

/// Every private-key surface the gateway has.
///
/// `vta_enabled` decides the surfaces that follow the signing backend. The
/// rest are fixed: a TLS key is a TLS key whatever `[vta]` says.
pub fn surfaces(vta_enabled: bool) -> Vec<KeySurface> {
    vec![
        KeySurface {
            id: "gateway_issuer",
            name: "Gateway issuer signing key",
            disposition: Disposition::Vta,
            severity: Severity::Forgery,
            location: "_storage/issuer_config.json (encrypted at rest when configured)",
            forgeable: "STS access tokens, ID-JAGs, agent-identity credentials, payment evidence, \
                        fabric issuer attestations",
            rationale: "Signs artifacts other parties trust and that outlive the compromise. Routed \
                        through CredentialAuthority since VTA-01, so enabling [vta] moves it.",
            migrated: Some(vta_enabled),
        },
        KeySurface {
            id: "gateway_webvh_update",
            name: "did:webvh update key for the gateway's own DID",
            disposition: Disposition::Vta,
            severity: Severity::Forgery,
            location: "_storage/issuer_config.json — the **same key** as the issuer signing key",
            forgeable: "A new entry in the gateway's own DID log, re-pointing its verification \
                        methods to an attacker-controlled key. What that is *worth* is now small — \
                        see the rationale.",
            rationale: "Downgraded after an audit, and the reasoning matters more than the verdict. \
                        This was the surface that could undo every other migration, because the \
                        fabric issuer attestation claimed this DID and peers resolved it to decide \
                        whose identities to accept. That attestation now claims the gateway's VTA \
                        context instead, and nothing else in production resolves this document to \
                        make a trust decision: DIDComm addresses the Connection Point DID, not this \
                        one; `x-affinidi-fabric-gateway-did` is explicitly caller-writable and not \
                        an anchor; credentials verify cryptographically rather than by resolving an \
                        issuer document; and STS verifies through the published JWKS. The document \
                        is still served at `/.well-known/did.json` — it is simply not relied upon. \
                        **The safety is contingent, not structural**: the key can still rewrite the \
                        gateway's identity, so anything that starts resolving this DID for a trust \
                        decision re-arms it in full. The residual case today is a Trust Recorder \
                        configured with a literal `authority_did` of this DID rather than the \
                        `{{ surface.issuer_did }}` template.",
            // Deliberately not `vta_enabled`: this key is the local issuer key
            // regardless of where *signing* was moved, so reporting it as
            // migrated would assert exactly the thing that is not true.
            migrated: Some(false),
        },
        KeySurface {
            id: "fabric_issuer_attestation",
            name: "Fabric issuer attestation signing",
            disposition: Disposition::Vta,
            severity: Severity::Forgery,
            location: "_storage/issuer_config.json — signs with the local issuer key, bypassing the \
                       CredentialAuthority seam",
            forgeable: "An attestation binding a Connection Point to an issuer DID, which a peer \
                        then pins and accepts identities from",
            rationale: "Signs as the gateway's **context** when `[vta]` is enabled, not with the \
                        local key: the claimed DID and the signing key must be the same party, \
                        because `check_signature` resolves the claimed `iss` and requires the key \
                        to be declared in that document. The context's `did:key` declares exactly \
                        the key that signs it, and is also the DID issuing the credentials the peer \
                        will receive — which is the property the attestation exists to establish. \
                        Routing it through the ordinary signing authority instead would claim the \
                        trust agent's DID while signing with a context key that document does not \
                        declare, and every peer would reject it; STS tokens survive that split only \
                        because they verify through the published JWKS.",
            migrated: Some(vta_enabled),
        },
        KeySurface {
            id: "agent_holder_keys",
            name: "Managed agent holder keys",
            disposition: Disposition::Vta,
            severity: Severity::Forgery,
            location: "_storage/identities/{identity_hash}.json, for agents onboarded before VTA-12",
            forgeable: "Presentations as any managed agent — the worst case, because the key belongs \
                        to someone else",
            rationale: "Migrated by VTA-12 for newly onboarded agents, whose key is minted in their \
                        own context and whose DID is a did:key with no update key. Existing records \
                        keep their key deliberately: rewriting them would change every agent's DID \
                        and invalidate credentials already issued to them.",
            // Per record, not per deployment: `vta_context_id` on each identity
            // is the real answer, so a single boolean here would be a lie in
            // either direction during migration.
            migrated: None,
        },
        KeySurface {
            id: "agent_webvh_update",
            name: "did:webvh update keys for agent DIDs",
            disposition: Disposition::Vta,
            severity: Severity::Forgery,
            location: "_storage/identities/{identity_hash}.json, for did:webvh agents",
            forgeable: "Updates to a managed agent's DID document, re-pointing its verification \
                        methods",
            rationale: "Does not arise for agents onboarded after VTA-12: their DID is a did:key, \
                        which has no mutable document and therefore no update key. Pre-migration \
                        did:webvh agents still carry one.",
            migrated: None,
        },
        KeySurface {
            id: "connection_point_keys",
            name: "Per-pairing Connection Point DID keys",
            disposition: Disposition::Vta,
            severity: Severity::Forgery,
            location: "_storage/gateways/{id}/connection-points/{cp_id}/",
            forgeable: "Fabric envelopes that appear to come from this gateway on that pairing",
            rationale: "A peer gateway admits a sender by its Connection Point DID, so holding the \
                        key impersonates this gateway to that peer. Not yet migrated; moving it \
                        requires re-pairing, because the DID is committed in the peer's record.",
            migrated: Some(false),
        },
        KeySurface {
            id: "vta_control_key",
            name: "VTA control key",
            disposition: Disposition::Stays,
            severity: Severity::Forgery,
            location: "secrets store, or TG_VTA_CONTROL_KEY_SEED, or ephemeral",
            forgeable: "Requests to the trust agent under this gateway's authority",
            rationale: "Cannot move: it is the key that authenticates *to* the trust agent, so \
                        holding it there would be circular. This is the irreducible residue of the \
                        design — the authority a compromised gateway still has. It is bounded by \
                        the grant, revocable, and every use is attributable, which is the whole \
                        difference between authority and custody.",
            migrated: Some(false),
        },
        KeySurface {
            id: "didcomm_key_agreement",
            name: "DIDComm key-agreement keys (X25519, P-256)",
            disposition: Disposition::Stays,
            severity: Severity::Confidentiality,
            location: "_storage/x25519_key.json, _storage/p256_key.json",
            forgeable: "Nothing. They decrypt rather than sign.",
            rationale: "Stays: these establish transport confidentiality for messages the gateway \
                        is the intended reader of. Moving them would mean a round trip to the trust \
                        agent per message to read mail addressed to this host, buying nothing \
                        against an attacker who is already on it.",
            migrated: Some(false),
        },
        KeySurface {
            id: "tls_server_key",
            name: "TLS server private key",
            disposition: Disposition::OutOfScope,
            severity: Severity::HostBound,
            location: "operator-supplied PEM at tls.key_path (not encrypted by the gateway)",
            forgeable: "Nothing signed. It terminates TLS.",
            rationale: "Out of scope: terminating TLS is what this host does, so an attacker on it \
                        serves traffic whether or not the key sits here. Operator-managed, like any \
                        web server's.",
            migrated: None,
        },
        KeySurface {
            id: "saml_sp_key",
            name: "SAML SP signing key",
            disposition: Disposition::OutOfScope,
            severity: Severity::Forgery,
            location: "operator-supplied PEM at the configured sp_key_path",
            forgeable: "Signed SAML AuthnRequests to the configured IdP",
            rationale: "Out of scope: supplied by the operator to match an IdP registration, and \
                        only loaded when request signing is switched on. Moving it would mean the \
                        trust agent holding a credential of the customer's identity provider.",
            migrated: None,
        },
        KeySurface {
            id: "x402_facilitator_keys",
            name: "x402 facilitator keys",
            disposition: Disposition::OutOfScope,
            severity: Severity::Forgery,
            location: "x402 config, inline or by secrets-store reference",
            forgeable: "Payment authorizations on the configured chains",
            rationale: "Out of scope here because they are blockchain account keys an operator \
                        funds and rotates, not gateway identity. An inline value is plaintext \
                        config — a secrets-store reference is the supported shape and should be \
                        preferred.",
            migrated: None,
        },
    ]
}

/// The surfaces that should be in the trust agent and are not.
///
/// This is the honest form of the epic's claim: it is empty, or it is a list.
pub fn residual_exceptions(vta_enabled: bool) -> Vec<&'static str> {
    surfaces(vta_enabled)
        .into_iter()
        .filter(|s| s.disposition == Disposition::Vta && s.migrated != Some(true))
        .map(|s| s.id)
        .collect()
}

/// Whether the gateway can honestly claim it holds no key that forges
/// something others trust.
///
/// Deliberately computed, never configured: an operator cannot set this, and a
/// surface added without a disposition cannot leave it accidentally true.
pub fn holds_no_forging_key(vta_enabled: bool) -> bool {
    !surfaces(vta_enabled)
        .into_iter()
        .any(|s| s.severity == Severity::Forgery && s.disposition == Disposition::Vta && s.migrated != Some(true))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every surface carries the fields a reader needs to act on it. A surface
    /// added with an empty rationale is a disposition nobody made.
    #[test]
    fn every_surface_is_fully_dispositioned() {
        for surface in surfaces(true) {
            assert!(!surface.id.is_empty(), "{} has no id", surface.name);
            assert!(
                !surface
                    .rationale
                    .trim()
                    .is_empty(),
                "`{}` has no rationale: a disposition without one is not a decision",
                surface.id
            );
            assert!(
                !surface
                    .forgeable
                    .trim()
                    .is_empty(),
                "`{}` does not say what it forges, which is what sets its priority",
                surface.id
            );
        }
    }

    #[test]
    fn surface_ids_are_unique() {
        let mut ids: Vec<&str> = surfaces(true)
            .iter()
            .map(|s| s.id)
            .collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate surface id");
    }

    /// Enabling the trust agent moves the issuer key and the fabric
    /// attestation, and nothing else moves by itself. Stated as a test so a
    /// future change that quietly flips another surface to "migrated" has to
    /// say so here.
    #[test]
    fn enabling_the_vta_migrates_the_issuer_key_alone() {
        let moved: Vec<&str> = surfaces(true)
            .into_iter()
            .filter(|s| s.migrated == Some(true))
            .map(|s| s.id)
            .collect();
        assert_eq!(moved, vec!["gateway_issuer", "fabric_issuer_attestation"]);

        assert!(
            surfaces(false)
                .into_iter()
                .all(|s| s.migrated != Some(true)),
            "with [vta] disabled nothing is migrated"
        );
    }

    /// The point of the whole ticket: the claim is false today, and the reason
    /// is the update key. If this test ever starts failing because the claim
    /// became true, that is the ticket being finished — update it deliberately.
    #[test]
    fn the_no_signing_key_claim_is_not_yet_true_and_says_why() {
        assert!(!holds_no_forging_key(true), "the claim must not become true by accident");
        let residual = residual_exceptions(true);
        assert!(
            residual.contains(&"gateway_webvh_update"),
            "the DID update key is the surface that can undo every other migration: {residual:?}"
        );
        assert!(!residual.contains(&"gateway_issuer"), "the issuer key does move when [vta] is enabled: {residual:?}");
    }

    /// A key that stays or is out of scope is not an exception — otherwise the
    /// residual list would never empty and would stop meaning anything.
    #[test]
    fn only_vta_dispositioned_surfaces_are_exceptions() {
        let residual = residual_exceptions(true);
        for surface in surfaces(true) {
            if surface.disposition != Disposition::Vta {
                assert!(
                    !residual.contains(&surface.id),
                    "`{}` is dispositioned {:?} and must not be listed as an exception",
                    surface.id,
                    surface.disposition
                );
            }
        }
    }

    /// The control key is the irreducible residue and must stay visible: it is
    /// what a reader needs in order to understand that this design bounds
    /// authority rather than eliminating it.
    #[test]
    fn the_control_key_is_recorded_as_staying() {
        let control = surfaces(true)
            .into_iter()
            .find(|s| s.id == "vta_control_key")
            .expect("the control key must be inventoried");
        assert_eq!(control.disposition, Disposition::Stays);
        assert_eq!(control.severity, Severity::Forgery);
    }
}

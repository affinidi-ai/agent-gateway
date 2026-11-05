//! Logos of the payment points in a Payment Manifest. A point names its logo by
//! [`LogoRef`]; agent-pay sends the bytes beside the manifest in its
//! `get-manifest` answer (`logos`). Each one is checked here as untrusted input
//! (it must be referenced by the manifest, hash to its `sha256`, and pass
//! [`validate_svg`]) and stored by hash under `<storage>/payment_logos/`, where
//! `GET /v1/gateways/payment-logos/{sha256}` serves it to the dashboard.

use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use base64::Engine;
use sha2::{Digest, Sha256};
use tracing::warn;

use super::payment_manifest::PaymentManifest;

pub const LOGO_MEDIA_TYPE: &str = "image/svg+xml";

/// Largest logo accepted, in bytes.
pub const MAX_LOGO_BYTES: usize = 32 * 1024;

/// Most logos read from one manifest answer.
const MAX_LOGOS_PER_MANIFEST: usize = 32;
/// Most logos kept on disk; past it a new logo is not stored.
const MAX_STORED_LOGOS: usize = 1024;
/// How long an unreferenced logo is kept, so one fetched for a manifest preview
/// that is not saved yet keeps showing.
const UNREFERENCED_LOGO_GRACE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// The logo a payment point is shown with.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LogoRef {
    pub id: String,
    pub media_type: String,
    /// Lowercase hex SHA-256 of the logo's bytes.
    pub sha256: String,
}

#[derive(Debug, serde::Deserialize)]
struct LogoAsset {
    sha256: String,
    media_type: String,
    data: String,
}

/// Whether `value` is a lowercase hex SHA-256, the only form a stored logo is named by.
pub fn is_logo_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn logos_dir() -> Option<PathBuf> {
    let gateways = crate::storage::get_gateways_storage_path()?;
    Some(
        Path::new(&gateways)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join("payment_logos"),
    )
}

/// Store the logos of `manifest` that `answer` (the `get-manifest` body) carries.
/// A logo that is not referenced by the manifest, does not hash to its name, or
/// fails [`validate_svg`] is skipped with a warning; logos never fail a fetch.
pub async fn store_manifest_logos(
    manifest: &PaymentManifest,
    answer: &serde_json::Value,
) {
    let Some(dir) = logos_dir() else {
        return;
    };
    store_manifest_logos_in(&dir, manifest, answer).await;
}

async fn store_manifest_logos_in(
    dir: &Path,
    manifest: &PaymentManifest,
    answer: &serde_json::Value,
) {
    let Some(assets) = answer
        .get("logos")
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };
    let present: std::collections::HashSet<String> = stored_logos(dir)
        .await
        .into_iter()
        .map(|(sha256, _)| sha256)
        .collect();
    let mut stored = present.len();
    for asset in assets
        .iter()
        .take(MAX_LOGOS_PER_MANIFEST)
    {
        match accepted_logo(manifest, asset) {
            Ok((sha256, _)) if stored >= MAX_STORED_LOGOS && !present.contains(&sha256) => {
                warn!("payment logo {sha256} not stored: {MAX_STORED_LOGOS} logos are already stored");
            }
            Ok((sha256, bytes)) => match write_logo(dir, &sha256, &bytes).await {
                Ok(true) => stored += 1,
                Ok(false) => {}
                Err(e) => warn!("payment logo {sha256} not stored: {e}"),
            },
            Err(reason) => warn!("payment logo refused: {reason}"),
        }
    }
}

fn accepted_logo(
    manifest: &PaymentManifest,
    asset: &serde_json::Value,
) -> Result<(String, Vec<u8>), String> {
    let asset: LogoAsset = serde_json::from_value(asset.clone()).map_err(|e| format!("malformed logo: {e}"))?;
    if !is_logo_hash(&asset.sha256) {
        return Err("a logo must be named by a lowercase hex SHA-256".to_string());
    }
    if asset.media_type != LOGO_MEDIA_TYPE {
        return Err(format!("logo {} is not {LOGO_MEDIA_TYPE}", asset.sha256));
    }
    let referenced = manifest
        .payment_points
        .iter()
        .filter_map(|point| point.logo.as_ref())
        .any(|logo| logo.sha256 == asset.sha256 && logo.media_type == asset.media_type);
    if !referenced {
        return Err(format!("logo {} is not referenced by the manifest", asset.sha256));
    }
    if asset.data.len() > MAX_LOGO_BYTES.div_ceil(3) * 4 {
        return Err(format!("logo {} is larger than {MAX_LOGO_BYTES} bytes", asset.sha256));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&asset.data)
        .map_err(|_| format!("logo {} is not base64", asset.sha256))?;
    if hex::encode(Sha256::digest(&bytes)) != asset.sha256 {
        return Err(format!("logo {} does not match its hash", asset.sha256));
    }
    validate_svg(&bytes).map_err(|reason| format!("logo {}: {reason}", asset.sha256))?;
    Ok((asset.sha256, bytes))
}

/// Writes the logo unless it is stored already; returns whether it wrote it.
async fn write_logo(
    dir: &Path,
    sha256: &str,
    bytes: &[u8],
) -> std::io::Result<bool> {
    let path = dir.join(format!("{sha256}.svg"));
    if tokio::fs::try_exists(&path)
        .await
        .unwrap_or(false)
    {
        return Ok(false);
    }
    tokio::fs::create_dir_all(dir).await?;
    let temporary = dir.join(format!(".{sha256}.{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&temporary, bytes).await?;
    tokio::fs::rename(&temporary, &path).await?;
    Ok(true)
}

/// The stored logos, by hash, with when each was written.
async fn stored_logos(dir: &Path) -> Vec<(String, Option<std::time::SystemTime>)> {
    let Ok(mut entries) = tokio::fs::read_dir(dir).await else {
        return Vec::new();
    };
    let mut logos = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(sha256) = name
            .to_str()
            .and_then(|name| name.strip_suffix(".svg"))
            .filter(|sha256| is_logo_hash(sha256))
        else {
            continue;
        };
        let modified = entry
            .metadata()
            .await
            .ok()
            .and_then(|metadata| metadata.modified().ok());
        logos.push((sha256.to_string(), modified));
    }
    logos
}

/// Deletes the stored logos no manifest in `manifests` references, except those
/// written within [`UNREFERENCED_LOGO_GRACE`]; returns how many it deleted.
pub async fn prune_unreferenced<'m>(manifests: impl IntoIterator<Item = &'m PaymentManifest>) -> usize {
    let Some(dir) = logos_dir() else {
        return 0;
    };
    prune_unreferenced_in(&dir, manifests, std::time::SystemTime::now()).await
}

async fn prune_unreferenced_in<'m>(
    dir: &Path,
    manifests: impl IntoIterator<Item = &'m PaymentManifest>,
    now: std::time::SystemTime,
) -> usize {
    let referenced: std::collections::HashSet<&str> = manifests
        .into_iter()
        .flat_map(|manifest| manifest.payment_points.iter())
        .filter_map(|point| point.logo.as_ref())
        .map(|logo| logo.sha256.as_str())
        .collect();
    let mut pruned = 0;
    for (sha256, modified) in stored_logos(dir).await {
        let recent = modified.is_none_or(|modified| {
            now.duration_since(modified)
                .is_ok_and(|age| age < UNREFERENCED_LOGO_GRACE)
                || now < modified
        });
        if referenced.contains(sha256.as_str()) || recent {
            continue;
        }
        match tokio::fs::remove_file(dir.join(format!("{sha256}.svg"))).await {
            Ok(()) => pruned += 1,
            Err(e) => warn!("unreferenced payment logo {sha256} not removed: {e}"),
        }
    }
    pruned
}

/// The stored logo named `sha256`, when there is one whose bytes still hash to that name.
pub async fn read_logo(sha256: &str) -> Option<Vec<u8>> {
    read_logo_in(&logos_dir()?, sha256).await
}

async fn read_logo_in(
    dir: &Path,
    sha256: &str,
) -> Option<Vec<u8>> {
    if !is_logo_hash(sha256) {
        return None;
    }
    let bytes = tokio::fs::read(dir.join(format!("{sha256}.svg")))
        .await
        .ok()?;
    (hex::encode(Sha256::digest(&bytes)) == sha256).then_some(bytes)
}

static EVENT_HANDLER: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"[\s/]on[a-z]+\s*=").expect("event handler pattern"));
static HREF: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"href\s*=\s*["']?\s*([^"'\s>]*)"#).expect("href pattern"));
static URL_REF: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"url\(\s*["']?\s*([^"')\s]*)"#).expect("url() pattern"));

/// Whether `bytes` is a logo safe to show: a UTF-8 SVG of at most
/// [`MAX_LOGO_BYTES`] with no script, event handler, embedded document or
/// image, entity or doctype, stylesheet import, or reference outside the
/// document (every `href` and `url()` must be `#…`). The same check agent-pay
/// applies before sending a logo.
pub fn validate_svg(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_LOGO_BYTES {
        return Err(format!("a logo must be 1 to {MAX_LOGO_BYTES} bytes"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "a logo must be UTF-8 text".to_string())?;
    let lower = text.to_ascii_lowercase();
    if !lower.contains("<svg") {
        return Err("a logo must be an SVG document".to_string());
    }
    for banned in [
        "<script",
        "<foreignobject",
        "<iframe",
        "<object",
        "<embed",
        "<image",
        "<!entity",
        "<!doctype",
        "javascript:",
        "@import",
    ] {
        if lower.contains(banned) {
            return Err(format!("a logo must not contain `{banned}`"));
        }
    }
    if EVENT_HANDLER.is_match(&lower) {
        return Err("a logo must not contain event handlers".to_string());
    }
    for captures in HREF
        .captures_iter(&lower)
        .chain(URL_REF.captures_iter(&lower))
    {
        if !captures[1].starts_with('#') {
            return Err("a logo may only reference its own elements".to_string());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateways::payment_manifest::PaymentPoint;

    const SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><linearGradient id="g"/></defs><rect fill="url(#g)"/></svg>"##;

    fn sha(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn manifest_with_logo(sha256: &str) -> PaymentManifest {
        PaymentManifest {
            payment_points: vec![PaymentPoint {
                id: "x402:base".into(),
                logo: Some(LogoRef {
                    id: "base".into(),
                    media_type: LOGO_MEDIA_TYPE.into(),
                    sha256: sha256.into(),
                }),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn answer(
        sha256: &str,
        bytes: &[u8],
    ) -> serde_json::Value {
        serde_json::json!({ "logos": [{
            "sha256": sha256,
            "media_type": LOGO_MEDIA_TYPE,
            "data": base64::engine::general_purpose::STANDARD.encode(bytes),
        }]})
    }

    #[tokio::test]
    async fn a_referenced_logo_matching_its_hash_is_stored_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let hash = sha(SVG.as_bytes());

        store_manifest_logos_in(dir.path(), &manifest_with_logo(&hash), &answer(&hash, SVG.as_bytes())).await;

        assert_eq!(
            read_logo_in(dir.path(), &hash)
                .await
                .as_deref(),
            Some(SVG.as_bytes())
        );
    }

    fn svg_numbered(n: usize) -> String {
        SVG.replace("<rect", &format!("<rect id=\"r{n}\""))
    }

    #[tokio::test]
    async fn no_new_logo_is_stored_past_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        for n in 0..MAX_STORED_LOGOS {
            std::fs::write(
                dir.path()
                    .join(format!("{}.svg", sha(n.to_string().as_bytes()))),
                b"x",
            )
            .unwrap();
        }
        let svg = svg_numbered(1);
        let hash = sha(svg.as_bytes());

        store_manifest_logos_in(dir.path(), &manifest_with_logo(&hash), &answer(&hash, svg.as_bytes())).await;

        assert_eq!(read_logo_in(dir.path(), &hash).await, None);
        assert_eq!(
            stored_logos(dir.path())
                .await
                .len(),
            MAX_STORED_LOGOS
        );
    }

    #[tokio::test]
    async fn pruning_keeps_referenced_and_recent_logos_and_deletes_old_unreferenced_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mut hashes = Vec::new();
        for n in 0..2 {
            let svg = svg_numbered(n);
            let hash = sha(svg.as_bytes());
            store_manifest_logos_in(dir.path(), &manifest_with_logo(&hash), &answer(&hash, svg.as_bytes())).await;
            hashes.push(hash);
        }
        let referenced = manifest_with_logo(&hashes[0]);

        assert_eq!(
            prune_unreferenced_in(dir.path(), [&referenced], std::time::SystemTime::now()).await,
            0,
            "a logo written within the grace period is kept"
        );
        let later = std::time::SystemTime::now() + UNREFERENCED_LOGO_GRACE + std::time::Duration::from_secs(1);
        assert_eq!(prune_unreferenced_in(dir.path(), [&referenced], later).await, 1);
        assert!(
            read_logo_in(dir.path(), &hashes[0])
                .await
                .is_some()
        );
        assert_eq!(read_logo_in(dir.path(), &hashes[1]).await, None);
    }

    #[tokio::test]
    async fn a_logo_is_refused_when_unreferenced_mismatched_or_unsafe() {
        let dir = tempfile::tempdir().unwrap();
        let hash = sha(SVG.as_bytes());
        let unsafe_svg = br#"<svg><script>alert(1)</script></svg>"#;
        let unsafe_hash = sha(unsafe_svg);

        store_manifest_logos_in(dir.path(), &manifest_with_logo(&"a".repeat(64)), &answer(&hash, SVG.as_bytes())).await;
        assert_eq!(read_logo_in(dir.path(), &hash).await, None, "not referenced by the manifest");

        store_manifest_logos_in(dir.path(), &manifest_with_logo(&hash), &answer(&hash, b"<svg/>")).await;
        assert_eq!(read_logo_in(dir.path(), &hash).await, None, "bytes do not hash to the name");

        store_manifest_logos_in(dir.path(), &manifest_with_logo(&unsafe_hash), &answer(&unsafe_hash, unsafe_svg)).await;
        assert_eq!(read_logo_in(dir.path(), &unsafe_hash).await, None, "unsafe svg");

        let mut png = answer(&hash, SVG.as_bytes());
        png["logos"][0]["media_type"] = serde_json::json!("image/png");
        store_manifest_logos_in(dir.path(), &manifest_with_logo(&hash), &png).await;
        assert_eq!(read_logo_in(dir.path(), &hash).await, None, "only svg is accepted");
    }

    #[tokio::test]
    async fn reading_refuses_a_malformed_name_and_a_tampered_file() {
        let dir = tempfile::tempdir().unwrap();
        let hash = sha(SVG.as_bytes());
        assert_eq!(read_logo_in(dir.path(), "../../etc/passwd").await, None);
        assert_eq!(read_logo_in(dir.path(), &hash.to_uppercase()).await, None);

        tokio::fs::write(
            dir.path()
                .join(format!("{hash}.svg")),
            b"<svg>changed</svg>",
        )
        .await
        .unwrap();
        assert_eq!(read_logo_in(dir.path(), &hash).await, None);
    }

    #[test]
    fn unsafe_or_oversized_svgs_are_refused() {
        let svg = |inner: &str| format!(r#"<svg xmlns="http://www.w3.org/2000/svg">{inner}</svg>"#);
        for unsafe_svg in [
            svg("<script>alert(1)</script>"),
            svg(r#"<rect onload="alert(1)"/>"#),
            svg(r#"<rect/onclick="x"/>"#),
            svg("<foreignObject><div/></foreignObject>"),
            svg(r#"<image href="https://evil.example/x.png"/>"#),
            svg(r#"<use xlink:href="https://evil.example/s.svg#a"/>"#),
            svg(r#"<rect fill="url(https://evil.example/p)"/>"#),
            svg("<style>@import 'https://evil.example/s.css';</style>"),
            format!("<!DOCTYPE svg [<!ENTITY x 'y'>]>{}", svg("")),
            "<html><body/></html>".to_string(),
        ] {
            assert!(validate_svg(unsafe_svg.as_bytes()).is_err(), "{unsafe_svg}");
        }
        assert!(validate_svg(&vec![b' '; MAX_LOGO_BYTES + 1]).is_err());
        assert_eq!(validate_svg(SVG.as_bytes()), Ok(()));
    }
}

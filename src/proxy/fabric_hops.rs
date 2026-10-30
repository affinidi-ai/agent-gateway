//! How many Fabric crossings a request has made. Gateways carry the count in
//! `X-Gateway-Fabric-Hops`; inside a gateway it rides in the transit token the
//! receiving gateway issues, so an agent cannot lower it. A request past
//! [`MAX_FABRIC_HOPS`] crossings is refused, which bounds chains of agents that
//! call each other through their gateways.

use std::collections::HashMap;

/// The header every Fabric send sets: the number of Fabric crossings the request
/// has made, this one included. No caller, agent or peer copy is forwarded.
pub(crate) const FABRIC_HOPS_HEADER: &str = "x-gateway-fabric-hops";

/// The most Fabric crossings a request may make.
pub(crate) const MAX_FABRIC_HOPS: u8 = 8;

/// The count an Access Point's Fabric send carries, and a Transit Point's when the
/// managed agent's transit token was not issued for a request that arrived over
/// Fabric.
pub(crate) const FIRST_FABRIC_HOP: u8 = 1;

/// Why a received hop count refuses the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FabricHopsRefusal {
    /// Not a single integer from 1 to 255.
    Malformed,
    /// More than [`MAX_FABRIC_HOPS`] crossings.
    TooMany,
}

pub(crate) fn is_fabric_hops_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(FABRIC_HOPS_HEADER)
}

/// The hop count a received request carries, from every value of the header in
/// any case: [`FIRST_FABRIC_HOP`] when there is none, as from a sender that
/// predates the header.
pub(crate) fn received_fabric_hops<'value>(
    values: impl IntoIterator<Item = &'value str>
) -> Result<u8, FabricHopsRefusal> {
    let mut values = values.into_iter();
    let Some(value) = values.next() else {
        return Ok(FIRST_FABRIC_HOP);
    };
    if values.next().is_some()
        || value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(FabricHopsRefusal::Malformed);
    }
    match value.parse::<u8>() {
        Ok(0) | Err(_) => Err(FabricHopsRefusal::Malformed),
        Ok(hops) if hops > MAX_FABRIC_HOPS => Err(FabricHopsRefusal::TooMany),
        Ok(hops) => Ok(hops),
    }
}

/// The count a Transit Point's Fabric send carries: one more than the Fabric
/// crossings its managed agent's transit token records, or [`FIRST_FABRIC_HOP`]
/// for a token issued for a direct request, or no token. `None` past
/// [`MAX_FABRIC_HOPS`].
pub(crate) fn next_fabric_hops(token_hops: Option<u8>) -> Option<u8> {
    match token_hops {
        None => Some(FIRST_FABRIC_HOP),
        Some(hops) => hops
            .checked_add(1)
            .filter(|next| *next <= MAX_FABRIC_HOPS),
    }
}

/// Sets the hop count on a buffered Fabric forward's headers, replacing every
/// other copy of the header in any case.
pub(crate) fn set_fabric_hops(
    headers: &mut HashMap<String, String>,
    hops: u8,
) {
    headers.retain(|name, _| !is_fabric_hops_header(name));
    headers.insert(FABRIC_HOPS_HEADER.to_ascii_uppercase(), hops.to_string());
}

/// Sets the hop count on a framed Fabric stream's headers.
pub(crate) fn set_stream_fabric_hops(
    headers: &mut axum::http::HeaderMap,
    hops: u8,
) {
    headers.insert(
        axum::http::HeaderName::from_static(FABRIC_HOPS_HEADER),
        axum::http::HeaderValue::from(u16::from(hops)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_received_count_is_one_integer_from_one_to_the_limit() {
        assert_eq!(received_fabric_hops([]), Ok(FIRST_FABRIC_HOP), "an older sender sends none");
        for (value, expected) in [("1", Ok(1)), ("3", Ok(3)), ("8", Ok(8)), ("08", Ok(8))] {
            assert_eq!(received_fabric_hops([value]), expected, "{value}");
        }
        for value in ["9", "255"] {
            assert_eq!(received_fabric_hops([value]), Err(FabricHopsRefusal::TooMany), "{value}");
        }
        for value in ["0", "256", "-1", "+3", " 3", "3 ", "3.0", "three", "", "99999999999"] {
            assert_eq!(received_fabric_hops([value]), Err(FabricHopsRefusal::Malformed), "{value:?}");
        }
        assert_eq!(received_fabric_hops(["2", "2"]), Err(FabricHopsRefusal::Malformed), "two copies");
    }

    #[test]
    fn a_transit_point_adds_one_crossing_and_stops_at_the_limit() {
        assert_eq!(next_fabric_hops(None), Some(1));
        assert_eq!(next_fabric_hops(Some(1)), Some(2));
        assert_eq!(next_fabric_hops(Some(7)), Some(8));
        assert_eq!(next_fabric_hops(Some(8)), None);
        assert_eq!(next_fabric_hops(Some(u8::MAX)), None);
    }

    #[test]
    fn a_send_replaces_every_other_copy_of_the_count() {
        let mut headers = HashMap::from([
            ("X-Gateway-Fabric-Hops".to_string(), "1".to_string()),
            ("x-gateway-fabric-hops".to_string(), "2".to_string()),
            ("X-OTHER".to_string(), "kept".to_string()),
        ]);
        set_fabric_hops(&mut headers, 3);
        assert_eq!(
            headers,
            HashMap::from([
                ("X-GATEWAY-FABRIC-HOPS".to_string(), "3".to_string()),
                ("X-OTHER".to_string(), "kept".to_string()),
            ])
        );

        let mut stream = axum::http::HeaderMap::new();
        stream.append("X-Gateway-Fabric-Hops", axum::http::HeaderValue::from_static("7"));
        stream.append("x-gateway-fabric-hops", axum::http::HeaderValue::from_static("6"));
        set_stream_fabric_hops(&mut stream, 2);
        assert_eq!(
            stream
                .get_all(FABRIC_HOPS_HEADER)
                .iter()
                .collect::<Vec<_>>(),
            ["2"]
        );
    }
}

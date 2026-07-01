//! Selection query model.
//!
//! Simpler than Mullvad's `RelayQuery`: no providers / ownership /
//! multihop / obfuscation / DAITA constraints. Warren = a single Warren exit
//! QUIC tunnel; geo + IP availability are sufficient.

use crate::WarrenRelay;

/// Location constraint: none, by country, or by (country, city) pair.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LocationConstraint {
    /// No location constraint.
    #[default]
    Any,
    /// Match by ISO-3166 alpha-2 country code (case-insensitive).
    Country(String),
    /// Match by (country code, city name) pair. Both the country code
    /// and the city are compared case-insensitively: the GUI emits the
    /// lower-cased city while the relay list stores the upstream-cased
    /// name (e.g. query `kassel` vs relay `Kassel`).
    City {
        /// ISO-3166 alpha-2 country code.
        country_code: String,
        /// City name (free form).
        city: String,
    },
}

/// IP availability required at selection time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IpAvailability {
    /// Client has both v4 AND v6 - any relay is fine.
    #[default]
    Both,
    /// Client has v4 only - exclude v6-only relays.
    Ipv4Only,
    /// Client has v6 only - exclude v4-only relays.
    Ipv6Only,
}

/// Composite selection query.
#[derive(Debug, Clone, Default)]
pub struct WarrenRelayQuery {
    location: LocationConstraint,
    ip_availability: IpAvailability,
    require_ipv6_egress: bool,
}

impl WarrenRelayQuery {
    /// Query without any constraint (equivalent to
    /// [`Default::default`]).
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Adds a location constraint (consumes + returns self).
    #[must_use]
    pub fn with_location(mut self, location: LocationConstraint) -> Self {
        self.location = location;
        self
    }

    /// Adds an IP availability constraint (consumes + returns self).
    #[must_use]
    pub fn with_ip_availability(mut self, ip: IpAvailability) -> Self {
        self.ip_availability = ip;
        self
    }

    /// Requires exits with attested IPv6 *egress* (consumes + returns
    /// self). Set it when the client intends to route in-tunnel IPv6:
    /// an exit without the capability would blackhole that traffic.
    #[must_use]
    pub fn with_require_ipv6_egress(mut self, require: bool) -> Self {
        self.require_ipv6_egress = require;
        self
    }

    /// `true` if `relay` satisfies every constraint of the query.
    #[must_use]
    pub(crate) fn matches(&self, relay: &WarrenRelay) -> bool {
        if !relay.is_active() {
            return false;
        }
        if !location_matches(&self.location, relay) {
            return false;
        }
        if !ip_matches(self.ip_availability, relay) {
            return false;
        }
        if self.require_ipv6_egress && !relay.egress_v6() {
            return false;
        }
        true
    }
}

fn location_matches(constraint: &LocationConstraint, relay: &WarrenRelay) -> bool {
    match constraint {
        LocationConstraint::Any => true,
        LocationConstraint::Country(cc) => relay.location().country_code().eq_ignore_ascii_case(cc),
        LocationConstraint::City { country_code, city } => {
            relay
                .location()
                .country_code()
                .eq_ignore_ascii_case(country_code)
                && relay.location().city().eq_ignore_ascii_case(city)
        }
    }
}

fn ip_matches(ip: IpAvailability, relay: &WarrenRelay) -> bool {
    match ip {
        IpAvailability::Both => relay.has_ipv4() || relay.has_ipv6(),
        IpAvailability::Ipv4Only => relay.has_ipv4(),
        IpAvailability::Ipv6Only => relay.has_ipv6(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WarrenRelayList;

    /// A single active relay in `DE` / `Kassel` (upstream-cased city),
    /// built through the real JSON ingest path.
    fn de_kassel_list() -> WarrenRelayList {
        // One active node in DE/Kassel with a single v4 entry endpoint and
        // v4-only egress capability (no v6 egress), built through the real
        // JSON ingest (v4 minimized node format).
        let json = format!(
            r#"{{"version":4,"nodes":[{{"id":"{eid}","exit_id":"{xid}","location":{{"country":"DE","city":"Kassel"}},"weight":100,"active":true,"egress":{{"ipv4":true,"ipv6":false}},"endpoints":[{{"addr":"127.0.0.1","family":"ipv4","listeners":[{{"port":7000,"transport":"quic","alpn":"h3"}}]}}]}}]}}"#,
            eid = "00".repeat(32),
            xid = "aa".repeat(16),
        );
        WarrenRelayList::from_json_str(&json).expect("valid warren-relays.json")
    }

    #[test]
    fn city_constraint_matches_case_insensitively() {
        // Regression: the GUI emits the lower-cased city (`kassel`) while
        // the relay stores the upstream-cased name (`Kassel`). Selecting a
        // specific server MUST still match; previously it was compared
        // char-by-char and produced `NoRelayMatch`, blocking the tunnel.
        let list = de_kassel_list();
        let relay = &list.relays()[0];
        let query = WarrenRelayQuery::any().with_location(LocationConstraint::City {
            country_code: "de".to_owned(),
            city: "kassel".to_owned(),
        });
        assert!(
            query.matches(relay),
            "city match must be case-insensitive: query 'kassel' vs relay 'Kassel'"
        );
    }

    #[test]
    fn ipv6_egress_requirement_excludes_relays_without_the_capability() {
        // A client that wants working in-tunnel IPv6 must never be
        // routed to an exit that cannot egress v6: the traffic would
        // silently blackhole. The node here has only a v4 egress
        // endpoint, so `egress_v6()` is false → not capable.
        let list = de_kassel_list();
        let relay = &list.relays()[0];
        let query = WarrenRelayQuery::any().with_require_ipv6_egress(true);
        assert!(
            !query.matches(relay),
            "an exit without proven IPv6 egress must not match"
        );

        let unconstrained = WarrenRelayQuery::any();
        assert!(
            unconstrained.matches(relay),
            "the same exit must keep matching when v6 egress is not required"
        );
    }

    #[test]
    fn city_constraint_still_rejects_a_different_city() {
        // Guard: case-insensitivity must not degrade into match-anything.
        let list = de_kassel_list();
        let relay = &list.relays()[0];
        let query = WarrenRelayQuery::any().with_location(LocationConstraint::City {
            country_code: "de".to_owned(),
            city: "berlin".to_owned(),
        });
        assert!(
            !query.matches(relay),
            "a different city must not match (Berlin != Kassel)"
        );
    }
}

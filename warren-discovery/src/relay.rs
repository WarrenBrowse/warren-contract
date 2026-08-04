//! Data model for a Warren node (entry / relay / exit).
//!
//! v7 model: a node's role is **structural**, expressed by three vectors
//! ([`WarrenRelay::entry`] / [`WarrenRelay::relay`] / [`WarrenRelay::exit`])
//! instead of a separate `roles` enum. A node is an *entry* if it has
//! direct dial points, a *relay* if it has relay facets, an *exit* if it
//! has exit facets. The public single-hop list ([`crate::signed`]) projects
//! only the minimum a client dials; the egress source IPs ([`Exit::egress`])
//! and the relay-facing exit ingress ([`Exit::ingress`]) are never published
//! to clients (they live in the canonical/admin structure and, for the
//! relay-facing endpoint, a relay-only channel).
//!
//! The dial target consumed by the tunnel ([`WarrenRelay::endpoint_addr`])
//! is derived from the `entry` ingress listeners. Node-level egress
//! capability is derived from the families present in the exit egress
//! addresses ([`WarrenRelay::egress_v4`] / [`WarrenRelay::egress_v6`]).

use std::net::{IpAddr, SocketAddr};

use warrenguard_wire::{ExitId, WarrenExitAddr, WarrenPubkey};

/// Node geolocation (country + city), MANUAL and authoritative for
/// selection.
///
/// The country code is normalized to lower-case ASCII so filter
/// comparisons can avoid `eq_ignore_ascii_case`. The city is kept as
/// provided.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Location {
    country_code: String,
    city: String,
}

impl Location {
    /// Builds a `Location`, lower-casing the country code.
    #[must_use]
    pub fn new(country_code: impl Into<String>, city: impl Into<String>) -> Self {
        let mut cc = country_code.into();
        cc.make_ascii_lowercase();
        Self {
            country_code: cc,
            city: city.into(),
        }
    }

    /// ISO-3166 alpha-2 country code, lower-case (`se`, `fr`, `de`, ...).
    #[must_use]
    pub fn country_code(&self) -> &str {
        &self.country_code
    }

    /// City name (free form).
    #[must_use]
    pub fn city(&self) -> &str {
        &self.city
    }
}

/// IP family of an [`Addr`]. Stored explicitly (and kept consistent with
/// the address by [`Addr::new`]) so a wire mislabel is detectable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// IPv4.
    V4,
    /// IPv6.
    V6,
}

impl Family {
    /// The family of an [`IpAddr`].
    #[must_use]
    pub fn of(ip: IpAddr) -> Self {
        if ip.is_ipv6() { Self::V6 } else { Self::V4 }
    }

    /// `"ipv4"` / `"ipv6"`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}

/// A way to dial an ingress: a `port` plus the wire `transport` (e.g.
/// `quic`) and the `alpn` token offered in the handshake (e.g. `h3`). The
/// `(transport, alpn)` pair is what the app surfaces as a selectable
/// connection type / obfuscation choice.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Listener {
    port: u16,
    transport: String,
    alpn: String,
}

impl Listener {
    /// Builds a listener.
    #[must_use]
    pub fn new(port: u16, transport: impl Into<String>, alpn: impl Into<String>) -> Self {
        Self {
            port,
            transport: transport.into(),
            alpn: alpn.into(),
        }
    }

    /// Listening port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Wire transport (`quic`, future `masque`, ...).
    #[must_use]
    pub fn transport(&self) -> &str {
        &self.transport
    }

    /// ALPN token offered in the handshake / connection-type id (`h3`).
    #[must_use]
    pub fn alpn(&self) -> &str {
        &self.alpn
    }
}

/// API-derived geolocation of an IP address: the ground truth
/// geo-restricted services see. Distinct from the node's manual
/// [`Location`] (authoritative for selection); may legitimately disagree.
/// Internal/admin only, never projected onto the public client lists.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GeoIp {
    location: Location,
    asn: Option<u32>,
    source: String,
}

impl GeoIp {
    /// Builds a geoip record.
    #[must_use]
    pub fn new(location: Location, asn: Option<u32>, source: impl Into<String>) -> Self {
        Self {
            location,
            asn,
            source: source.into(),
        }
    }

    /// Resolved geolocation (country/city).
    #[must_use]
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Autonomous system number, when resolved.
    #[must_use]
    pub fn asn(&self) -> Option<u32> {
        self.asn
    }

    /// DB edition + date the resolution came from (e.g.
    /// `GeoLite2-City-2026-06`).
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// A node address: the IP, its [`Family`], and an optional API-derived
/// [`GeoIp`]. The common building block of [`Ingress`] and [`Egress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addr {
    ipaddr: IpAddr,
    family: Family,
    geoip: Option<GeoIp>,
}

impl Addr {
    /// Builds an address, deriving [`Family`] from `ipaddr`.
    #[must_use]
    pub fn new(ipaddr: IpAddr, geoip: Option<GeoIp>) -> Self {
        Self {
            ipaddr,
            family: Family::of(ipaddr),
            geoip,
        }
    }

    /// The IP address.
    #[must_use]
    pub fn ipaddr(&self) -> IpAddr {
        self.ipaddr
    }

    /// The IP family.
    #[must_use]
    pub fn family(&self) -> Family {
        self.family
    }

    /// API-derived geoip, when resolved (admin/diagnostics only).
    #[must_use]
    pub fn geoip(&self) -> Option<&GeoIp> {
        self.geoip.as_ref()
    }
}

/// A dialable inbound point: an [`Addr`] plus the `{port, transport, alpn}`
/// listeners served there. Used for direct entry endpoints, relay
/// endpoints, and the relay-facing endpoints of an exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ingress {
    addr: Addr,
    listener: Vec<Listener>,
}

impl Ingress {
    /// Builds an ingress point.
    #[must_use]
    pub fn new(addr: Addr, listener: Vec<Listener>) -> Self {
        Self { addr, listener }
    }

    /// The address.
    #[must_use]
    pub fn addr(&self) -> &Addr {
        &self.addr
    }

    /// The listeners served at this address.
    #[must_use]
    pub fn listener(&self) -> &[Listener] {
        &self.listener
    }
}

/// A relay facet: where the relay is dialed ([`Ingress`]) plus its own
/// TLS RPK identity and routing tag, **distinct from the node identity**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    ingress: Ingress,
    rpk: [u8; 32],
    relay_id: [u8; 16],
}

impl Endpoint {
    /// Builds a relay endpoint facet.
    #[must_use]
    pub fn new(ingress: Ingress, rpk: [u8; 32], relay_id: [u8; 16]) -> Self {
        Self {
            ingress,
            rpk,
            relay_id,
        }
    }

    /// Where the relay is dialed.
    #[must_use]
    pub fn ingress(&self) -> &Ingress {
        &self.ingress
    }

    /// The relay's Ed25519 RPK (TLS pin), distinct from the node id.
    #[must_use]
    pub fn rpk(&self) -> &[u8; 32] {
        &self.rpk
    }

    /// The relay routing tag (relay-side), distinct from the node exit_id.
    #[must_use]
    pub fn relay_id(&self) -> &[u8; 16] {
        &self.relay_id
    }
}

/// An egress source: the IP the internet sees. **Never published to
/// clients** (only the canonical/admin structure carries it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Egress {
    addr: Addr,
}

impl Egress {
    /// Builds an egress source.
    #[must_use]
    pub fn new(addr: Addr) -> Self {
        Self { addr }
    }

    /// The egress source address.
    #[must_use]
    pub fn addr(&self) -> &Addr {
        &self.addr
    }
}

/// An exit facet: the exit crypto (RPK + HPKE recipient key + DNS flag),
/// the relay-facing [`Ingress`] points (where relays dial the exit;
/// relay-only) and the hidden [`Egress`] source addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    rpk: [u8; 32],
    hpke_pubkey: [u8; 32],
    dns_disabled: bool,
    ingress: Vec<Ingress>,
    egress: Vec<Egress>,
}

impl Exit {
    /// Builds an exit facet.
    #[must_use]
    pub fn new(
        rpk: [u8; 32],
        hpke_pubkey: [u8; 32],
        dns_disabled: bool,
        ingress: Vec<Ingress>,
        egress: Vec<Egress>,
    ) -> Self {
        Self {
            rpk,
            hpke_pubkey,
            dns_disabled,
            ingress,
            egress,
        }
    }

    /// Exit Ed25519 RPK (relay→exit pin).
    #[must_use]
    pub fn rpk(&self) -> &[u8; 32] {
        &self.rpk
    }

    /// X25519 HPKE recipient key (the client seals frames to it).
    #[must_use]
    pub fn hpke_pubkey(&self) -> &[u8; 32] {
        &self.hpke_pubkey
    }

    /// Whether the exit attests it runs no recursive resolver.
    #[must_use]
    pub fn dns_disabled(&self) -> bool {
        self.dns_disabled
    }

    /// Relay-facing dial points (where relays reach the exit). Relay-only.
    #[must_use]
    pub fn ingress(&self) -> &[Ingress] {
        &self.ingress
    }

    /// Egress source addresses (hidden from clients).
    #[must_use]
    pub fn egress(&self) -> &[Egress] {
        &self.egress
    }
}

/// A Warren node: identity + structural role facets + selection metadata.
///
/// `weight == 0` effectively disables the node for weighted selection
/// even when `active == true`.
///
/// `exit_id` is the operator-assigned stable identifier that survives
/// legitimate Ed25519 rotation. It anchors TOFU pinning.
///
/// The struct keeps the name `WarrenRelay` for source-compat with the
/// many call sites; it models a *node*.
#[derive(Debug, Clone)]
pub struct WarrenRelay {
    id: WarrenPubkey,
    exit_id: ExitId,
    location: Location,
    weight: u64,
    active: bool,
    entry: Vec<Ingress>,
    relay: Vec<Endpoint>,
    exit: Vec<Exit>,
    /// Node-level egress capability (can route in-tunnel traffic to the
    /// v4 / v6 internet). On the admin/full side it is derived from the
    /// families of [`Exit::egress`]; on the public client side it comes
    /// straight from the v7 wire booleans (no egress address published).
    egress_v4_cap: bool,
    egress_v6_cap: bool,
    /// Node-level NAT-PMP port-forwarding capability (doc 79). `Some(true)` if
    /// the exit runs an enabled NAT-PMP gateway, `Some(false)` if it is
    /// explicitly disabled, `None` if the signed roster carried no flag (exit
    /// binary pre-dates it: unknown). Comes straight from the v9 wire; the
    /// client only offers or prefers port forwarding when it is `Some(true)`.
    port_forward: Option<bool>,
    /// Derived dial target (entry listeners → sockets), cached at
    /// construction so the hot dial path stays cheap.
    endpoint_addr: WarrenExitAddr,
}

impl WarrenRelay {
    /// Builds a node from the **full canonical** facets (admin side). The
    /// egress capability is derived from the families present in the exit
    /// egress addresses; `endpoint_addr` (the single-hop tunnel dial
    /// target) is derived from the `entry` ingress listeners.
    // The node identity + selection metadata + the three structural role
    // facets are genuinely independent inputs; bundling them into a params
    // struct would only move the same fields elsewhere without clarity.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        id: WarrenPubkey,
        exit_id: ExitId,
        location: Location,
        weight: u64,
        active: bool,
        entry: Vec<Ingress>,
        relay: Vec<Endpoint>,
        exit: Vec<Exit>,
    ) -> Self {
        let egress_v4_cap = egress_has_family(&exit, Family::V4);
        let egress_v6_cap = egress_has_family(&exit, Family::V6);
        let endpoint_addr = derive_endpoint_addr(id, &entry);
        Self {
            id,
            exit_id,
            location,
            weight,
            active,
            entry,
            relay,
            exit,
            egress_v4_cap,
            egress_v6_cap,
            port_forward: None,
            endpoint_addr,
        }
    }

    /// Builds a node from the **public v7 wire** projection (client side):
    /// only the direct `entry` endpoints are known, and egress is two
    /// capability booleans (no egress source address is published to
    /// clients). The `relay` / `exit` facets are empty client-side.
    // Same rationale as `new`: identity + selection metadata + entry +
    // egress caps are independent wire-derived inputs.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn from_public(
        id: WarrenPubkey,
        exit_id: ExitId,
        location: Location,
        weight: u64,
        active: bool,
        entry: Vec<Ingress>,
        egress_v4: bool,
        egress_v6: bool,
    ) -> Self {
        let endpoint_addr = derive_endpoint_addr(id, &entry);
        Self {
            id,
            exit_id,
            location,
            weight,
            active,
            entry,
            relay: Vec::new(),
            exit: Vec::new(),
            egress_v4_cap: egress_v4,
            egress_v6_cap: egress_v6,
            port_forward: None,
            endpoint_addr,
        }
    }

    /// Stamps a v6 X.509 cover-domain SNI (wg-0005) onto this node's dial
    /// target. Carried on the signed roster node (`cover_domain`); `None`
    /// keeps the raw-public-key handshake untouched. The client dials this
    /// hostname as SNI and validates the exit's real certificate via WebPKI
    /// instead of pinning the Ed25519 raw public key.
    #[must_use]
    pub fn with_cover_domain(mut self, cover_domain: Option<String>) -> Self {
        if let Some(domain) = cover_domain {
            self.endpoint_addr = self.endpoint_addr.with_cover_domain(domain);
        }
        self
    }

    /// Stamps the node-level NAT-PMP port-forwarding capability (doc 79) carried
    /// by the v9 signed roster. `None` (legacy exit that pre-dates the flag)
    /// leaves the capability unknown, which the client treats as "not offered".
    #[must_use]
    pub fn with_port_forward(mut self, port_forward: Option<bool>) -> Self {
        self.port_forward = port_forward;
        self
    }

    /// Stamps the node-level TLS-over-TCP fallback carrier capability (v10)
    /// carried by the signed roster onto this node's single-hop dial target.
    /// Only `Some(true)` arms the capability on the [`WarrenExitAddr`]; `None`
    /// (legacy exit) or `Some(false)` leaves the exit dialed over UDP only, so a
    /// blocked handshake is never pointlessly retried over TCP. Mirrors
    /// [`with_cover_domain`](Self::with_cover_domain): the flag rides inside
    /// `endpoint_addr`, so no `WarrenRelay`-level field or selector plumbing is
    /// needed.
    #[must_use]
    pub fn with_tcp_fallback(mut self, tcp_fallback: Option<bool>) -> Self {
        if tcp_fallback == Some(true) {
            self.endpoint_addr = self.endpoint_addr.with_tcp_fallback();
        }
        self
    }

    /// Ed25519 identity of the node (32-byte pubkey).
    #[must_use]
    pub fn id(&self) -> WarrenPubkey {
        self.id
    }

    /// Ed25519 identity of the node (alias of [`Self::id`], kept for
    /// source-compat with existing call sites).
    #[must_use]
    pub fn endpoint_id(&self) -> WarrenPubkey {
        self.id
    }

    /// Stable operator-assigned identifier (16 bytes). Anchors TOFU
    /// pinning.
    #[must_use]
    pub fn exit_id(&self) -> ExitId {
        self.exit_id
    }

    /// Single-hop dial target (IPv4/IPv6 UDP sockets), derived from the
    /// `entry` ingress listeners.
    #[must_use]
    pub fn endpoint_addr(&self) -> &WarrenExitAddr {
        &self.endpoint_addr
    }

    /// Direct entry endpoints (clients dial these in single-hop).
    #[must_use]
    pub fn entry(&self) -> &[Ingress] {
        &self.entry
    }

    /// Relay facets.
    #[must_use]
    pub fn relay(&self) -> &[Endpoint] {
        &self.relay
    }

    /// Exit facets.
    #[must_use]
    pub fn exit(&self) -> &[Exit] {
        &self.exit
    }

    /// Declared node geolocation (manual, authoritative for selection).
    #[must_use]
    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Relative weight for random selection.
    #[must_use]
    pub fn weight(&self) -> u64 {
        self.weight
    }

    /// `true` if the node is marked active by the upstream list.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// `true` if at least one entry dial socket is IPv4.
    #[must_use]
    pub fn has_ipv4(&self) -> bool {
        self.endpoint_addr.ip_addrs().any(|sa| sa.is_ipv4())
    }

    /// `true` if at least one entry dial socket is IPv6.
    #[must_use]
    pub fn has_ipv6(&self) -> bool {
        self.endpoint_addr.ip_addrs().any(|sa| sa.is_ipv6())
    }

    /// `true` if the node has a probed IPv4 egress source (it can route
    /// in-tunnel client traffic to the IPv4 internet).
    #[must_use]
    pub fn egress_v4(&self) -> bool {
        self.egress_v4_cap
    }

    /// `true` if the node has a probed IPv6 egress source. Orthogonal to
    /// [`Self::has_ipv6`] (a node may be v4-dialable yet offer v6 egress,
    /// and vice versa).
    #[must_use]
    pub fn egress_v6(&self) -> bool {
        self.egress_v6_cap
    }

    /// Node-level NAT-PMP port-forwarding capability (doc 79): `Some(true)` if
    /// the exit runs an enabled NAT-PMP gateway, `Some(false)` if explicitly
    /// disabled, `None` if unknown (roster carried no flag). The client only
    /// offers or prefers port forwarding when this is `Some(true)`.
    #[must_use]
    pub fn port_forward(&self) -> Option<bool> {
        self.port_forward
    }

    /// Distinct ALPN tokens advertised across this node's `entry`
    /// listeners, in first-seen (preference) order. The client offers
    /// these in the QUIC handshake instead of a compile-time constant.
    /// Empty when no entry listener carries one.
    #[must_use]
    pub fn dial_alpns(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for ing in &self.entry {
            for l in ing.listener() {
                if !out.iter().any(|a| a == l.alpn()) {
                    out.push(l.alpn().to_owned());
                }
            }
        }
        out
    }
}

/// `true` if any exit facet has an egress source of family `fam`.
fn egress_has_family(exit: &[Exit], fam: Family) -> bool {
    exit.iter()
        .flat_map(Exit::egress)
        .any(|e| e.addr().family() == fam)
}

/// Builds the single-hop dial target ([`WarrenExitAddr`]) from a node's
/// `entry` ingress points: one socket per `(addr, listener.port)` pair.
fn derive_endpoint_addr(id: WarrenPubkey, entry: &[Ingress]) -> WarrenExitAddr {
    let sockets = entry.iter().flat_map(|ing| {
        let ip = ing.addr().ipaddr();
        ing.listener()
            .iter()
            .map(move |l| SocketAddr::new(ip, l.port()))
    });
    WarrenExitAddr::from_ip_addrs(id, sockets)
}

/// List of available Warren nodes.
///
/// Opaque container; the internal invariant (dedup by `WarrenPubkey`,
/// stable sorting, ...) is the producer's responsibility.
#[derive(Debug, Clone, Default)]
pub struct WarrenRelayList {
    relays: Vec<WarrenRelay>,
}

impl WarrenRelayList {
    /// Builds a new list from a vector of nodes.
    #[must_use]
    pub fn new(relays: Vec<WarrenRelay>) -> Self {
        Self { relays }
    }

    /// Immutable slice of nodes.
    #[must_use]
    pub fn relays(&self) -> &[WarrenRelay] {
        &self.relays
    }

    /// Total number of nodes (including inactive).
    #[must_use]
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// `true` if the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn pubkey() -> WarrenPubkey {
        WarrenPubkey::from_bytes([0x11; 32])
    }

    fn ingress(ip: IpAddr, ports: &[u16]) -> Ingress {
        Ingress::new(
            Addr::new(ip, None),
            ports
                .iter()
                .map(|p| Listener::new(*p, "quic", "h3"))
                .collect(),
        )
    }

    fn exit_egress(ips: &[IpAddr]) -> Exit {
        Exit::new(
            [1; 32],
            [2; 32],
            false,
            Vec::new(),
            ips.iter()
                .map(|ip| Egress::new(Addr::new(*ip, None)))
                .collect(),
        )
    }

    fn node(entry: Vec<Ingress>, exit: Vec<Exit>) -> WarrenRelay {
        WarrenRelay::new(
            pubkey(),
            ExitId::from_bytes([0xaa; 16]),
            Location::new("NL", "Amsterdam"),
            100,
            true,
            entry,
            Vec::new(),
            exit,
        )
    }

    #[test]
    fn endpoint_addr_is_derived_from_entry_listeners() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let n = node(
            vec![ingress(v4, &[443, 8443]), ingress(v6, &[443])],
            Vec::new(),
        );
        let mut sockets: Vec<SocketAddr> = n.endpoint_addr().ip_addrs().collect();
        sockets.sort();
        assert_eq!(sockets.len(), 3, "2 (v4 ports) + 1 (v6 port) dial sockets");
        assert!(sockets.contains(&"192.0.2.90:443".parse().unwrap()));
        assert!(sockets.contains(&"192.0.2.90:8443".parse().unwrap()));
        assert!(sockets.contains(&"[2001:db8::2]:443".parse().unwrap()));
    }

    #[test]
    fn egress_capability_is_derived_from_exit_egress_families() {
        // v4 + v6 egress addresses -> both capabilities; supports a
        // v6-only-egress exit too.
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 90));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let dual = node(Vec::new(), vec![exit_egress(&[v4, v6])]);
        assert!(dual.egress_v4());
        assert!(dual.egress_v6());

        let v6_only = node(Vec::new(), vec![exit_egress(&[v6])]);
        assert!(!v6_only.egress_v4(), "v6-only egress: no v4 capability");
        assert!(v6_only.egress_v6());
    }

    #[test]
    fn has_family_reflects_entry_endpoints() {
        let v4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let n = node(vec![ingress(v4, &[443])], Vec::new());
        assert!(n.has_ipv4());
        assert!(!n.has_ipv6());
    }

    #[test]
    fn from_public_takes_egress_caps_from_booleans_not_addresses() {
        // Client side: the public v7 wire carries no egress address, only
        // capability booleans. `from_public` must honor them even though
        // the exit facet is empty.
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let n = WarrenRelay::from_public(
            pubkey(),
            ExitId::from_bytes([0xaa; 16]),
            Location::new("NL", "Amsterdam"),
            100,
            true,
            vec![ingress(v4, &[443])],
            false,
            true,
        );
        assert!(n.exit().is_empty(), "client side has no exit facet");
        assert!(!n.egress_v4(), "egress v4 cap from wire bool (false)");
        assert!(n.egress_v6(), "egress v6 cap from wire bool (true)");
        assert!(n.has_ipv4(), "still v4-dialable via entry");
    }

    #[test]
    fn port_forward_capability_defaults_unknown_and_is_stamped_by_builder() {
        // doc 79: a node built without the flag reports `None` (unknown, treated
        // as "not offered" by the client). `with_port_forward` stamps the signed
        // roster capability, and an explicitly-disabled exit stays distinct from
        // an enabled one and from unknown.
        let v4 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let base = WarrenRelay::from_public(
            pubkey(),
            ExitId::from_bytes([0xaa; 16]),
            Location::new("NL", "Amsterdam"),
            100,
            true,
            vec![ingress(v4, &[443])],
            true,
            false,
        );
        assert_eq!(
            base.port_forward(),
            None,
            "unknown until the roster sets it"
        );
        assert_eq!(
            base.clone().with_port_forward(Some(true)).port_forward(),
            Some(true),
            "enabled NAT-PMP surfaces as Some(true)"
        );
        assert_eq!(
            base.with_port_forward(Some(false)).port_forward(),
            Some(false),
            "explicitly-disabled NAT-PMP stays Some(false), distinct from unknown"
        );
    }

    #[test]
    fn dial_alpns_collects_distinct_entry_alpns() {
        let v4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let n = node(
            vec![Ingress::new(
                Addr::new(v4, None),
                vec![
                    Listener::new(443, "quic", "h3"),
                    Listener::new(8443, "quic", "h3"),
                ],
            )],
            Vec::new(),
        );
        assert_eq!(n.dial_alpns(), vec!["h3".to_owned()]);
    }
}

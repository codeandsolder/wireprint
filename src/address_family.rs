use std::net::SocketAddr;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Address-family policy applied to the actual connector's DNS candidates.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    #[default]
    Auto,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    #[must_use]
    pub const fn accepts(self, address: SocketAddr) -> bool {
        match self {
            Self::Auto => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }

    /// Preserve DNS result order and remove addresses from other families.
    #[must_use]
    pub fn filter(self, addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
        addresses
            .into_iter()
            .filter(|address| self.accepts(*address))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_filter_preserves_order_and_excludes_other_families() {
        let addresses = [
            "[2001:db8::1]:443".parse().expect("IPv6"),
            "192.0.2.1:443".parse().expect("IPv4"),
            "[2001:db8::2]:443".parse().expect("IPv6"),
            "192.0.2.2:443".parse().expect("IPv4"),
        ];
        assert_eq!(AddressFamily::Auto.filter(addresses), addresses);
        assert_eq!(
            AddressFamily::Ipv4.filter(addresses),
            [addresses[1], addresses[3]]
        );
        assert_eq!(
            AddressFamily::Ipv6.filter(addresses),
            [addresses[0], addresses[2]]
        );
        assert!(AddressFamily::Ipv6.filter([addresses[1]]).is_empty());
        assert!(AddressFamily::Ipv4.filter([addresses[0]]).is_empty());
    }

    #[test]
    fn family_serializes_and_defaults_explicitly() {
        assert_eq!(
            serde_json::to_value(AddressFamily::Auto).expect("JSON"),
            "auto"
        );
        assert_eq!(
            serde_json::to_value(AddressFamily::Ipv4).expect("JSON"),
            "ipv4"
        );
        assert_eq!(
            serde_json::to_value(AddressFamily::Ipv6).expect("JSON"),
            "ipv6"
        );
        assert_eq!(AddressFamily::default(), AddressFamily::Auto);
    }
}

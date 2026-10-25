use anyhow::{Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use wreq::{
    http2::{Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder},
    tls::{AlpnProtocol, TlsOptions, TlsVersion},
};
use wreq_util::{Emulation, Platform, Profile};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportProfile {
    Plain,
    /// Intentionally conspicuous but standards-valid TLS/H2 fingerprint for early-rejection screening.
    LowFidelity,
    Chrome149,
}

impl TransportProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::LowFidelity => "low-fidelity",
            Self::Chrome149 => "chrome149",
        }
    }

    pub fn configure(
        self,
        mut builder: wreq::ClientBuilder,
        platform: PlatformKind,
    ) -> wreq::ClientBuilder {
        match self {
            Self::Plain => {}
            Self::LowFidelity => {
                builder = builder
                    .tls_options(low_fidelity_tls_options())
                    .http2_options(low_fidelity_http2_options());
            }
            Self::Chrome149 => {
                builder = builder.emulation(
                    Emulation::builder()
                        .profile(Profile::Chrome149)
                        .platform(platform.into())
                        .headers(false)
                        .http2(true)
                        .build(),
                );
            }
        }
        builder
    }
}

fn low_fidelity_tls_options() -> TlsOptions {
    TlsOptions::builder()
        // Keep normal protocol compatibility while making the ClientHello deliberately
        // unlike a modern browser: no GREASE, no extension permutation, no ECH grease.
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .enable_ech_grease(false)
        .permute_extensions(false)
        .grease_enabled(false)
        .grease_sigalgs_enabled(false)
        // A P-256-only offer is legal and broadly interoperable, but conspicuously
        // unlike contemporary browser curve/key-share families.
        .curves_list("P-256")
        .renegotiation(false)
        .build()
}

fn low_fidelity_http2_options() -> Http2Options {
    let settings_order = SettingsOrder::builder()
        .push(SettingId::MaxHeaderListSize)
        .push(SettingId::EnablePush)
        .push(SettingId::HeaderTableSize)
        .push(SettingId::MaxConcurrentStreams)
        .push(SettingId::InitialWindowSize)
        .push(SettingId::MaxFrameSize)
        .build();
    let pseudo_order = PseudoOrder::builder()
        .push(PseudoId::Path)
        .push(PseudoId::Authority)
        .push(PseudoId::Method)
        .push(PseudoId::Scheme)
        .build();

    Http2Options::builder()
        // Deliberately small/spec-like values rather than a browser-tuned flow-control shape.
        .initial_connection_window_size(65_535)
        .initial_window_size(65_535)
        .header_table_size(4_096)
        .enable_push(false)
        .max_concurrent_streams(13)
        .max_frame_size(16_384)
        .max_header_list_size(8_192)
        .settings_order(settings_order)
        .headers_pseudo_order(pseudo_order)
        .build()
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformKind {
    Windows,
    Macos,
    Linux,
}

impl PlatformKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
        }
    }

    pub fn parse_name(value: &str) -> Result<Self> {
        match value {
            "windows" => Ok(Self::Windows),
            "macos" => Ok(Self::Macos),
            "linux" => Ok(Self::Linux),
            _ => bail!("unknown platform: {value}"),
        }
    }
}

impl From<PlatformKind> for Platform {
    fn from(value: PlatformKind) -> Self {
        match value {
            PlatformKind::Windows => Self::Windows,
            PlatformKind::Macos => Self::MacOS,
            PlatformKind::Linux => Self::Linux,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_fidelity_transport_has_stable_name() {
        assert_eq!(TransportProfile::LowFidelity.name(), "low-fidelity");
    }

    #[test]
    fn low_fidelity_transport_parses_from_cli_name() {
        assert!(matches!(
            TransportProfile::from_str("low-fidelity", false),
            Ok(TransportProfile::LowFidelity)
        ));
    }
}

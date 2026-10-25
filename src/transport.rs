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
    /// Low-fidelity TLS with ordinary/default HTTP/2, for mechanism decomposition.
    LowFidelityTls,
    /// Ordinary/default TLS with low-fidelity HTTP/2, for mechanism decomposition.
    LowFidelityH2,
    /// Chrome 149 TLS with library-default HTTP/2, for positive-side decomposition.
    Chrome149Tls,
    /// Library-default TLS with Chrome 149 HTTP/2, for positive-side decomposition.
    Chrome149H2,
    /// Current-ish mobile WebKit transport control (iPhone Safari 18.1.1).
    SafariIos18,
    /// Older mobile WebKit transport control (iPhone Safari 16.5).
    SafariIos16,
    /// Mobile Gecko transport control (Firefox Android 135).
    FirefoxAndroid135,
    /// Old Chromium/Android transport shape; useful as a WebView-era proxy, not an exact WebView claim.
    Chromium100Era,
    /// Old native Android application stack control (OkHttp 3.9).
    Okhttp39,
    Chrome149,
}

impl TransportProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::LowFidelity => "low-fidelity",
            Self::LowFidelityTls => "low-fidelity-tls",
            Self::LowFidelityH2 => "low-fidelity-h2",
            Self::Chrome149Tls => "chrome149-tls",
            Self::Chrome149H2 => "chrome149-h2",
            Self::SafariIos18 => "safari-ios18",
            Self::SafariIos16 => "safari-ios16",
            Self::FirefoxAndroid135 => "firefox-android135",
            Self::Chromium100Era => "chromium100-era",
            Self::Okhttp39 => "okhttp39",
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
            Self::LowFidelityTls => {
                builder = builder.tls_options(low_fidelity_tls_options());
            }
            Self::LowFidelityH2 => {
                builder = builder.http2_options(low_fidelity_http2_options());
            }
            Self::Chrome149Tls => {
                builder = builder
                    .emulation(browser_emulation(Profile::Chrome149, platform.into()))
                    .http2_options(None);
            }
            Self::Chrome149H2 => {
                builder = builder
                    .emulation(browser_emulation(Profile::Chrome149, platform.into()))
                    .tls_options(None);
            }
            Self::SafariIos18 => {
                builder =
                    builder.emulation(browser_emulation(Profile::SafariIos18_1_1, Platform::IOS));
            }
            Self::SafariIos16 => {
                builder =
                    builder.emulation(browser_emulation(Profile::SafariIos16_5, Platform::IOS));
            }
            Self::FirefoxAndroid135 => {
                builder = builder.emulation(browser_emulation(
                    Profile::FirefoxAndroid135,
                    Platform::Android,
                ));
            }
            Self::Chromium100Era => {
                builder =
                    builder.emulation(browser_emulation(Profile::Chrome100, Platform::Android));
            }
            Self::Okhttp39 => {
                builder =
                    builder.emulation(browser_emulation(Profile::OkHttp3_9, Platform::Android));
            }
            Self::Chrome149 => {
                builder = builder.emulation(browser_emulation(Profile::Chrome149, platform.into()));
            }
        }
        builder
    }
}

fn browser_emulation(profile: Profile, platform: Platform) -> Emulation {
    Emulation::builder()
        .profile(profile)
        .platform(platform)
        .headers(false)
        .http2(true)
        .build()
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
        assert!(matches!(
            TransportProfile::from_str("low-fidelity-tls", false),
            Ok(TransportProfile::LowFidelityTls)
        ));
        assert!(matches!(
            TransportProfile::from_str("low-fidelity-h2", false),
            Ok(TransportProfile::LowFidelityH2)
        ));
        for name in [
            "chrome149-tls",
            "chrome149-h2",
            "safari-ios18",
            "safari-ios16",
            "firefox-android135",
            "chromium100-era",
            "okhttp39",
        ] {
            assert!(
                TransportProfile::from_str(name, false).is_ok(),
                "failed to parse {name}"
            );
        }
    }

    #[test]
    fn low_fidelity_decomposition_profiles_have_stable_names() {
        assert_eq!(TransportProfile::LowFidelityTls.name(), "low-fidelity-tls");
        assert_eq!(TransportProfile::LowFidelityH2.name(), "low-fidelity-h2");
        assert_eq!(TransportProfile::Chrome149Tls.name(), "chrome149-tls");
        assert_eq!(TransportProfile::Chrome149H2.name(), "chrome149-h2");
        assert_eq!(TransportProfile::SafariIos18.name(), "safari-ios18");
        assert_eq!(TransportProfile::SafariIos16.name(), "safari-ios16");
        assert_eq!(
            TransportProfile::FirefoxAndroid135.name(),
            "firefox-android135"
        );
        assert_eq!(TransportProfile::Chromium100Era.name(), "chromium100-era");
        assert_eq!(TransportProfile::Okhttp39.name(), "okhttp39");
    }
}

use std::collections::HashSet;

use anyhow::{Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use wreq::{
    http2::{Http2Options, PseudoId, PseudoOrder, SettingId, SettingsOrder},
    tls::{AlpnProtocol, ExtensionType, KeyShare, TlsOptions, TlsVersion},
};
use wreq_util::{Emulation, Platform, Profile};

pub const TRANSPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BuiltinTransport {
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
    /// Chrome/Chromium 100-era transport shape; useful as a WebView-era proxy, not an exact WebView claim.
    Chromium100Era,
    /// Old native Android application stack control (OkHttp 3.9).
    Okhttp39,
    Chrome149,
}

impl BuiltinTransport {
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

    pub fn into_profile(self, platform: PlatformKind) -> TransportProfile {
        let explicit_platform = self.requires_explicit_platform().then_some(platform);
        TransportProfile {
            name: self.name().into(),
            provenance: Some(match self {
                Self::Plain => "wireprint builtin neutral transport control".into(),
                Self::LowFidelity | Self::LowFidelityTls | Self::LowFidelityH2 => {
                    "wireprint intentional standards-valid low-fidelity transport control".into()
                }
                _ => "wireprint reference transport with automatic application headers disabled; not a claim of vendor identity".into(),
            }),
            implementation: Some(TransportImplementation::Builtin {
                profile: self,
                platform: explicit_platform,
            }),
            observations: Vec::new(),
        }
    }

    fn requires_explicit_platform(self) -> bool {
        matches!(
            self,
            Self::Chrome149 | Self::Chrome149Tls | Self::Chrome149H2
        )
    }

    fn fixed_platform(self) -> Option<PlatformKind> {
        match self {
            Self::SafariIos18 | Self::SafariIos16 => Some(PlatformKind::Ios),
            Self::FirefoxAndroid135 | Self::Chromium100Era | Self::Okhttp39 => {
                Some(PlatformKind::Android)
            }
            _ => None,
        }
    }

    fn effective_platform(self, explicit: Option<PlatformKind>) -> Option<PlatformKind> {
        self.fixed_platform().or(explicit)
    }

    fn configure(
        self,
        mut builder: wreq::ClientBuilder,
        platform: Option<PlatformKind>,
    ) -> Result<wreq::ClientBuilder> {
        if self.requires_explicit_platform() && platform.is_none() {
            bail!("builtin transport '{}' requires a platform", self.name());
        }
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
                    .emulation(browser_emulation(
                        Profile::Chrome149,
                        platform.expect("validated platform").into(),
                    ))
                    .http2_options(None);
            }
            Self::Chrome149H2 => {
                builder = builder
                    .emulation(browser_emulation(
                        Profile::Chrome149,
                        platform.expect("validated platform").into(),
                    ))
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
                builder = builder.emulation(browser_emulation(
                    Profile::Chrome149,
                    platform.expect("validated platform").into(),
                ));
            }
        }
        Ok(builder)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportSet {
    pub schema_version: u32,
    pub transports: Vec<TransportProfile>,
}

impl TransportSet {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != TRANSPORT_SCHEMA_VERSION {
            bail!(
                "unsupported transport schema version: {} (expected {})",
                self.schema_version,
                TRANSPORT_SCHEMA_VERSION
            );
        }
        if self.transports.is_empty() {
            bail!("transport set is empty");
        }
        let mut names = HashSet::with_capacity(self.transports.len());
        for profile in &self.transports {
            profile.validate()?;
            if !names.insert(profile.name.as_str()) {
                bail!("duplicate transport profile name: {}", profile.name);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportProfile {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation: Option<TransportImplementation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<TransportObservation>,
}

impl TransportProfile {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("transport profile name is empty");
        }
        if let Some(TransportImplementation::Builtin { profile, platform }) =
            self.implementation.as_ref()
        {
            if profile.requires_explicit_platform() && platform.is_none() {
                bail!(
                    "transport profile '{}' uses builtin '{}' without a required platform",
                    self.name,
                    profile.name()
                );
            }
        }
        for observation in &self.observations {
            if observation.scheme.trim().is_empty() {
                bail!(
                    "transport profile '{}' has an observation with an empty scheme",
                    self.name
                );
            }
            if observation.value.trim().is_empty() {
                bail!(
                    "transport profile '{}' has an empty {} observation",
                    self.name,
                    observation.scheme
                );
            }
        }
        Ok(())
    }

    pub fn runnable(&self) -> bool {
        self.implementation.is_some()
    }

    pub fn platform(&self) -> Option<PlatformKind> {
        match self.implementation.as_ref() {
            Some(TransportImplementation::Builtin { profile, platform }) => {
                profile.effective_platform(*platform)
            }
            Some(TransportImplementation::HyperRustls { .. })
            | Some(TransportImplementation::WreqMeasured { .. })
            | None => None,
        }
    }

    pub fn configure(&self, builder: wreq::ClientBuilder) -> Result<wreq::ClientBuilder> {
        match self.implementation.as_ref() {
            Some(TransportImplementation::Builtin { profile, platform }) => {
                profile.configure(builder, *platform)
            }
            Some(TransportImplementation::WreqMeasured { profile }) => {
                Ok(profile.configure(builder))
            }
            Some(TransportImplementation::HyperRustls { .. }) => bail!(
                "transport profile '{}' uses the native hyper/rustls backend, not wreq",
                self.name
            ),
            None => bail!(
                "transport profile '{}' is observational only and has no runnable implementation",
                self.name
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportImplementation {
    Builtin {
        profile: BuiltinTransport,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        platform: Option<PlatformKind>,
    },
    HyperRustls {
        profile: HyperRustlsProfileKind,
    },
    WreqMeasured {
        profile: WreqMeasuredProfileKind,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HyperRustlsProfileKind {
    #[serde(rename = "reqwest-0.12.28-compatible-rustls-0.23.42")]
    Reqwest01228CompatibleRustls02342,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum WreqMeasuredProfileKind {
    #[serde(rename = "envoy-chatgpt-user-compatible-2026")]
    EnvoyChatgptUserCompatible2026,
}

impl WreqMeasuredProfileKind {
    fn configure(self, builder: wreq::ClientBuilder) -> wreq::ClientBuilder {
        match self {
            Self::EnvoyChatgptUserCompatible2026 => {
                let tls = TlsOptions::builder()
                    .curves_list("X25519:P-256:P-384:P-521")
                    .key_shares(&[KeyShare::X25519])
                    .cipher_list(concat!(
                        "TLS_AES_128_GCM_SHA256:",
                        "TLS_AES_256_GCM_SHA384:",
                        "TLS_CHACHA20_POLY1305_SHA256:",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
                        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
                        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
                        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:",
                        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
                        "TLS_RSA_WITH_AES_128_GCM_SHA256:",
                        "TLS_RSA_WITH_AES_128_CBC_SHA:",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
                        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
                        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:",
                        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
                        "TLS_RSA_WITH_AES_256_GCM_SHA384:",
                        "TLS_RSA_WITH_AES_256_CBC_SHA"
                    ))
                    .preserve_tls13_cipher_list(true)
                    .sigalgs_list(concat!(
                        "ecdsa_secp256r1_sha256:",
                        "rsa_pss_rsae_sha256:",
                        "rsa_pkcs1_sha256:",
                        "ecdsa_secp384r1_sha384:",
                        "rsa_pss_rsae_sha384:",
                        "rsa_pkcs1_sha384:",
                        "rsa_pss_rsae_sha512:",
                        "rsa_pkcs1_sha512:",
                        "rsa_pkcs1_sha1"
                    ))
                    .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
                    .min_tls_version(TlsVersion::TLS_1_1)
                    .max_tls_version(TlsVersion::TLS_1_3)
                    .grease_enabled(false)
                    .permute_extensions(false)
                    .enable_ocsp_stapling(false)
                    .enable_signed_cert_timestamps(false)
                    .enable_ech_grease(false)
                    .renegotiation(true)
                    .session_ticket(true)
                    .extension_permutation(&[
                        ExtensionType::SERVER_NAME,
                        ExtensionType::EXTENDED_MASTER_SECRET,
                        ExtensionType::RENEGOTIATE,
                        ExtensionType::SUPPORTED_GROUPS,
                        ExtensionType::EC_POINT_FORMATS,
                        ExtensionType::SESSION_TICKET,
                        ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                        ExtensionType::SIGNATURE_ALGORITHMS,
                        ExtensionType::KEY_SHARE,
                        ExtensionType::PSK_KEY_EXCHANGE_MODES,
                        ExtensionType::SUPPORTED_VERSIONS,
                        ExtensionType::PADDING,
                        ExtensionType::PRE_SHARED_KEY,
                    ])
                    .build();

                let settings_order = SettingsOrder::builder()
                    .extend([
                        SettingId::EnablePush,
                        SettingId::HeaderTableSize,
                        SettingId::EnableConnectProtocol,
                        SettingId::MaxConcurrentStreams,
                        SettingId::InitialWindowSize,
                    ])
                    .build();
                let pseudo_order = PseudoOrder::builder()
                    .extend([
                        PseudoId::Authority,
                        PseudoId::Path,
                        PseudoId::Method,
                        PseudoId::Scheme,
                    ])
                    .build();
                let http2 = Http2Options::builder()
                    .enable_push(false)
                    .header_table_size(4096)
                    .enable_connect_protocol(false)
                    .max_concurrent_streams(1024)
                    .initial_window_size(1_048_576)
                    .initial_connection_window_size(25_165_824)
                    .settings_order(settings_order)
                    .headers_pseudo_order(pseudo_order)
                    .build();

                builder
                    .no_gzip()
                    .no_brotli()
                    .no_deflate()
                    .tls_options(tls)
                    .http2_options(http2)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportObservation {
    /// Fingerprint/observation namespace, for example `ja4` or `akamai_http2_client_fingerprint`.
    pub scheme: String,
    pub value: String,
    #[serde(default)]
    pub completeness: TransportObservationCompleteness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportObservationCompleteness {
    #[default]
    Exact,
    Prefix,
    Partial,
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
        .alpn_protocols([AlpnProtocol::HTTP2, AlpnProtocol::HTTP1])
        .min_tls_version(TlsVersion::TLS_1_2)
        .max_tls_version(TlsVersion::TLS_1_3)
        .enable_ech_grease(false)
        .permute_extensions(false)
        .grease_enabled(false)
        .grease_sigalgs_enabled(false)
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

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PlatformKind {
    Windows,
    Macos,
    Linux,
    Ios,
    Android,
}

impl PlatformKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }

    pub fn parse_name(value: &str) -> Result<Self> {
        match value {
            "windows" => Ok(Self::Windows),
            "macos" => Ok(Self::Macos),
            "linux" => Ok(Self::Linux),
            "ios" => Ok(Self::Ios),
            "android" => Ok(Self::Android),
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
            PlatformKind::Ios => Self::IOS,
            PlatformKind::Android => Self::Android,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_names_are_stable_and_parseable() {
        let names = [
            "plain",
            "low-fidelity",
            "low-fidelity-tls",
            "low-fidelity-h2",
            "chrome149-tls",
            "chrome149-h2",
            "safari-ios18",
            "safari-ios16",
            "firefox-android135",
            "chromium100-era",
            "okhttp39",
            "chrome149",
        ];
        for name in names {
            let profile = BuiltinTransport::from_str(name, false).expect("parse builtin transport");
            assert_eq!(profile.name(), name);
        }
    }

    #[test]
    fn builtin_platform_semantics_are_explicit() {
        assert_eq!(
            BuiltinTransport::Chrome149
                .into_profile(PlatformKind::Windows)
                .platform(),
            Some(PlatformKind::Windows)
        );
        assert_eq!(
            BuiltinTransport::SafariIos18
                .into_profile(PlatformKind::Macos)
                .platform(),
            Some(PlatformKind::Ios)
        );
        assert_eq!(
            BuiltinTransport::Okhttp39
                .into_profile(PlatformKind::Macos)
                .platform(),
            Some(PlatformKind::Android)
        );
        assert_eq!(
            BuiltinTransport::Plain
                .into_profile(PlatformKind::Macos)
                .platform(),
            None
        );
    }
}

use anyhow::{Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use wreq_util::{Emulation, Platform, Profile};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportProfile {
    Plain,
    Chrome149,
}

impl TransportProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Chrome149 => "chrome149",
        }
    }

    pub fn configure(
        self,
        mut builder: wreq::ClientBuilder,
        platform: PlatformKind,
    ) -> wreq::ClientBuilder {
        if let Self::Chrome149 = self {
            builder = builder.emulation(
                Emulation::builder()
                    .profile(Profile::Chrome149)
                    .platform(platform.into())
                    .headers(false)
                    .http2(true)
                    .build(),
            );
        }
        builder
    }
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

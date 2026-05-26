//! Configuration management for the Blocklist client

use config::{Config, ConfigError, Environment, File, FileFormat};
use serde::{Deserialize, Deserializer};
use std::{sync::LazyLock, time::Duration};
use url::Url;

use clap::Parser;
use std::path::PathBuf;

/// Struct which represent command line arguments
#[derive(Parser, Debug)]
#[command(name = "Blocklist Client")]
struct Cli {
    /// Path to the configuration file
    #[arg(short = 'c', long = "config", value_name = "PATH")]
    config: Option<PathBuf>,
}

/// Command line arguments for the blocklist client
static CLI: LazyLock<Cli> = LazyLock::new(Cli::parse);

/// Top-level configuration for the Blocklist client
#[derive(Deserialize, Clone, Debug)]
pub struct Settings {
    /// Blocklist client's server related config
    pub server: ServerConfig,
    /// Blocklist client's risk service config
    pub risk_analysis: Option<RiskAnalysisConfig>,
    /// Sanctions file config
    pub sanctions: Option<SanctionFileConfig>,
}

/// Blocklist client's server related config
#[derive(Deserialize, Clone, Debug)]
pub struct ServerConfig {
    /// Host of the Blocklist client
    pub host: String,
    /// Port of the Blocklist client
    pub port: u16,
}

/// Assessment method for the Blocklist client
#[derive(Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentMethod {
    /// Use sanctions list API
    Sanctions,
    /// Use risk analysis API
    RiskAnalysis,
}

fn default_sanction_polling_interval() -> Duration {
    Duration::from_secs(3600)
}

fn default_assessment_method() -> AssessmentMethod {
    AssessmentMethod::Sanctions
}

/// Sanction file config
#[derive(Deserialize, Clone, Debug)]
pub struct SanctionFileConfig {
    /// The URL to fetch the file from
    #[serde(deserialize_with = "url_deserializer_single")]
    pub url: Url,
    /// Optional header for authorization
    pub header: Option<SanctionFileConfigHeader>,
    /// Polling interval to fetch the sanction list
    #[serde(
        default = "default_sanction_polling_interval",
        deserialize_with = "duration_seconds_deserializer"
    )]
    pub polling_interval: Duration,
    /// The path for a local sanction file to use before the first fetch
    pub local_path: Option<PathBuf>,
}

/// Sanction file config header
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SanctionFileConfigHeader {
    /// The header name
    pub key: String,
    /// The header value
    pub value: String,
}

/// Blocklist client's risk API config
#[derive(Deserialize, Clone, Debug)]
pub struct RiskAnalysisConfig {
    /// API URL of the Risk service
    pub api_url: String,
    /// API key for the Risk service
    pub api_key: String,
    /// Assessment method for the Blocklist client
    #[serde(default = "default_assessment_method")]
    pub assessment_method: AssessmentMethod,
}

/// Statically configured settings for the Blocklist client
pub static SETTINGS: LazyLock<Settings> = LazyLock::new(|| match &CLI.config {
    Some(path) => {
        Settings::new_from_path(path.to_str().unwrap()).expect("Failed to load configuration")
    }
    None => Settings::new().expect("Failed to load configuration"),
});

impl Settings {
    /// Initializing the global config first with default values and then with provided/overwritten environment variables.
    /// The explicit separator with double underscores is needed to correctly parse the nested config structure.
    pub fn new() -> Result<Self, ConfigError> {
        let env = Environment::with_prefix("BLOCKLIST_CLIENT")
            .separator("__")
            .prefix_separator("_");

        let cfg = Config::builder()
            .add_source(File::from_str(
                include_str!("config/default.toml"),
                FileFormat::Toml,
            ))
            .add_source(env)
            .build()?;
        let settings: Settings = cfg.try_deserialize()?;

        settings.validate()?;

        Ok(settings)
    }

    /// Initializing the global config with values from provided config file and then with provided/overwritten environment variables.
    /// The explicit separator with double underscores is needed to correctly parse the nested config structure.
    pub fn new_from_path(path: &str) -> Result<Self, ConfigError> {
        let env = Environment::with_prefix("BLOCKLIST_CLIENT")
            .separator("__")
            .prefix_separator("_");

        let cfg = Config::builder()
            .add_source(File::with_name(path))
            .add_source(env)
            .build()?;

        let settings: Settings = cfg.try_deserialize()?;

        settings.validate()?;

        Ok(settings)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.host.is_empty() {
            return Err(ConfigError::Message("Host cannot be empty".to_string()));
        }
        if !(1..=65535).contains(&self.server.port) {
            return Err(ConfigError::Message(
                "Port must be between 1 and 65535".to_string(),
            ));
        }

        if self.risk_analysis.is_some() && self.sanctions.is_some() {
            return Err(ConfigError::Message(
                "`risk_analysis` and `sanctions` are mutually exclusive; set only one".to_string(),
            ));
        }

        if self.risk_analysis.is_none() && self.sanctions.is_none() {
            return Err(ConfigError::Message(
                "either `risk_analysis` or `sanctions` must be configured".to_string(),
            ));
        }

        Ok(())
    }
}

/// A deserializer for the url::Url type. Does not support deserializing a list,
/// only a single URL.
fn url_deserializer_single<'de, D>(deserializer: D) -> Result<url::Url, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)?
        .parse()
        .map_err(serde::de::Error::custom)
}

/// A deserializer for the std::time::Duration type.
/// Serde includes a default deserializer, but it expects a struct.
pub fn duration_seconds_deserializer<'de, D>(
    deserializer: D,
) -> Result<std::time::Duration, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(std::time::Duration::from_secs(
        u64::deserialize(deserializer).map_err(serde::de::Error::custom)?,
    ))
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;

    fn clear_env() {
        for var in std::env::vars() {
            if var.0.starts_with("BLOCKLIST_CLIENT_") {
                unsafe {
                    std::env::remove_var(var.0);
                }
            }
        }
    }
    fn set_var<K: AsRef<std::ffi::OsStr>, V: AsRef<std::ffi::OsStr>>(key: K, value: V) {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    #[test]
    fn no_method_configured() {
        clear_env();

        let settings = Settings::new();

        assert_matches!(settings, Err(ConfigError::Message(m)) if m.contains("either `risk_analysis` or `sanctions`"));
    }

    #[test]
    fn both_methods_configured() {
        clear_env();

        set_var("BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL", "some-url");
        set_var("BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY", "some-key");
        set_var(
            "BLOCKLIST_CLIENT_RISK_ANALYSIS__ASSESSMENT_METHOD",
            "sanctions",
        );

        set_var("BLOCKLIST_CLIENT_SANCTIONS__URL", "https://example.com");

        let settings = Settings::new();

        assert_matches!(settings, Err(ConfigError::Message(m)) if m.contains("mutually exclusive"));
    }

    #[test]
    fn risk_api_default() {
        clear_env();

        set_var("BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL", "some-url");
        set_var("BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY", "some-key");

        let settings = Settings::new().unwrap();

        let risk_analysis = settings.risk_analysis.unwrap();
        assert_eq!(risk_analysis.api_url, "some-url");
        assert_eq!(risk_analysis.api_key, "some-key");
        assert_matches!(risk_analysis.assessment_method, AssessmentMethod::Sanctions);
    }

    #[test]
    fn risk_api_explicit_assessment() {
        clear_env();
        set_var("BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL", "some-url");
        set_var("BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY", "some-key");
        set_var(
            "BLOCKLIST_CLIENT_RISK_ANALYSIS__ASSESSMENT_METHOD",
            "risk_analysis",
        );

        let settings = Settings::new().unwrap();

        let risk_analysis = settings.risk_analysis.unwrap();
        assert_eq!(risk_analysis.api_url, "some-url");
        assert_eq!(risk_analysis.api_key, "some-key");
        assert_matches!(
            risk_analysis.assessment_method,
            AssessmentMethod::RiskAnalysis
        );

        assert!(settings.sanctions.is_none());
    }

    #[test]
    fn sanction_list_minimal() {
        clear_env();

        set_var("BLOCKLIST_CLIENT_SANCTIONS__URL", "https://example.com");

        let settings = Settings::new().unwrap();

        assert!(settings.risk_analysis.is_none());

        let sanctions = settings.sanctions.unwrap();
        assert_eq!(sanctions.url, "https://example.com".parse().unwrap());
        assert_eq!(
            sanctions.polling_interval,
            default_sanction_polling_interval()
        );
        assert!(sanctions.header.is_none());
    }

    #[test]
    fn sanction_list_full() {
        clear_env();

        set_var("BLOCKLIST_CLIENT_SANCTIONS__URL", "https://example.com");
        set_var("BLOCKLIST_CLIENT_SANCTIONS__POLLING_INTERVAL", "124");
        set_var("BLOCKLIST_CLIENT_SANCTIONS__HEADER__KEY", "x-api-key");
        set_var("BLOCKLIST_CLIENT_SANCTIONS__HEADER__VALUE", "my-key");

        let settings = Settings::new().unwrap();

        assert!(settings.risk_analysis.is_none());

        let sanctions = settings.sanctions.unwrap();

        assert_eq!(sanctions.url, "https://example.com".parse().unwrap());
        assert_eq!(sanctions.polling_interval, Duration::from_secs(124));
        assert_eq!(
            sanctions.header,
            Some(SanctionFileConfigHeader {
                key: "x-api-key".to_owned(),
                value: "my-key".to_owned()
            })
        );
    }
}

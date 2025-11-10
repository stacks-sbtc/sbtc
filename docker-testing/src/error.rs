#[derive(Debug, thiserror::Error)]
pub enum DockerTestingError {
    #[error(transparent)]
    TestContainers(#[from] testcontainers::TestcontainersError),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    #[error(transparent)]
    ImageSpecific(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("connectivity checks did not succeed within the allotted time")]
    StartupConnectivityTimeout,

    #[error("invalid version format: '{0}'. Expected format #.#")]
    InvalidVersionFormat(String),
}

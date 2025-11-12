//! Docker-based test containers for integration tests
//!

use testcontainers::compose::DockerCompose;

use crate::error::Error;

/// Builder for test containers
pub struct TestContainersBuilder {
    /// Compose files to use
    compose_files: Vec<String>,
}
impl TestContainersBuilder {
    /// Create a new `TestContainersBuilder`
    pub fn new() -> Self {
        Self { compose_files: vec![] }
    }
    /// Add compose file
    pub fn with_compose(mut self, filename: &str) -> Self {
        self.compose_files.push(filename.to_string());
        self
    }
    /// Build a new `TestContainers` with this config
    pub fn build(self) -> TestContainers {
        TestContainers::new(self)
    }
}

impl Default for TestContainersBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A `TestContainers` manage an isolated docker stack for tests
pub struct TestContainers {
    /// The underlying compose stack
    compose: DockerCompose,
}
impl TestContainers {
    /// Create a new `TestContainers`
    pub fn new(config: TestContainersBuilder) -> Self {
        let compose = DockerCompose::with_local_client(&config.compose_files);
        Self { compose }
    }

    /// Up the required services
    pub async fn up(&mut self) -> Result<(), Error> {
        self.compose.up().await.map_err(Error::ComposeError)
    }

    /// Get the service exposed port given the internal port
    pub async fn get_service_port(&self, service: &str, internal_port: u16) -> Result<u16, Error> {
        let container = self.compose.service(service).ok_or(Error::ComposeError(
            testcontainers::compose::ComposeError::ServiceNotFound(service.to_string()),
        ))?;
        container
            .get_host_port_ipv4(internal_port)
            .await
            .map_err(Error::Testcontainers)
    }

    /// Get the service host
    pub async fn get_service_host(&self, service: &str) -> Result<url::Host, Error> {
        let container = self.compose.service(service).ok_or(Error::ComposeError(
            testcontainers::compose::ComposeError::ServiceNotFound(service.to_string()),
        ))?;
        container.get_host().await.map_err(Error::Testcontainers)
    }
}

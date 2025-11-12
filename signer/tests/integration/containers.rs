use bitcoin::{AddressType, Amount};
use bitcoincore_rpc::RpcApi as _;
use sbtc::testing::{
    containers::{TestContainers as BaseTestContainers, TestContainersBuilder},
    regtest::{
        BITCOIN_CORE_RPC_PASSWORD, BITCOIN_CORE_RPC_USERNAME, BITCOIN_CORE_WALLET_NAME,
        FAUCET_LABEL, FAUCET_SECRET_KEY, Faucet, MIN_BLOCKCHAIN_HEIGHT, get_or_create_wallet,
    },
};
use signer::{
    bitcoin::rpc::BitcoinCoreClient, error::Error, storage::postgres::PgStore,
    testing::storage::get_connection_pool,
};
use tokio::sync::OnceCell;
use url::Url;

const COMPOSE_BITCOIN: &str = "docker-compose.bitcoin.yml";
const COMPOSE_DATABASE: &str = "docker-compose.db.yml";
const COMPOSE_EMILY: &str = "docker-compose.emily.yml";

const SERVICE_BITCOIN: &str = "bitcoind";
const SERVICE_BITCOIN_RPC_PORT: u16 = 18443;

const SERVICE_DATABASE: &str = "postgres";
const SERVICE_DATABASE_PORT: u16 = 5432;
const SERVICE_DATABASE_USER: &str = "postgres";
const SERVICE_DATABASE_PASSWORD: &str = "postgres";

fn compose_path(file_name: &str) -> String {
    // Evaluate `CARGO_MANIFEST_DIR` at runtime for nextest relocation
    format!(
        "{}/../docker/tests/{file_name}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    )
}

pub trait TestContainersBuilderExt {
    async fn start(self) -> TestContainers;

    fn with_bitcoin(self) -> Self;
    fn with_database(self) -> Self;
    fn with_emily(self) -> Self;

    async fn start_bitcoin() -> TestContainers;
    async fn start_database() -> TestContainers;
}

impl TestContainersBuilderExt for TestContainersBuilder {
    /// Build a new `TestContainers` with this config and start it, panic if fails
    async fn start(self) -> TestContainers {
        let mut stack = self.build();
        stack.up().await.expect("failed to start the stack");
        stack.into()
    }
    /// Require Bitcoin service
    fn with_bitcoin(self) -> Self {
        self.with_compose(&compose_path(COMPOSE_BITCOIN))
    }
    /// Require DB service
    fn with_database(self) -> Self {
        self.with_compose(&compose_path(COMPOSE_DATABASE))
    }
    /// Require Emily service
    fn with_emily(self) -> Self {
        self.with_compose(&compose_path(COMPOSE_EMILY))
    }
    /// Start the test stack with only Bitcoin, panic if fails
    async fn start_bitcoin() -> TestContainers {
        Self::new().with_bitcoin().start().await
    }
    /// Start the test stack with only the database, panic if fails
    async fn start_database() -> TestContainers {
        Self::new().with_database().start().await
    }
}

pub struct TestContainers {
    containers: BaseTestContainers,
    bitcoin: OnceCell<BitcoinContainer>,
    database: OnceCell<DatabaseContainer>,
}

impl From<BaseTestContainers> for TestContainers {
    fn from(value: BaseTestContainers) -> Self {
        TestContainers {
            containers: value,
            bitcoin: OnceCell::new(),
            database: OnceCell::new(),
        }
    }
}

impl TestContainers {
    /// Get the Bitcoin RPC address
    async fn get_bitcoin_url(&self) -> Result<Url, Error> {
        let host = self.containers.get_service_host(SERVICE_BITCOIN).await?;
        let port = self
            .containers
            .get_service_port(SERVICE_BITCOIN, SERVICE_BITCOIN_RPC_PORT)
            .await?;
        format!(
            "http://{}:{}@{}:{}",
            BITCOIN_CORE_RPC_USERNAME, BITCOIN_CORE_RPC_PASSWORD, host, port
        )
        .parse()
        .map_err(Error::InvalidUrl)
    }

    /// Get the database address
    async fn get_database_url(&self) -> Result<String, Error> {
        let host = self.containers.get_service_host(SERVICE_DATABASE).await?;
        let port = self
            .containers
            .get_service_port(SERVICE_DATABASE, SERVICE_DATABASE_PORT)
            .await?;
        Ok(format!(
            "postgres://{}:{}@{}:{}",
            SERVICE_DATABASE_USER, SERVICE_DATABASE_PASSWORD, host, port
        ))
    }

    /// Get the Bitcoin container
    pub async fn bitcoin(&self) -> &BitcoinContainer {
        self.bitcoin
            .get_or_init(|| BitcoinContainer::from_containers(self))
            .await
    }

    /// Get the database container
    pub async fn database(&self) -> &DatabaseContainer {
        self.database
            .get_or_init(|| DatabaseContainer::from_containers(self))
            .await
    }
}

pub struct BitcoinContainer {
    url: Url,
    rpc_client: bitcoincore_rpc::Client,
}

impl BitcoinContainer {
    pub async fn from_containers(containers: &TestContainers) -> Self {
        let auth = bitcoincore_rpc::Auth::UserPass(
            BITCOIN_CORE_RPC_USERNAME.to_string(),
            BITCOIN_CORE_RPC_PASSWORD.to_string(),
        );
        let url = containers
            .get_bitcoin_url()
            .await
            .expect("cannot get bitcoin url");

        let rpc_client = bitcoincore_rpc::Client::new(url.as_ref(), auth)
            .expect("cannot create bitcoin rpc client");

        get_or_create_wallet(&rpc_client, BITCOIN_CORE_WALLET_NAME);
        let faucet = Faucet::new(FAUCET_SECRET_KEY, AddressType::P2wpkh, &rpc_client);
        faucet.track_address(FAUCET_LABEL);

        let amount = rpc_client
            .get_received_by_address(&faucet.address, None)
            .unwrap();
        if amount < Amount::from_int_btc(1) {
            faucet.generate_blocks(MIN_BLOCKCHAIN_HEIGHT);
        }

        BitcoinContainer { url, rpc_client }
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn rpc(&self) -> &bitcoincore_rpc::Client {
        &self.rpc_client
    }

    pub fn get_faucet(&self) -> Faucet<'_> {
        Faucet::new(FAUCET_SECRET_KEY, AddressType::P2wpkh, &self.rpc_client)
    }

    pub fn get_client(&self) -> BitcoinCoreClient {
        self.url().try_into().expect("cannot create bitcoin client")
    }
}

pub struct DatabaseContainer {
    url: String,
}

impl DatabaseContainer {
    pub async fn from_containers(containers: &TestContainers) -> Self {
        let base_url = containers
            .get_database_url()
            .await
            .expect("cannot get database url");
        let postgres_url = format!("{base_url}/postgres");
        let pool = get_connection_pool(&postgres_url);

        sqlx::query("CREATE DATABASE signer WITH OWNER = 'postgres';")
            .execute(&pool)
            .await
            .expect("failed to create test database");

        // In order to create a new database from another database, there
        // cannot exist any other connections to that database. So we
        // explicitly close this connection. See the notes section in the docs
        // <https://www.postgresql.org/docs/16/sql-createdatabase.html>
        pool.close().await;

        let test_db_url = format!("{base_url}/signer");
        let store = PgStore::connect(&test_db_url).await.unwrap();

        store
            .apply_migrations()
            .await
            .expect("failed to apply db migrations");

        DatabaseContainer { url: test_db_url }
    }

    pub async fn get_store(&self) -> PgStore {
        PgStore::connect(&self.url).await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use fake::Fake as _;
    use signer::{
        storage::{DbRead as _, DbWrite as _},
        testing::get_rng,
    };

    use super::*;

    #[tokio::test]
    async fn test_up() {
        let mut stack = TestContainersBuilder::new()
            .with_bitcoin()
            .with_database()
            // TODO: restore .with_emily()
            .build();
        stack.up().await.unwrap();

        assert!(stack.get_service_host(SERVICE_BITCOIN).await.is_ok());
        assert!(
            stack
                .get_service_port(SERVICE_BITCOIN, SERVICE_BITCOIN_RPC_PORT)
                .await
                .is_ok()
        );

        assert!(stack.get_service_host(SERVICE_DATABASE).await.is_ok());
        assert!(
            stack
                .get_service_port(SERVICE_DATABASE, SERVICE_DATABASE_PORT)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_bitcoin() {
        let stack = TestContainersBuilder::start_bitcoin().await;
        let bitcoin = stack.bitcoin().await;

        let rpc = bitcoin.rpc();
        let faucet = bitcoin.get_faucet();
        let client = bitcoin.get_client();

        let block = faucet.generate_block();

        assert!(rpc.get_block(&block).is_ok());
        assert_eq!(client.get_best_block_hash().unwrap(), block);
    }

    #[tokio::test]
    async fn test_up_db() {
        let stack = TestContainersBuilder::start_database().await;
        let store = stack.database().await.get_store().await;

        let mut rng = get_rng();
        let block = fake::Faker.fake_with_rng(&mut rng);
        store.write_bitcoin_block(&block).await.unwrap();
        assert_eq!(
            store
                .get_bitcoin_block(&block.block_hash)
                .await
                .unwrap()
                .unwrap(),
            block
        );
    }

    #[ignore = "Emily container takes too much time to build"]
    #[tokio::test]
    async fn test_up_emily() {
        let mut stack = TestContainersBuilder::new().with_emily().build();
        stack.up().await.unwrap();

        assert!(stack.get_service_host("emily-server").await.is_ok());
        assert!(stack.get_service_port("emily-server", 3031).await.is_ok());
    }
}

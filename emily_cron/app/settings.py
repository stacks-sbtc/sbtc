import os

# Environment variables and configuration
API_KEY = os.getenv("EMILY_API_KEY", "")
EMILY_ENDPOINT = os.getenv("EMILY_ENDPOINT", "http://emily-server:3031").removesuffix("/")
PRIVATE_EMILY_ENDPOINT = os.getenv(
    "PRIVATE_EMILY_ENDPOINT", f"http://emily-server:3031"
).removesuffix("/")

MEMPOOL_API_URL = os.getenv("MEMPOOL_API_URL", "http://mempool-api:8999/api").removesuffix("/")
# Certain endpoints accessible from mempool.space are internally routed to electrs,
# and not directly exposed by mempool/backend.
# In our local setup, we don't use an extra routing service, so we directly connect
# to the electrs instance instead. We need to specify a different base URL for these
# endpoints.
ELECTRS_API_URL = os.getenv("ELECTRS_API_URL", "http://electrs:3002").removesuffix("/")

HIRO_API_URL = os.getenv("HIRO_API_URL", "https://api.hiro.so").removesuffix("/")

# The address of the deployer of the sbtc-registry contract
DEPLOYER_ADDRESS = os.getenv("DEPLOYER_ADDRESS", "SN3R84XZYA63QS28932XQF3G1J8R9PC3W76P9CSQS")

# The number of confirmations required for a deposit update to be considered final
MIN_BLOCK_CONFIRMATIONS = int(os.getenv("MIN_BLOCK_CONFIRMATIONS", 6))

# Maximum time (in seconds) a transaction can remain unconfirmed before being marked as FAILED
MAX_UNCONFIRMED_TIME = int(os.getenv("MAX_UNCONFIRMED_TIME", 60 * 60 * 24))  # 24 hours in seconds

import os

# Environment variables and configuration
API_KEY = os.getenv("EMILY_API_KEY", "")

EMILY_ENDPOINT = os.getenv("EMILY_ENDPOINT", "http://127.0.0.1:3031").removesuffix("/")

NEW_BLOCK_URL = f"{EMILY_ENDPOINT}/new_block"

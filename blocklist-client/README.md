# Blocklist Client

This Blocklist Client is an auxiliary service for serving a sBTC signer in the process of handling sBTC requests.

The binary exposes a `/screen/{address}` API endpoint, invoked by the sBTC signer binary to screen the
involved addresses before fulfilling a request. The main use case is to prevent interacting with sanctioned addresses.

## Building

Change to the blocklist-client directory and build the program using `cargo`.

```bash
cd blocklist-client
cargo build --release
```

## Running

The blocklist-client supports two sources of blocked addresses:
- File-based sanctions: the binary periodically fetches a list of sanctioned addresses from a URL and uses them to
  answer screening requests.
- Chainalysis API: the binary queries Chainalysis API (or compatible) to answer screening requests.

To configure the blocklist client, either provide a config file (see [src/config/default.toml](src/config/default.toml)
for a commented example) or provide the relevant configuration via environment variables.

### File-based configuration

You need to provide the URL to fetch the blocked addresses list.

- BLOCKLIST_CLIENT_SANCTIONS__URL=`https://example.com/sanctions.txt`

Optionally you can specify:

- BLOCKLIST_CLIENT_SANCTIONS__LOCAL_PATH=<seed sanction list>
- BLOCKLIST_CLIENT_SANCTIONS__POLLING_INTERVAL=<fetching interval in seconds>
- BLOCKLIST_CLIENT_SANCTIONS__HEADER__KEY=<optional header key when fetching>
- BLOCKLIST_CLIENT_SANCTIONS__HEADER__VALUE=<optional header value when fetching>

### API configuration

You need to provide the API details (URL and API key) and the assessment method to use when interacting with the API.

- BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=<provider-url>
- BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=<your_api_key>

Optionally you can specify:

- BLOCKLIST_CLIENT_RISK_ANALYSIS__ASSESSMENT_METHOD=<sanctions (default)|risk_analysis>

```bash
BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=https://your-risk-provider-api.com/ BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=your_api_key ../target/release/blocklist-client
```

### Server configuration

If not specified, the default values from `./src/config/default.toml` will be used.

- BLOCKLIST_CLIENT_SERVER__HOST=<server-hostname-or-ip>
- BLOCKLIST_CLIENT_SERVER__PORT=<server-port>

```bash
BLOCKLIST_CLIENT_SERVER__HOST=127.0.0.1 BLOCKLIST_CLIENT_SERVER__PORT=8080 BLOCKLIST_CLIENT_RISK_ANALYSIS__API_URL=https://your-risk-provider-api.com/ BLOCKLIST_CLIENT_RISK_ANALYSIS__API_KEY=your_api_key BLOCKLIST_CLIENT_RISK_ANALYSIS__ASSESSMENT_METHOD=risk_analysis  ../target/release/blocklist-client
```

## Accessing the API

Once the blocklist client is running successfully, you can access it as follows:

`curl http://127.0.0.1:3030/screen/0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a` should return a response like

```json
{"is_blocklisted":true,"severity":"Severe","accept":false,"reason":"sanctions"}
```

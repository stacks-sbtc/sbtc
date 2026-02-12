#!/usr/bin/env sh

# shellcheck disable=SC2059
# shellcheck source=/dev/null

# Encoding
LC_CTYPE=en_US.UTF-8

# Colors
GRAY='\e[0;90m' # Gray
RED='\e[0;31m' # Red
NC='\e[0m' # No Color
BOLD='\e[1m' # Bold

PROJECT_ROOT="$PWD"
SIGNER_CONFIG="$PROJECT_ROOT/docker/sbtc/signer/signer-config.toml"
ENV_PATH="$PROJECT_ROOT/envs"
DOCKER_COMPOSE_PATH="$PROJECT_ROOT/docker/docker-compose.yml"

LOG_SETTINGS="debug" # Default log level
LOG_SETTINGS="$LOG_SETTINGS,signer::stacks::api=info" # Stacks API
LOG_SETTINGS="$LOG_SETTINGS,hyper=info" # Hyper
LOG_SETTINGS="$LOG_SETTINGS,sqlx=info" # SQLx
LOG_SETTINGS="$LOG_SETTINGS,reqwest=info" # Reqwest
# LibP2P
LOG_SETTINGS="$LOG_SETTINGS,netlink_proto=info,libp2p_autonat=info,libp2p_gossipsub=info,multistream_select=info,yamux=info,libp2p_ping=info,libp2p_kad=info,libp2p_swarm=info,libp2p_tcp=info,libp2p_identify=info,libp2p_dns=info"

# Display help information
exec_help() {
  printf "${BOLD}Usage:${NC} ./signers.sh <command> [arguments]\n\n"
  printf "${BOLD}Available commands:${NC}\n"
  printf "  ${BOLD}run <number>${NC}              Run the specified number of signers (e.g., ./signers.sh run 3)\n"
  printf "  ${BOLD}demo${NC}                      Execute predefined demo operations (donation, deposit)\n"
  printf "  ${BOLD}fund-btc <addr> <sats>${NC}    Fund a Bitcoin address from the regtest wallet (e.g., ./signers.sh fund-btc <address> 100000)\n"
  printf "  ${BOLD}info${NC}                      Get signer info from the database\n"
  printf "  ${BOLD}stop${NC}                      Stop all running signer processes\n"
  printf "  ${BOLD}help${NC}                      Display this help message\n"
}

# Run the specified number of signers
exec_run() {
  if [ "$1" -eq 1 ]; then
    printf "${RED}ERROR:${NC} At least 2 signers are required\n"
    exit 1
  fi

  printf "${GRAY}Running ${NC}${BOLD}$*${NC} signers\n"

  # Turn all the relevant postgres instances off and on.
  docker compose -f "$DOCKER_COMPOSE_PATH" --profile sbtc-postgres up --detach

  # Wait for the postgres instances to start (can get ssl handshake errors etc. otherwise)
  sleep 1

  # Setup the bootstrap signer set.
  i=1
  BOOTSTRAP_SIGNER_SET=""
  while [ $i -le "$1" ]
  do
    SIGNER_KEY=$(. "$ENV_PATH/signer-$i.env"; echo "$SIGNER_PUBKEY")
    if [ "$BOOTSTRAP_SIGNER_SET" = "" ]; then
      export BOOTSTRAP_SIGNER_SET="$SIGNER_KEY"
    else
      export BOOTSTRAP_SIGNER_SET="$BOOTSTRAP_SIGNER_SET,$SIGNER_KEY"
    fi
    i=$((i + 1))
  done

  printf "${BOLD}Using bootstrap signer set:${NC} $BOOTSTRAP_SIGNER_SET\n"

  # Spin up the specified number of signers.
  cargo build --bin  signer
  i=1
  while [ $i -le "$1" ]
  do
    (
      . "$ENV_PATH/signer-$i.env" \
      && export RUST_LOG="$LOG_SETTINGS" \
      && export SIGNER_SIGNER__BOOTSTRAP_SIGNING_SET="$BOOTSTRAP_SIGNER_SET" \
      && cargo run --bin signer -- --config "$SIGNER_CONFIG" --migrate-db > "$PWD/target/signer-$i.log" 2>&1 \
      &
    )
    i=$((i + 1))
  done

  printf "${GRAY}$* signers started${NC}\n"
}

exec_demo() {
  cargo run -p signer --bin demo-cli donation --amount 10000
  cargo run -p signer --bin demo-cli deposit --amount 10000000 # 0.1 BTC
}

exec_info() {
  cargo run -p signer --bin demo-cli info
}

exec_fund_btc() {
  # Check if recipient and sats arguments are provided
  if [ -z "$1" ] || [ -z "$2" ]; then
    printf "${RED}ERROR:${NC} Missing arguments for fund-btc. Usage: fund-btc <recipient_address> <sats_amount>\n"
    exit 1
  fi
  # Fund the BTC address using the provided arguments, capturing output
  printf "${GRAY}Attempting to fund BTC address ${BOLD}%s${NC} with ${BOLD}%s${NC} sats...${NC}\n" "$1" "$2"
  # Capture stdout and stderr
  output=$(cargo run -p signer --bin demo-cli fund-btc --recipient "$1" --amount "$2" 2>&1)
  status=$? # Capture the exit status

  if [ $status -eq 0 ]; then
    # On success, print only the last line of the output (which should contain the tx_id)
    printf "%s\n" "$output" | tail -n 1
  else
    # On error, print an error line and exit with status 1
    printf "${RED}ERROR:${NC} Failed to fund BTC address.\n"
    printf "%s\n" "$output" | tail -n 1
    exit 1
  fi
}

# The main function
main() {
  if [ "$#" -eq 0 ]; then
    printf "${RED}ERROR:${NC} No command provided\n"
    exit 0
  fi

  # Parse the command line arguments
  case "$1" in
    # Run the specified number of signers. Valid values are 2 or 3.
    "run")
      shift # Shift the command off the argument list
      exec_run "$@"
      ;;
    # Execute demo operations
    "demo")
      shift # Shift the command off the argument list
      exec_demo "$@"
      ;;
    "fund-btc")
      shift # Shift the command off the argument list
      exec_fund_btc "$@"
      ;;
    # Get signers info from db
    "info")
      shift # Shift the command off the argument list
      exec_info "$@"
      ;;
    # Stop all running signers by killing the processes.
    "stop")
      ps -ef | awk '/[s]igner --config/{print $2}' | xargs kill -9
    ;;
    # Display help
    "help")
      exec_help
    ;;
    *)
      printf "${RED}ERROR:${NC} Unknown command: $1\n"
      exec_help # Show help on unknown command
      exit 1
  esac
}

# Run the main function with all the command line arguments
main "$@"

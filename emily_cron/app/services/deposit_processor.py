import logging
from itertools import chain
from typing import Iterable

from ..clients import PrivateEmilyAPI, HiroAPI, MempoolAPI
from ..models import (
    DepositUpdate,
    EnrichedDepositInfo,
    RequestStatus,
    DepositInfo,
)

logger = logging.getLogger(__name__)


class DepositProcessor:
    """Service for processing deposits."""

    def process_rbf_transactions(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
    ) -> list[DepositUpdate]:
        """Process RBF transactions.
        Args:
            enriched_deposits: List of enriched deposit information
        Returns:
            list[DepositUpdate]: List of deposit updates
        """
        updates = []

        # Find transactions with RBF replacements
        rbf_txs = [tx for tx in enriched_deposits if tx.rbf_txids]
        if not rbf_txs:
            return updates

        logger.info(f"Found {len(rbf_txs)} transactions with RBF replacements")

        # Group by replacement chain
        rbf_groups = self._group_rbf_transactions(rbf_txs)

        # Process each group
        for group_txids in rbf_groups.values():
            # Find all transactions in this group
            group_txs = [tx for tx in enriched_deposits if tx.bitcoin_txid in group_txids]

            # Check if any transaction in this group is confirmed
            confirmed_txs = [tx for tx in group_txs if tx.confirmed_height is not None]

            if not confirmed_txs:
                logger.debug(f"No confirmed transactions found for group {group_txids}")
                continue

            # If we have confirmed transactions, mark all unconfirmed ones as FAILED
            for tx in group_txs:
                if tx.confirmed_height is None:
                    logger.info(
                        f"Marking RBF'd transaction {tx.bitcoin_txid} as FAILED (replaced by confirmed tx)"
                    )
                    updates.append(
                        DepositUpdate(
                            bitcoin_txid=tx.bitcoin_txid,
                            bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                            status=RequestStatus.FAILED.value,
                            status_message=f"Replaced by confirmed tx {confirmed_txs[0].bitcoin_txid}",
                        )
                    )
        return updates

    def process_expired_locktime(
        self,
        enriched_deposits: list[EnrichedDepositInfo],
        bitcoin_chaintip_height: int,
    ) -> list[DepositUpdate]:
        """Process transactions with expired locktime.

        This includes:
        - Transactions where locktime expired and the UTXO was NOT spent.
        - Transactions where the UTXO was reclaimed.

        Args:
            enriched_deposits: List of enriched deposit information
            bitcoin_chaintip_height: Current Bitcoin chain tip height

        Returns:
            list[DepositUpdate]: List of deposit updates
        """
        updates = []

        for tx in enriched_deposits:
            # Step 1: Check if the time-based expiry condition is met
            if not tx.is_expired(bitcoin_chaintip_height):
                continue  # Not eligible for failure yet based on time

            # Step 2: Time has expired, now check UTXO status
            logger.debug(f"Deposit {tx.bitcoin_txid} time expired, checking UTXO status...")
            utxo_status = MempoolAPI.get_utxo_status(tx.bitcoin_txid, tx.bitcoin_tx_output_index)
            is_utxo_spent = utxo_status.get("spent", False)
            if not is_utxo_spent:
                # Case 1: Time expired AND UTXO is unspent -> Mark FAILED
                logger.info(
                    f"Marking transaction {tx.bitcoin_txid} as FAILED (Locktime expired, unspent)"
                )
                updates.append(
                    DepositUpdate(
                        bitcoin_txid=tx.bitcoin_txid,
                        bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                        status=RequestStatus.FAILED.value,
                        status_message=f"Locktime expired at height {bitcoin_chaintip_height} and UTXO unspent",
                    )
                )
                continue

            # Step 3: UTXO is spent, check if it was a reclaim
            spending_txid = utxo_status.get("txid")
            if spending_txid is None:
                logger.warning(
                    f"Deposit {tx.bitcoin_txid} UTXO is spent, but spending TXID is missing from API response. Cannot check for reclaim."
                )
                continue  # Cannot determine reclaim, skip at this time
            vin_index = utxo_status.get("vin")
            if vin_index is None:
                logger.warning(
                    f"Deposit {tx.bitcoin_txid} UTXO spent by {spending_txid}, but no vin index found in API response. Cannot check for reclaim."
                )
                continue  # Cannot determine reclaim, skip at this time

            logger.debug(
                f"Deposit {tx.bitcoin_txid} UTXO spent by {spending_txid}, checking for reclaim..."
            )
            spending_tx_details = MempoolAPI.get_transaction(spending_txid)
            if not spending_tx_details:
                logger.warning(
                    f"Could not fetch spending tx details for {spending_txid} to check for reclaim of {tx.bitcoin_txid}."
                )
                continue  # Cannot determine reclaim, skip at this time

            vin = spending_tx_details.get("vin", [])
            try:
                vin = vin[vin_index]
            except IndexError:
                logger.warning(
                    f"Deposit {tx.bitcoin_txid} UTXO spent by {spending_txid}, but vin index {vin_index} is out of bounds. Cannot check for reclaim."
                )
                continue  # Cannot determine reclaim, skip at this time
            witness_data = vin.get("witness", [])
            # Simple check: does witness contain the reclaim script?
            is_reclaim_check = any(tx.reclaim_script in item for item in witness_data)

            if is_reclaim_check:
                # Case 2: Time expired, UTXO spent, AND identified as reclaim -> Mark FAILED
                logger.info(
                    f"Marking transaction {tx.bitcoin_txid} as FAILED (Depositor reclaim detected)"
                )
                updates.append(
                    DepositUpdate(
                        bitcoin_txid=tx.bitcoin_txid,
                        bitcoin_tx_output_index=tx.bitcoin_tx_output_index,
                        status=RequestStatus.FAILED.value,
                        status_message=f"Depositor reclaim detected in tx {spending_txid}",
                    )
                )
            else:
                # Case 3: Time expired, UTXO spent, but NOT identified as reclaim -> Assume signer sweep, do nothing.
                logger.debug(
                    f"Deposit {tx.bitcoin_txid} time expired, but UTXO spent by {spending_txid} (likely signer sweep). Not failing."
                )

        logger.info(f"Found {len(updates)} transactions to mark as FAILED (expired or reclaimed)")

        return updates

    def update_deposits(self) -> None:
        """Update deposit statuses.

        This is the main entry point for the deposit processor.
        It fetches deposits, enriches them, processes them, and updates their status.
        """
        logger.info("Running deposit status update job")

        # Get current blockchain state
        bitcoin_chaintip_height = MempoolAPI.get_tip_height()
        stacks_chaintip = HiroAPI.get_stacks_block()

        logger.info(f"Bitcoin chain tip: {bitcoin_chaintip_height}")
        logger.info(f"Stacks chain tip: {stacks_chaintip}")

        # Fetch pending and accepted deposits.
        # Accepted deposits are included because Bitcoin forks could invalidate
        # a previously accepted deposit, or a malicious signer may have modified
        # a pending or invalid deposit to Accepted.
        pending_deposits = PrivateEmilyAPI.fetch_deposits(RequestStatus.PENDING)
        accepted_deposits = PrivateEmilyAPI.fetch_deposits(RequestStatus.ACCEPTED)

        # Enrich deposits with additional transaction data
        enriched_deposits = self._enrich_deposits(chain(pending_deposits, accepted_deposits))

        # Process deposits and collect updates
        updates = []

        # Process transactions with expired locktime or reclaimed
        locktime_updates = self.process_expired_locktime(enriched_deposits, bitcoin_chaintip_height)
        updates.extend(locktime_updates)

        # Process RBF transactions
        rbf_updates = self.process_rbf_transactions(enriched_deposits)
        updates.extend(rbf_updates)

        # Apply updates
        if updates:
            logger.info(f"Updating {len(updates)} deposit statuses")
            PrivateEmilyAPI.update_deposits(updates)
        else:
            logger.info("No deposit updates needed")

        logger.info("Deposit status update job completed")

    def _group_rbf_transactions(self, rbf_txs: list[EnrichedDepositInfo]) -> dict[str, set[str]]:
        """Group RBF transactions by their replacement chains.
        Args:
            rbf_txs: List of transactions with RBF replacements
        Returns:
            dict[str, set[str]]: Dictionary mapping group IDs to sets of transaction IDs
        """
        rbf_groups: dict[str, set[str]] = {}

        # First, build groups of related transactions (original + replacements)
        for tx in rbf_txs:
            # Create a set of all txids in this RBF chain
            chain_txids = set(tx.rbf_txids)
            chain_txids.add(tx.bitcoin_txid)

            # Find all groups that overlap with this chain
            overlapping_groups = []
            for group_id, group_txids in list(rbf_groups.items()):
                if chain_txids.intersection(group_txids):
                    overlapping_groups.append(group_id)

            if overlapping_groups:
                # Merge all overlapping groups into the first one
                primary_group_id = overlapping_groups[0]
                merged_txids = set(rbf_groups[primary_group_id])

                # Add the current chain
                merged_txids.update(chain_txids)

                # Merge in all other overlapping groups
                for group_id in overlapping_groups[1:]:
                    merged_txids.update(rbf_groups[group_id])
                    # Remove the merged group
                    del rbf_groups[group_id]

                # Update the primary group with the merged set
                rbf_groups[primary_group_id] = merged_txids
            else:
                # Create a new group
                rbf_groups[tx.bitcoin_txid] = chain_txids

        return rbf_groups

    def _enrich_deposits(self, deposits: Iterable[DepositInfo]) -> list[EnrichedDepositInfo]:
        """Fetch transaction details and UTXO status, and enrich deposit info.

        Args:
            deposits: Iterable of DepositInfo objects

        Returns:
            list[EnrichedDepositInfo]: List of enriched deposit information
        """
        transaction_details = []
        for deposit in deposits:
            tx_data = MempoolAPI.get_transaction(deposit.bitcoin_txid)

            if not tx_data:
                transaction_details.append(EnrichedDepositInfo.from_missing(deposit))
                continue

            if "fee" not in tx_data:
                logger.debug(f"Fee is missing for transaction {deposit.bitcoin_txid}")

            additional_info = {
                "in_mempool": True,
                "fee": tx_data.get("fee"),
                "confirmed_height": tx_data.get("status", {}).get("block_height"),
                "confirmed_time": tx_data.get("status", {}).get("block_time"),
            }

            # Only check for RBF if not confirmed
            if additional_info["confirmed_height"] is None:
                additional_info["rbf_txids"] = MempoolAPI.check_for_rbf(deposit.bitcoin_txid)

            transaction_details.append(
                EnrichedDepositInfo.from_deposit_info(deposit, additional_info)
            )

        return transaction_details

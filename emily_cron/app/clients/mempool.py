import logging
from typing import Any

from .base import APIClient
from .. import settings

logger = logging.getLogger(__name__)


def _collect_rbf_txids(data: dict[str, Any] | None) -> set[str]:
    """Recursively collect all RBF transaction IDs from the replacement chain.

    Args:
        data: Transaction replacement data from mempool API

    Returns:
        Set of transaction IDs that replaced the original transaction
    """
    txids = set()

    if data is None:
        return txids

    if tx := data.get("tx", {}):
        if txid := tx.get("txid"):
            txids.add(txid)

    for replacement in data.get("replaces", []):
        txids.update(_collect_rbf_txids(replacement))

    return txids


class MempoolAPI(APIClient):
    """Client for interacting with the Mempool API."""

    BASE_URL = settings.MEMPOOL_API_URL

    @classmethod
    def check_for_rbf(cls, txid: str) -> set[str]:
        """Check if a Bitcoin transaction was replaced by RBF.

        Args:
            txid: The transaction ID to check

        Returns:
            Set of transaction IDs that replaced the original transaction
        """
        data = cls.get(f"/v1/tx/{txid}/rbf")
        return _collect_rbf_txids(data.get("replacements", {}))

    @classmethod
    def get_tip_height(cls) -> int:
        """Get the height of the tip of the Bitcoin chain.

        Errors are not ignored (ignore_errors=False) because tip height
        is critical for processing deposits and determining chain state.

        Returns:
            int: The height of the tip of the Bitcoin chain

        Raises:
            requests.RequestException: If the request fails (HTTP 400-599)
            ValueError: If the response cannot be parsed as JSON
        """
        return cls.get("/v1/blocks/tip/height", ignore_errors=False)

    @classmethod
    def get_transaction(cls, txid: str) -> dict[str, Any]:
        """Fetch details for a Bitcoin transaction.

        Args:
            txid: The transaction ID to fetch

        Returns:
            dict: Transaction details or empty dict if not found
        """
        return cls.get(f"/tx/{txid}", ignore_errors=True)

    @classmethod
    def get_utxo_status(cls, txid: str, vout: int) -> dict[str, Any]:
        """Check if a specific transaction output (UTXO) has been spent.

        Args:
            txid: The transaction ID of the UTXO
            vout: The output index (vout) of the UTXO

        Returns:
            dict: Status of the UTXO. Example:
                  {'spent': False} if unspent.
                  {'spent': True, 'txid': 'spending_txid', 'vin': 0, 'status': {'confirmed': True/False}} if spent.
                  Returns empty dict if the original txid is not found or other errors.
        """
        # This endpoint returns spending info if spent, 404 or empty if not.
        # We don't raise on error here because a 404 indicates "unspent".
        spending_info = cls.get(f"/tx/{txid}/outspend/{vout}", ignore_errors=True)
        if not spending_info or not spending_info.get("spent", False):
            return {"spent": False}
        else:
            # Ensure status dictionary exists
            status = spending_info.get("status", {})
            return {
                "spent": True,
                "txid": spending_info.get("txid"),
                "vin": spending_info.get("vin"),
                "status": {"confirmed": status.get("confirmed", False)},
            }

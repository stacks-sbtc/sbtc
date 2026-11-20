//! General utilities for the storage.

use std::collections::BTreeMap;
use std::collections::HashSet;

use crate::bitcoin::utxo::SignerUtxo;
use crate::bitcoin::utxo::SignerUtxoKeySet;
use crate::error::Error;

/// Given the sBTC transactions in a block, return the signer UTXO locked by
/// one of the known signer key sets, if there is exactly one.
pub fn get_utxo(
    key_sets: &BTreeMap<bitcoin::ScriptBuf, SignerUtxoKeySet>,
    sbtc_txs: Vec<bitcoin::Transaction>,
) -> Result<Option<SignerUtxo>, Error> {
    let spent: HashSet<bitcoin::OutPoint> = sbtc_txs
        .iter()
        .flat_map(|tx| tx.input.iter().map(|txin| txin.previous_output))
        .collect();

    let mut utxos = sbtc_txs
        .iter()
        .flat_map(|tx| {
            if let Some(tx_out) = tx.output.first() {
                let outpoint = bitcoin::OutPoint::new(tx.compute_txid(), 0);
                if let Some(key_set) = key_sets.get(&tx_out.script_pubkey)
                    && !spent.contains(&outpoint)
                {
                    return Some(SignerUtxo {
                        outpoint,
                        amount: tx_out.value.to_sat(),
                        key_set: key_set.clone(),
                    });
                }
            }

            None
        })
        .collect::<Vec<_>>();

    match utxos.len() {
        0 => Ok(None),
        1 => Ok(utxos.pop()),
        _ => Err(Error::TooManySignerUtxos),
    }
}

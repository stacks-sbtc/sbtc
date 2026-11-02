# CreateDepositRequestBody

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_tx_output_index** | **u32** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **String** | Bitcoin transaction id. | 
**deposit_script** | **String** | Deposit script. | 
**max_fee** | Option<**u64**> | Maximum fee in satoshis. Required for v2 deposits. | [optional]
**recipient** | Option<**String**> | The consensus-encoded Stacks principal, represented as hex. Required for v2 deposits. | [optional]
**reclaim_script** | **String** | Reclaim script. | 
**transaction_hex** | **String** | The raw transaction hex. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



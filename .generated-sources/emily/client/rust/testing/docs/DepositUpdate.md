# DepositUpdate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_tx_output_index** | **u32** | Output index on the bitcoin transaction associated with this specific deposit. | 
**bitcoin_txid** | **String** | Bitcoin transaction id. | 
**fulfillment** | Option<[**models::Fulfillment**](Fulfillment.md)> |  | [optional]
**replaced_by_tx** | Option<**String**> | Transaction ID of the transaction that replaced this one via RBF. | [optional]
**status** | [**models::DepositStatus**](DepositStatus.md) |  | 
**status_message** | **String** | The status message of the deposit. | 

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



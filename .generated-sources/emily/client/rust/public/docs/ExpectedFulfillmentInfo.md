# ExpectedFulfillmentInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_block_height** | Option<**u64**> | The estimated bitcoin block height for the bitcoin block confirming the transaction fulling the withdrawal request. This value is estimated by Emily once when the withdrawal request is initially received. | [optional]
**bitcoin_txid** | Option<**String**> | The expected txid of the sweep transaction fulfilling the withdrawal request. This field is populated once, it is not updated if there is an RBF transaction that also fulfills the request. | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



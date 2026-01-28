# ExpectedFulfillmentInfo

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bitcoin_block_height** | Option<**u64**> | Expected bitcoin block height into which sweep transaction will be included into the block. Calculated by Emily once, no ajustments are made if something goes wrong. | [optional]
**bitcoin_txid** | Option<**String**> | Expected txid of the sweep transaction. This field is populated once, and will not be changed if there is and rbf (and will show incorrect expectation) | [optional]

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)



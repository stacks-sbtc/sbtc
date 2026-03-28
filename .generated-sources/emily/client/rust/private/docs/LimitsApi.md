# \LimitsApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_limits**](LimitsApi.md#get_limits) | **GET** /limits | Get the global limits.
[**set_limits**](LimitsApi.md#set_limits) | **POST** /limits | Set limits handler.



## get_limits

> models::Limits get_limits()
Get the global limits.

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::Limits**](Limits.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## set_limits

> models::Limits set_limits(limits)
Set limits handler.

Note, that `available_to_withdraw` is not settable, but is calculated based on the other fields. Value of `available_to_withdraw` passed to this endpoint will be ignored.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**limits** | [**Limits**](Limits.md) |  | [required] |

### Return type

[**models::Limits**](Limits.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


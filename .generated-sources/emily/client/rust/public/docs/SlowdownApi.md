# \ThrottleApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**start_throttle**](ThrottleApi.md#start_throttle) | **POST** /start_throttle | Try to turn on slow mode



## start_throttle

> models::Limits start_throttle(throttle_reqwest)
Try to turn on slow mode

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**throttle_reqwest** | [**ThrottleReqwest**](ThrottleReqwest.md) |  | [required] |

### Return type

[**models::Limits**](Limits.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


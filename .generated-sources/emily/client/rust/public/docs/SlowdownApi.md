# \SlowdownApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**get_slowdown_key**](SlowdownApi.md#get_slowdown_key) | **GET** /slowdown | Get the slowdown key details.
[**start_slowdown**](SlowdownApi.md#start_slowdown) | **POST** /slowdown/start | Try to turn on slow mode



## get_slowdown_key

> models::SlowdownKey get_slowdown_key(body)
Get the slowdown key details.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**body** | **String** |  | [required] |

### Return type

[**models::SlowdownKey**](SlowdownKey.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: text/plain
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## start_slowdown

> models::Limits start_slowdown(slowdown_reqwest)
Try to turn on slow mode

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**slowdown_reqwest** | [**SlowdownReqwest**](SlowdownReqwest.md) |  | [required] |

### Return type

[**models::Limits**](Limits.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


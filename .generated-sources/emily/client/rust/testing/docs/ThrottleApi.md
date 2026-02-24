# \ThrottleApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**activate_throttle_key**](ThrottleApi.md#activate_throttle_key) | **PATCH** /throttle/activate | Activate existing (previously deactivated) throttle key
[**add_throttle_key**](ThrottleApi.md#add_throttle_key) | **POST** /throttle | Add throttle key handler.
[**deactivate_throttle_key**](ThrottleApi.md#deactivate_throttle_key) | **PATCH** /throttle/deactivate | Deactivate existing throttle key
[**get_throttle_key**](ThrottleApi.md#get_throttle_key) | **GET** /throttle | Get the throttle key details.
[**start_throttle**](ThrottleApi.md#start_throttle) | **POST** /start_throttle | Try to turn on throttle mode
[**stop_throttle**](ThrottleApi.md#stop_throttle) | **POST** /throttle/stop | Stop throttle.



## activate_throttle_key

> activate_throttle_key(body)
Activate existing (previously deactivated) throttle key

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**body** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: text/plain
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## add_throttle_key

> add_throttle_key(throttle_key)
Add throttle key handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**throttle_key** | [**ThrottleKey**](ThrottleKey.md) |  | [required] |

### Return type

 (empty response body)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## deactivate_throttle_key

> deactivate_throttle_key(body)
Deactivate existing throttle key

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**body** | **String** |  | [required] |

### Return type

 (empty response body)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: text/plain
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## get_throttle_key

> models::GetThrottleKeyResponse get_throttle_key(body)
Get the throttle key details.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**body** | **String** |  | [required] |

### Return type

[**models::GetThrottleKeyResponse**](GetThrottleKeyResponse.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: text/plain
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## start_throttle

> models::Limits start_throttle(throttle_request)
Try to turn on throttle mode

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**throttle_request** | [**ThrottleRequest**](ThrottleRequest.md) |  | [required] |

### Return type

[**models::Limits**](Limits.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## stop_throttle

> serde_json::Value stop_throttle()
Stop throttle.

### Parameters

This endpoint does not need any parameter.

### Return type

[**serde_json::Value**](serde_json::Value.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


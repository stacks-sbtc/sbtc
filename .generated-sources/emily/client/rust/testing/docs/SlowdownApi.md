# \SlowdownApi

All URIs are relative to *http://localhost*

Method | HTTP request | Description
------------- | ------------- | -------------
[**activate_slowdown_key**](SlowdownApi.md#activate_slowdown_key) | **PATCH** /slowdown/activate/{name} | Activate existing (previously deactivated) slowdown key
[**add_slowdown_key**](SlowdownApi.md#add_slowdown_key) | **POST** /slowdown | Add slowdown key handler.
[**deactivate_slowdown_key**](SlowdownApi.md#deactivate_slowdown_key) | **PATCH** /slowdown/deactivate/{name} | Deactivate existing slowdown key
[**get_slowdown_key**](SlowdownApi.md#get_slowdown_key) | **GET** /slowdown | Get the slowdown key details.
[**start_slowdown**](SlowdownApi.md#start_slowdown) | **POST** /start_slowdown | Try to turn on slow mode



## activate_slowdown_key

> serde_json::Value activate_slowdown_key(name)
Activate existing (previously deactivated) slowdown key

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**name** | **String** | The name of the key to activate | [required] |

### Return type

[**serde_json::Value**](serde_json::Value.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## add_slowdown_key

> models::SlowdownKey add_slowdown_key(slowdown_key)
Add slowdown key handler.

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**slowdown_key** | [**SlowdownKey**](SlowdownKey.md) |  | [required] |

### Return type

[**models::SlowdownKey**](SlowdownKey.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: application/json
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## deactivate_slowdown_key

> serde_json::Value deactivate_slowdown_key(name)
Deactivate existing slowdown key

### Parameters


Name | Type | Description  | Required | Notes
------------- | ------------- | ------------- | ------------- | -------------
**name** | **String** | The name of the key to deactivate | [required] |

### Return type

[**serde_json::Value**](serde_json::Value.md)

### Authorization

[ApiGatewayKey](../README.md#ApiGatewayKey)

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


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


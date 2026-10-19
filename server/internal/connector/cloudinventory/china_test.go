package cloudinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func chinaConfig(provider string) Config {
	if provider == "aliyun" {
		return Config{AccountID: "19681320001234567", Regions: []string{"cn-hangzhou"}, AddressMode: "private"}
	}
	return Config{AccountID: "1000262009", Regions: []string{"ap-guangzhou"}, AddressMode: "private"}
}
func chinaCredential(provider string) Credential {
	id := "AKIDsyntheticcloudkey001"
	if provider == "aliyun" {
		id = "STS.syntheticcloudkey001"
	}
	return Credential{AccessKeyID: id, SecretAccessKey: "synthetic-china-cloud-secret", SessionToken: "synthetic-session+/=token"}
}
func encodedJSON(t *testing.T, value any) string {
	t.Helper()
	data, e := json.Marshal(value)
	require.NoError(t, e)
	return string(data)
}
func jsonFixtureClient(t *testing.T, provider string, fn func(*http.Request, string, url.Values, map[string]any) *http.Response) *Client {
	t.Helper()
	c := NewClient()
	c.now = func() time.Time { return time.Date(2026, 10, 19, 0, 20, 0, 0, time.FixedZone("qa", 8*3600)) }
	c.http.Transport = roundTrip(func(request *http.Request) (*http.Response, error) {
		assert.Equal(t, "https", request.URL.Scheme)
		assert.Equal(t, "POST", request.Method)
		assert.Empty(t, request.URL.RawQuery)
		raw, e := io.ReadAll(request.Body)
		require.NoError(t, e)
		values := url.Values{}
		var body map[string]any
		action := ""
		if provider == "aliyun" {
			values, e = url.ParseQuery(string(raw))
			require.NoError(t, e)
			action = values.Get("Action")
			assert.Equal(t, chinaCredential(provider).AccessKeyID, values.Get("AccessKeyId"))
			assert.Equal(t, chinaCredential(provider).SessionToken, values.Get("SecurityToken"))
			assert.Len(t, values.Get("SignatureNonce"), 32)
			assert.Equal(t, "2026-10-18T16:20:00Z", values.Get("Timestamp"))
			assert.NotEmpty(t, values.Get("Signature"))
		} else {
			require.NoError(t, json.Unmarshal(raw, &body))
			action = request.Header.Get("X-TC-Action")
			assert.Equal(t, chinaCredential(provider).SessionToken, request.Header.Get("X-TC-Token"))
			assert.Contains(t, request.Header.Get("Authorization"), "/2026-10-18/")
		}
		assert.Contains(t, []string{"GetCallerIdentity", "DescribeInstances"}, action)
		return fn(request, action, values, body), nil
	})
	t.Cleanup(c.Close)
	return c
}
func identityResponse(provider string) map[string]any {
	account := chinaConfig(provider).AccountID
	if provider == "aliyun" {
		return map[string]any{"AccountId": account, "Arn": "acs:ram::" + account + ":assumed-role/qa/session", "RequestId": "identity-qa"}
	}
	return map[string]any{"Response": map[string]any{"AccountId": account, "Arn": "qcs::cam:uin/" + account + ":role/qa/session", "RequestId": "identity-qa"}}
}
func chinaInstance(provider string, n int, state string) map[string]any {
	if provider == "aliyun" {
		return map[string]any{"InstanceId": fmt.Sprintf("i-aliyun%08d", n), "InstanceName": "QA ECS", "InstanceOwnerId": json.Number(chinaConfig(provider).AccountID), "RegionId": "cn-hangzhou", "ZoneId": "cn-hangzhou-h", "Status": state, "VpcAttributes": map[string]any{"PrivateIpAddress": map[string]any{"IpAddress": []string{"10.0.0.7"}}}, "PublicIpAddress": map[string]any{"IpAddress": []string{"192.0.2.8"}}, "EipAddress": map[string]any{"IpAddress": "192.0.2.7"}, "NetworkInterfaces": map[string]any{"NetworkInterface": []any{map[string]any{"Ipv6Sets": map[string]any{"Ipv6Set": []any{map[string]any{"Ipv6Address": "2001:db8::7"}}}}}}, "Tags": map[string]any{"Tag": []any{map[string]any{"TagKey": "team", "TagValue": "ops"}}}}
	}
	return map[string]any{"InstanceId": fmt.Sprintf("ins-%08d", n), "InstanceName": "QA CVM", "InstanceState": state, "Placement": map[string]any{"Zone": "ap-guangzhou-3"}, "PrivateIpAddresses": []string{"10.0.0.7"}, "PublicIpAddresses": []string{"192.0.2.7"}, "IPv6Addresses": []string{"2001:db8::7"}, "Tags": []any{map[string]any{"Key": "team", "Value": "ops"}}}
}
func chinaPage(provider string, items []map[string]any, total int, next string) map[string]any {
	if provider == "aliyun" {
		return map[string]any{"RequestId": "page-qa", "NextToken": next, "Instances": map[string]any{"Instance": items}}
	}
	return map[string]any{"Response": map[string]any{"RequestId": "page-qa", "TotalCount": total, "InstanceSet": items}}
}

func TestAlibabaRPCPublishedSignatureVectors(t *testing.T) {
	// Public test credentials and vectors from Alibaba Cloud's RPC documentation.
	// https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism
	values := url.Values{"AccessKeyId": {"testid"}, "Action": {"DescribeDedicatedHosts"}, "Format": {"JSON"}, "RegionId": {"cn-beijing"}, "SignatureMethod": {"HMAC-SHA1"}, "SignatureNonce": {"edb2b34af0af9a6d14deaf7c1a5315eb"}, "SignatureVersion": {"1.0"}, "Timestamp": {"2023-03-13T08:34:30Z"}, "Version": {"2014-05-26"}}
	assert.Equal(t, "9NaGiOspFP5UPcwX8Iwt2YJXXuk=", aliyunSignature("GET", values, "testsecret"))
	values = url.Values{"AccessKeyId": {"testid"}, "AccountName": {"<a%b'>"}, "Action": {"SingleSendMail"}, "AddressType": {"1"}, "Format": {"XML"}, "HtmlBody": {"4"}, "RegionId": {"cn-hangzhou"}, "ReplyToAddress": {"true"}, "SignatureMethod": {"HMAC-SHA1"}, "SignatureNonce": {"c1b2c332-4cfb-4a0f-b8cc-ebe622aa0a5c"}, "SignatureVersion": {"1.0"}, "Subject": {"3"}, "TagName": {"2"}, "Timestamp": {"2016-10-20T06:27:56Z"}, "ToAddress": {"1@test.com"}, "Version": {"2015-11-23"}}
	assert.Equal(t, "llJfXJjBW3OacrVgxxsITgYaYm0=", aliyunSignature("POST", values, "testsecret"))
	assert.Equal(t, "%20%2B%2A~%2F%E4%B8%AD", rpcEscape(" +*~/中"))
}

func TestTencentPublishedTC3SignatureVector(t *testing.T) {
	// https://www.tencentcloud.com/document/product/1176/55147
	request, e := http.NewRequest("POST", "https://cvm.tencentcloudapi.com/", nil)
	require.NoError(t, e)
	body := `{"Limit": 1, "Filters": [{"Values": ["unnamed"], "Name": "instance-name"}]}`
	signTencent(request, body, "cvm", "ap-guangzhou", "DescribeInstances", "2017-03-12", Credential{AccessKeyID: "AKID" + strings.Repeat("*", 32), SecretAccessKey: strings.Repeat("*", 32)}, time.Unix(1551113065, 0))
	assert.Equal(t, "TC3-HMAC-SHA256 Credential=AKID"+strings.Repeat("*", 32)+"/2019-02-25/cvm/tc3_request, SignedHeaders=content-type;host, Signature=a7b8551448762bd123d6f79e81815e31a92013640a6cef36a08ad4b292a4d2f2", request.Header.Get("Authorization"))
}

func TestChinaInventoryIdentityPaginationMetadataAndStoppedInstances(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		t.Run(provider, func(t *testing.T) {
			pages, preflights := 0, 0
			c := jsonFixtureClient(t, provider, func(request *http.Request, action string, values url.Values, body map[string]any) *http.Response {
				if action == "GetCallerIdentity" {
					assert.Equal(t, map[string]string{"aliyun": "sts.aliyuncs.com", "tencentcloud": "sts.tencentcloudapi.com"}[provider], request.URL.Host)
					return response(200, encodedJSON(t, identityResponse(provider)))
				}
				if provider == "aliyun" {
					assert.Equal(t, "ecs.cn-hangzhou.aliyuncs.com", request.URL.Host)
					assert.Equal(t, "100", values.Get("MaxResults"))
					assert.Equal(t, "cn-hangzhou", values.Get("RegionId"))
					if values.Get("DryRun") == "true" {
						preflights++
						return response(400, `{"Code":"DryRunOperation","RequestId":"dry-run-qa"}`)
					}
				} else {
					assert.Equal(t, "cvm.tencentcloudapi.com", request.URL.Host)
					assert.Equal(t, "ap-guangzhou", request.Header.Get("X-TC-Region"))
					assert.Equal(t, "2017-03-12", request.Header.Get("X-TC-Version"))
					assert.Equal(t, float64(100), body["Limit"])
					assert.Equal(t, float64(pages), body["Offset"])
				}
				pages++
				state := "Running"
				next := "next+page/="
				if provider == "tencentcloud" {
					state = "RUNNING"
				}
				if pages == 2 {
					state = "Stopped"
					next = ""
					if provider == "tencentcloud" {
						state = "STOPPED"
					}
					if provider == "aliyun" {
						assert.Equal(t, "next+page/=", values.Get("NextToken"))
					}
				}
				return response(200, encodedJSON(t, chinaPage(provider, []map[string]any{chinaInstance(provider, pages, state)}, 2, next)))
			})
			rows, e := c.List(context.Background(), provider, chinaConfig(provider), chinaCredential(provider))
			require.NoError(t, e)
			require.Len(t, rows, 2)
			assert.Equal(t, 2, pages)
			if provider == "aliyun" {
				assert.Equal(t, 2, preflights)
			}
			assert.Equal(t, "running", rows[0].State)
			assert.Equal(t, "stopped", rows[1].State)
			assert.Equal(t, "10.0.0.7", rows[0].PrivateIP)
			assert.Equal(t, "192.0.2.7", rows[0].PublicIP)
			assert.Equal(t, "2001:db8::7", rows[0].IPv6)
			assert.Equal(t, "ops", rows[0].Tags["team"])
			assert.NotEmpty(t, rows[0].ProviderState)
		})
	}
}

func TestAlibabaPreflightDenialCannotPublishAnEmptyOrPartialInventory(t *testing.T) {
	for _, mode := range []string{"before", "after", "not-dry-run", "missing-array", "token-cycle", "wrong-region", "wrong-owner", "bad-ip"} {
		t.Run(mode, func(t *testing.T) {
			preflights := 0
			c := jsonFixtureClient(t, "aliyun", func(_ *http.Request, action string, v url.Values, _ map[string]any) *http.Response {
				if action == "GetCallerIdentity" {
					return response(200, encodedJSON(t, identityResponse("aliyun")))
				}
				if v.Get("DryRun") == "true" {
					preflights++
					if mode == "before" || mode == "after" && preflights == 2 {
						return response(403, `{"Code":"Forbidden.RAM","RequestId":"denied-qa"}`)
					}
					if mode == "not-dry-run" {
						return response(200, encodedJSON(t, chinaPage("aliyun", []map[string]any{}, 0, "")))
					}
					return response(400, `{"Code":"DryRunOperation"}`)
				}
				item := chinaInstance("aliyun", 1, "Running")
				next := ""
				switch mode {
				case "wrong-region":
					item["RegionId"] = "cn-beijing"
				case "wrong-owner":
					item["InstanceOwnerId"] = json.Number("99999999999999999")
				case "bad-ip":
					item["EipAddress"] = map[string]any{"IpAddress": "127.0.0.1"}
				case "token-cycle":
					next = "repeat"
				case "missing-array":
					return response(200, `{"RequestId":"qa","Instances":{}}`)
				}
				items := []map[string]any{item}
				if mode == "token-cycle" {
					items = []map[string]any{}
				}
				return response(200, encodedJSON(t, chinaPage("aliyun", items, 1, next)))
			})
			rows, e := c.List(context.Background(), "aliyun", chinaConfig("aliyun"), chinaCredential("aliyun"))
			assert.Error(t, e)
			assert.Nil(t, rows)
			if mode == "before" || mode == "after" {
				assert.ErrorIs(t, e, ErrPermission)
			}
		})
	}
}

func TestChinaInventoryDoesNotReturnPartialRegions(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		t.Run(provider, func(t *testing.T) {
			cfg := chinaConfig(provider)
			second := "ap-shanghai"
			if provider == "aliyun" {
				second = "cn-shanghai"
			}
			cfg.Regions = append(cfg.Regions, second)
			c := jsonFixtureClient(t, provider, func(request *http.Request, action string, v url.Values, _ map[string]any) *http.Response {
				if action == "GetCallerIdentity" {
					return response(200, encodedJSON(t, identityResponse(provider)))
				}
				region := request.Header.Get("X-TC-Region")
				if provider == "aliyun" {
					region = v.Get("RegionId")
				}
				if region == second {
					if provider == "aliyun" {
						return response(403, `{"Code":"Forbidden.RAM"}`)
					}
					return response(200, `{"Response":{"Error":{"Code":"UnauthorizedOperation"}}}`)
				}
				if v.Get("DryRun") == "true" {
					return response(400, `{"Code":"DryRunOperation"}`)
				}
				return response(200, encodedJSON(t, chinaPage(provider, []map[string]any{chinaInstance(provider, 1, "Running")}, 1, "")))
			})
			rows, e := c.List(context.Background(), provider, cfg, chinaCredential(provider))
			assert.ErrorIs(t, e, ErrPermission)
			assert.Nil(t, rows)
		})
	}
}

func TestChinaRetriesAreBoundedAndCancellationStopsBackoff(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		for _, cancelRequest := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cancel=%v", provider, cancelRequest), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				calls := 0
				nonces := map[string]bool{}
				c := jsonFixtureClient(t, provider, func(_ *http.Request, _ string, v url.Values, _ map[string]any) *http.Response {
					calls++
					if provider == "aliyun" {
						assert.False(t, nonces[v.Get("SignatureNonce")])
						nonces[v.Get("SignatureNonce")] = true
					}
					if cancelRequest {
						cancel()
					}
					if provider == "aliyun" {
						return response(400, `{"Code":"Throttling.User"}`)
					}
					return response(200, `{"Response":{"Error":{"Code":"RequestLimitExceeded.GlobalRegionUinLimitExceeded"}}}`)
				})
				rows, e := c.List(ctx, provider, chinaConfig(provider), chinaCredential(provider))
				assert.Nil(t, rows)
				if cancelRequest {
					assert.ErrorIs(t, e, context.Canceled)
					assert.Equal(t, 1, calls)
				} else {
					assert.ErrorIs(t, e, ErrUnavailable)
					assert.Equal(t, 3, calls)
				}
			})
		}
	}
}

func TestChinaEmptyInventoryAndFutureStatesRemainExplicit(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		for _, empty := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/empty=%v", provider, empty), func(t *testing.T) {
				c := jsonFixtureClient(t, provider, func(_ *http.Request, action string, v url.Values, _ map[string]any) *http.Response {
					if action == "GetCallerIdentity" {
						return response(200, encodedJSON(t, identityResponse(provider)))
					}
					if v.Get("DryRun") == "true" {
						return response(400, `{"Code":"DryRunOperation"}`)
					}
					items := []map[string]any{}
					if !empty {
						items = append(items, chinaInstance(provider, 1, "FUTURE_STATE"))
					}
					return response(200, encodedJSON(t, chinaPage(provider, items, len(items), "")))
				})
				rows, e := c.List(context.Background(), provider, chinaConfig(provider), chinaCredential(provider))
				require.NoError(t, e)
				if empty {
					assert.Empty(t, rows)
				} else {
					require.Len(t, rows, 1)
					assert.Equal(t, "unknown", rows[0].State)
					assert.Equal(t, "FUTURE_STATE", rows[0].ProviderState)
				}
			})
		}
	}
}

func TestChinaConfigBoundsAndTemporaryCredentialLimits(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		cfg, credentials := chinaConfig(provider), chinaCredential(provider)
		_, e := Validate(provider, cfg, credentials)
		require.NoError(t, e)
		for _, region := range []string{"cn-hangzhou.evil.invalid", "../metadata", "127.0.0.1", "ap-guangzhou/x", "ap-\r\ninjected"} {
			bad := cfg
			bad.Regions = []string{region}
			_, e = Validate(provider, bad, credentials)
			assert.ErrorIs(t, e, ErrConfig)
		}
		badKey := credentials
		badKey.AccessKeyID += "\r\n"
		_, e = Validate(provider, cfg, badKey)
		assert.ErrorIs(t, e, ErrConfig)
	}
	key := chinaCredential("tencentcloud")
	key.AccessKeyID = "AKID" + strings.Repeat("x", 1020)
	key.SecretAccessKey = strings.Repeat("s", 1024)
	key.SessionToken = strings.Repeat("t", 4096)
	_, e := Validate("tencentcloud", chinaConfig("tencentcloud"), key)
	require.NoError(t, e)
	key.SessionToken += "t"
	_, e = Validate("tencentcloud", chinaConfig("tencentcloud"), key)
	assert.ErrorIs(t, e, ErrConfig)
}

func TestChinaTransportBoundsRejectRedirectsAndOversizedBodies(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		for _, mode := range []string{"html503", "oversized", "redirect", "malformed"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				calls := 0
				c := jsonFixtureClient(t, provider, func(_ *http.Request, action string, v url.Values, _ map[string]any) *http.Response {
					if action == "GetCallerIdentity" {
						return response(200, encodedJSON(t, identityResponse(provider)))
					}
					if v.Get("DryRun") == "true" {
						return response(400, `{"Code":"DryRunOperation"}`)
					}
					calls++
					switch mode {
					case "html503":
						return response(503, "<html>temporary gateway failure</html>")
					case "oversized":
						return response(200, strings.Repeat("x", (8<<20)+1))
					case "redirect":
						r := response(302, `{}`)
						r.Header.Set("Location", "https://outside.invalid/credentials")
						return r
					default:
						return response(200, `{"RequestId":`)
					}
				})
				rows, e := c.List(context.Background(), provider, chinaConfig(provider), chinaCredential(provider))
				assert.ErrorIs(t, e, ErrUnavailable)
				assert.Nil(t, rows)
				if mode == "html503" {
					assert.Equal(t, 3, calls)
				} else {
					assert.Equal(t, 1, calls)
				}
			})
		}
	}
}

func TestChinaMetadataBoundStopsAccumulationBeforePublishing(t *testing.T) {
	for _, provider := range []string{"aliyun", "tencentcloud"} {
		t.Run(provider, func(t *testing.T) {
			page := 0
			c := jsonFixtureClient(t, provider, func(_ *http.Request, action string, v url.Values, _ map[string]any) *http.Response {
				if action == "GetCallerIdentity" {
					return response(200, encodedJSON(t, identityResponse(provider)))
				}
				if v.Get("DryRun") == "true" {
					return response(400, `{"Code":"DryRunOperation"}`)
				}
				items := []map[string]any{}
				for n := 0; n < 100; n++ {
					item := chinaInstance(provider, page*100+n, "Running")
					if provider == "aliyun" {
						item["Tags"] = map[string]any{"Tag": []any{map[string]any{"TagKey": "large", "TagValue": strings.Repeat("&", 2048)}}}
					} else {
						item["Tags"] = []any{map[string]any{"Key": "large", "Value": strings.Repeat("&", 2048)}}
					}
					items = append(items, item)
				}
				page++
				next := fmt.Sprint(page)
				if page == 4 {
					next = ""
				}
				return response(200, encodedJSON(t, chinaPage(provider, items, 400, next)))
			})
			rows, e := c.List(context.Background(), provider, chinaConfig(provider), chinaCredential(provider))
			assert.ErrorIs(t, e, ErrCapacity)
			assert.Nil(t, rows)
			assert.LessOrEqual(t, page, 4)
		})
	}
}

func TestTencentRejectsChangingCountsDuplicatePagesAndMissingFields(t *testing.T) {
	for _, mode := range []string{"identity", "arn", "count-changed", "duplicate", "empty-page", "missing-count", "missing-array", "wrong-zone", "bad-ip", "count-capacity", "permission"} {
		t.Run(mode, func(t *testing.T) {
			c := jsonFixtureClient(t, "tencentcloud", func(_ *http.Request, action string, _ url.Values, body map[string]any) *http.Response {
				if action == "GetCallerIdentity" {
					identity := identityResponse("tencentcloud")
					inner := identity["Response"].(map[string]any)
					if mode == "identity" {
						inner["AccountId"] = "9999999999"
					}
					if mode == "arn" {
						inner["Arn"] = "qcs::cam:uin/9999999999:root"
					}
					return response(200, encodedJSON(t, identity))
				}
				if mode == "permission" {
					return response(200, `{"Response":{"Error":{"Code":"UnauthorizedOperation"},"RequestId":"denied-qa"}}`)
				}
				offset := int(body["Offset"].(float64))
				item := chinaInstance("tencentcloud", offset+1, "RUNNING")
				total := 2
				switch mode {
				case "wrong-zone":
					item["Placement"] = map[string]any{"Zone": "ap-beijing-1"}
				case "bad-ip":
					item["IPv6Addresses"] = []string{"fe80::1%eth0"}
				case "count-capacity":
					total = MaxInstances + 1
				case "count-changed":
					if offset > 0 {
						total = 3
					}
				case "duplicate":
					item = chinaInstance("tencentcloud", 1, "RUNNING")
				case "empty-page":
					return response(200, encodedJSON(t, chinaPage("tencentcloud", []map[string]any{}, 2, "")))
				case "missing-count":
					return response(200, `{"Response":{"RequestId":"qa","InstanceSet":[]}}`)
				case "missing-array":
					return response(200, `{"Response":{"RequestId":"qa","TotalCount":0}}`)
				}
				return response(200, encodedJSON(t, chinaPage("tencentcloud", []map[string]any{item}, total, "")))
			})
			rows, e := c.List(context.Background(), "tencentcloud", chinaConfig("tencentcloud"), chinaCredential("tencentcloud"))
			assert.Error(t, e)
			assert.Nil(t, rows)
			if mode == "permission" {
				assert.ErrorIs(t, e, ErrPermission)
			}
			if mode == "count-capacity" {
				assert.ErrorIs(t, e, ErrCapacity)
			}
		})
	}
}

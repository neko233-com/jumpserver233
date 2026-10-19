package cloudinventory

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // Alibaba Cloud RPC's documented SignatureVersion=1.0.
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var aliyunInstancePattern = regexp.MustCompile(`^i-[A-Za-z0-9]{3,64}$`)

func rpcEscape(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }
func aliyunSignature(method string, values url.Values, secret string) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "Signature" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, rpcEscape(key)+"="+rpcEscape(values.Get(key)))
	}
	canonical := strings.Join(parts, "&")
	signer := hmac.New(sha1.New, []byte(secret+"&"))
	_, _ = signer.Write([]byte(method + "&%2F&" + rpcEscape(canonical)))
	return base64.StdEncoding.EncodeToString(signer.Sum(nil))
}

func (c *Client) aliyunRequest(ctx context.Context, region, service, action, version string, credential Credential, parameters url.Values, dryRun bool, out any) error {
	endpoint := "https://sts.aliyuncs.com/"
	if service == "ecs" {
		endpoint = "https://ecs." + region + ".aliyuncs.com/"
	}
	data, status, code, e := c.jsonRequest(ctx, "aliyun", func() (*http.Request, error) {
		values := url.Values{}
		for key, value := range parameters {
			values[key] = slices.Clone(value)
		}
		nonce := make([]byte, 16)
		if _, e := rand.Read(nonce); e != nil {
			return nil, e
		}
		values.Set("Action", action)
		values.Set("Version", version)
		values.Set("Format", "JSON")
		values.Set("AccessKeyId", credential.AccessKeyID)
		values.Set("SignatureMethod", "HMAC-SHA1")
		values.Set("SignatureVersion", "1.0")
		values.Set("SignatureNonce", hex.EncodeToString(nonce))
		values.Set("Timestamp", c.now().UTC().Format("2006-01-02T15:04:05Z"))
		if credential.SessionToken != "" {
			values.Set("SecurityToken", credential.SessionToken)
		}
		values.Set("Signature", aliyunSignature(http.MethodPost, values, credential.SecretAccessKey))
		request, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
		if e == nil {
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
		}
		return request, e
	})
	if e != nil {
		return e
	}
	if dryRun {
		if code == "DryRunOperation" && status == http.StatusBadRequest {
			return nil
		}
		return providerError(status, code)
	}
	if status != http.StatusOK || code != "" {
		return providerError(status, code)
	}
	if json.Unmarshal(data, out) != nil {
		return ErrUnavailable
	}
	return nil
}

type aliyunInstance struct {
	ID     string      `json:"InstanceId"`
	Name   string      `json:"InstanceName"`
	Region string      `json:"RegionId"`
	Zone   string      `json:"ZoneId"`
	State  string      `json:"Status"`
	Owner  json.Number `json:"InstanceOwnerId"`
	Inner  struct {
		IPs []string `json:"IpAddress"`
	} `json:"InnerIpAddress"`
	Public struct {
		IPs []string `json:"IpAddress"`
	} `json:"PublicIpAddress"`
	EIP struct {
		IP string `json:"IpAddress"`
	} `json:"EipAddress"`
	VPC struct {
		Private struct {
			IPs []string `json:"IpAddress"`
		} `json:"PrivateIpAddress"`
	} `json:"VpcAttributes"`
	Interfaces struct {
		Items []struct {
			IPv6 struct {
				Items []struct {
					IP string `json:"Ipv6Address"`
				} `json:"Ipv6Set"`
			} `json:"Ipv6Sets"`
		} `json:"NetworkInterface"`
	} `json:"NetworkInterfaces"`
	Tags struct {
		Items []struct {
			Key   string `json:"TagKey"`
			Value string `json:"TagValue"`
		} `json:"Tag"`
	} `json:"Tags"`
}

func (i aliyunInstance) normalized(account, region string) (Instance, error) {
	if !aliyunInstancePattern.MatchString(i.ID) || i.Region != region || i.Owner != "" && i.Owner.String() != account {
		return Instance{}, ErrIdentity
	}
	if i.State == "" || !safeCloudText(i.State, 64) || !safeCloudText(i.Name, 1024) || !safeCloudText(i.Zone, 128) {
		return Instance{}, ErrUnavailable
	}
	value := Instance{Provider: "aliyun", AccountID: account, Region: region, ID: i.ID, Name: i.Name, ProviderState: i.State, State: powerState(i.State), Zone: i.Zone}
	if value.Name == "" {
		value.Name = i.ID
	}
	var e error
	value.PrivateIP, e = cloudIP(append(slices.Clone(i.VPC.Private.IPs), i.Inner.IPs...), false)
	if e != nil {
		return Instance{}, e
	}
	value.PublicIP, e = cloudIP(append([]string{i.EIP.IP}, i.Public.IPs...), false)
	if e != nil {
		return Instance{}, e
	}
	ipv6 := []string{}
	for _, nic := range i.Interfaces.Items {
		for _, ip := range nic.IPv6.Items {
			ipv6 = append(ipv6, ip.IP)
		}
	}
	value.IPv6, e = cloudIP(ipv6, true)
	if e != nil {
		return Instance{}, e
	}
	tags := make([]struct{ Key, Value string }, len(i.Tags.Items))
	for n, tag := range i.Tags.Items {
		tags[n] = struct{ Key, Value string }{tag.Key, tag.Value}
	}
	value.Tags, e = cloudTags(tags)
	if e != nil {
		return Instance{}, e
	}
	return value, nil
}

func (c *Client) listAliyun(ctx context.Context, config Config, credential Credential) ([]Instance, error) {
	var identity struct {
		Account   string `json:"AccountId"`
		ARN       string `json:"Arn"`
		RequestID string `json:"RequestId"`
	}
	if e := c.aliyunRequest(ctx, "", "sts", "GetCallerIdentity", "2015-04-01", credential, nil, false, &identity); e != nil {
		return nil, e
	}
	if identity.RequestID == "" || identity.Account != config.AccountID || !strings.HasPrefix(identity.ARN, "acs:ram::"+config.AccountID+":") {
		return nil, ErrIdentity
	}
	out := []Instance{}
	budget := inventoryBudget{}
	for _, region := range config.Regions {
		preflight := func() error {
			return c.aliyunRequest(ctx, region, "ecs", "DescribeInstances", "2014-05-26", credential, url.Values{"RegionId": {region}, "MaxResults": {"100"}, "DryRun": {"true"}}, true, nil)
		}
		// Some unauthorized RAM calls return an empty list. Explicit pre/post
		// permission checks prevent treating that response as an empty inventory.
		if e := preflight(); e != nil {
			return nil, e
		}
		token := ""
		tokens := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 500 {
				return nil, ErrCapacity
			}
			parameters := url.Values{"RegionId": {region}, "MaxResults": {"100"}}
			if token != "" {
				parameters.Set("NextToken", token)
			}
			var response struct {
				RequestID string `json:"RequestId"`
				Next      string `json:"NextToken"`
				Instances *struct {
					Items *[]aliyunInstance `json:"Instance"`
				} `json:"Instances"`
			}
			if e := c.aliyunRequest(ctx, region, "ecs", "DescribeInstances", "2014-05-26", credential, parameters, false, &response); e != nil {
				return nil, e
			}
			if response.RequestID == "" || len(response.Next) > 16384 || response.Instances == nil || response.Instances.Items == nil || len(*response.Instances.Items) > 100 {
				return nil, ErrUnavailable
			}
			for _, item := range *response.Instances.Items {
				value, e := item.normalized(config.AccountID, region)
				if e != nil {
					return nil, e
				}
				if e = budget.add(value); e != nil {
					return nil, e
				}
				out = append(out, value)
			}
			if response.Next == "" {
				break
			}
			if tokens[response.Next] {
				return nil, ErrUnavailable
			}
			tokens[response.Next] = true
			token = response.Next
		}
		if e := preflight(); e != nil {
			return nil, e
		}
	}
	return out, nil
}

package cloudinventory

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var tencentInstancePattern = regexp.MustCompile(`^ins-[A-Za-z0-9]{3,64}$`)

func signTencent(request *http.Request, body, service, region, action, version string, credential Credential, now time.Time) {
	stamp := strconv.FormatInt(now.Unix(), 10)
	day := now.UTC().Format("2006-01-02")
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("X-TC-Action", action)
	request.Header.Set("X-TC-Version", version)
	request.Header.Set("X-TC-Timestamp", stamp)
	if region != "" {
		request.Header.Set("X-TC-Region", region)
	}
	if credential.SessionToken != "" {
		request.Header.Set("X-TC-Token", credential.SessionToken)
	}
	headers := "content-type:" + request.Header.Get("Content-Type") + "\nhost:" + request.URL.Host + "\n"
	signed := "content-type;host"
	canonical := "POST\n/\n\n" + headers + "\n" + signed + "\n" + hash(body)
	scope := day + "/" + service + "/tc3_request"
	key := hmac256([]byte("TC3"+credential.SecretAccessKey), day)
	key = hmac256(key, service)
	key = hmac256(key, "tc3_request")
	signature := hex.EncodeToString(hmac256(key, "TC3-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+hash(canonical)))
	request.Header.Set("Authorization", "TC3-HMAC-SHA256 Credential="+credential.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
}

func (c *Client) tencentRequest(ctx context.Context, service, region, action, version string, credential Credential, input, out any) error {
	body, e := json.Marshal(input)
	if e != nil {
		return ErrConfig
	}
	data, status, code, e := c.jsonRequest(ctx, "tencentcloud", func() (*http.Request, error) {
		request, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+service+".tencentcloudapi.com/", strings.NewReader(string(body)))
		if e == nil {
			signTencent(request, string(body), service, region, action, version, credential, c.now())
		}
		return request, e
	})
	if e != nil {
		return e
	}
	if status != http.StatusOK || code != "" {
		return providerError(status, code)
	}
	var envelope struct{ Response json.RawMessage }
	if json.Unmarshal(data, &envelope) != nil || json.Unmarshal(envelope.Response, out) != nil {
		return ErrUnavailable
	}
	return nil
}

type tencentInstance struct {
	ID        string `json:"InstanceId"`
	Name      string `json:"InstanceName"`
	State     string `json:"InstanceState"`
	Placement struct{ Zone string }
	Private   []string `json:"PrivateIpAddresses"`
	Public    []string `json:"PublicIpAddresses"`
	IPv6      []string `json:"IPv6Addresses"`
	Tags      []struct{ Key, Value string }
}

func (i tencentInstance) normalized(account, region string) (Instance, error) {
	if !tencentInstancePattern.MatchString(i.ID) || i.Placement.Zone != "" && !strings.HasPrefix(i.Placement.Zone, region+"-") {
		return Instance{}, ErrIdentity
	}
	if i.State == "" || !safeCloudText(i.State, 64) || !safeCloudText(i.Name, 1024) || !safeCloudText(i.Placement.Zone, 128) {
		return Instance{}, ErrUnavailable
	}
	value := Instance{Provider: "tencentcloud", AccountID: account, Region: region, ID: i.ID, Name: i.Name, ProviderState: i.State, State: powerState(i.State), Zone: i.Placement.Zone}
	if value.Name == "" {
		value.Name = i.ID
	}
	var e error
	value.PrivateIP, e = cloudIP(i.Private, false)
	if e != nil {
		return Instance{}, e
	}
	value.PublicIP, e = cloudIP(i.Public, false)
	if e != nil {
		return Instance{}, e
	}
	value.IPv6, e = cloudIP(i.IPv6, true)
	if e != nil {
		return Instance{}, e
	}
	value.Tags, e = cloudTags(i.Tags)
	if e != nil {
		return Instance{}, e
	}
	return value, nil
}

func (c *Client) listTencent(ctx context.Context, config Config, credential Credential) ([]Instance, error) {
	var identity struct {
		AccountID string `json:"AccountId"`
		ARN       string `json:"Arn"`
		RequestID string `json:"RequestId"`
	}
	if e := c.tencentRequest(ctx, "sts", "", "GetCallerIdentity", "2018-08-13", credential, struct{}{}, &identity); e != nil {
		return nil, e
	}
	if identity.RequestID == "" || identity.AccountID != config.AccountID || !strings.HasPrefix(identity.ARN, "qcs:") || !strings.Contains(identity.ARN, ":uin/"+config.AccountID+":") {
		return nil, ErrIdentity
	}
	out := []Instance{}
	budget := inventoryBudget{}
	for _, region := range config.Regions {
		total := -1
		offset := 0
		for page := 0; ; page++ {
			if page >= 500 {
				return nil, ErrCapacity
			}
			var response struct {
				RequestID string             `json:"RequestId"`
				Total     *int               `json:"TotalCount"`
				Instances *[]tencentInstance `json:"InstanceSet"`
			}
			if e := c.tencentRequest(ctx, "cvm", region, "DescribeInstances", "2017-03-12", credential, struct{ Limit, Offset int }{100, offset}, &response); e != nil {
				return nil, e
			}
			if response.RequestID == "" || response.Total == nil || *response.Total < 0 || response.Instances == nil || len(*response.Instances) > 100 {
				return nil, ErrUnavailable
			}
			if *response.Total > MaxInstances {
				return nil, ErrCapacity
			}
			if total < 0 {
				total = *response.Total
			} else if total != *response.Total {
				return nil, ErrUnavailable
			}
			items := *response.Instances
			if offset+len(items) > total || len(items) == 0 && offset < total {
				return nil, ErrUnavailable
			}
			for _, item := range items {
				value, e := item.normalized(config.AccountID, region)
				if e != nil {
					return nil, e
				}
				if e = budget.add(value); e != nil {
					return nil, e
				}
				out = append(out, value)
			}
			offset += len(items)
			if offset == total {
				break
			}
		}
	}
	return out, nil
}

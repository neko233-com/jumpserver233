package cloudinventory

import (
	"context"
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

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(code int, body string) *http.Response {
	return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}
func config() Config {
	return Config{AccountID: "123456789012", Regions: []string{"us-east-1"}, AddressMode: "private"}
}
func credential() Credential {
	return Credential{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "synthetic-cloud-secret-access-key", SessionToken: "synthetic-cloud-session-token"}
}

const identityXML = `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/qa</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>`

func instanceXML(id, state string) string {
	return `<item><instanceId>` + id + `</instanceId><instanceState><name>` + state + `</name></instanceState><privateIpAddress>10.0.0.7</privateIpAddress><ipAddress>192.0.2.7</ipAddress><placement><availabilityZone>us-east-1a</availabilityZone></placement><tagSet><item><key>Name</key><value>qa-node</value></item></tagSet><networkInterfaceSet><item><ipv6AddressesSet><item><ipv6Address>2001:db8::7</ipv6Address></item></ipv6AddressesSet></item></networkInterfaceSet></item>`
}
func inventoryXML(items, token string) string {
	return `<DescribeInstancesResponse><requestId>qa-request</requestId><reservationSet><item><ownerId>123456789012</ownerId><instancesSet>` + items + `</instancesSet></item></reservationSet><nextToken>` + token + `</nextToken></DescribeInstancesResponse>`
}
func testClient(t *testing.T, f func(*http.Request, url.Values) *http.Response) *Client {
	t.Helper()
	c := NewClient()
	c.now = func() time.Time { return time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC) }
	c.http.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, "https", r.URL.Scheme)
		assert.Equal(t, "POST", r.Method)
		assert.Empty(t, r.URL.RawQuery)
		body, e := io.ReadAll(r.Body)
		require.NoError(t, e)
		v, e := url.ParseQuery(string(body))
		require.NoError(t, e)
		assert.Contains(t, r.Header.Get("Authorization"), "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token")
		assert.Equal(t, credential().SessionToken, r.Header.Get("X-Amz-Security-Token"))
		return f(r, v), nil
	})
	t.Cleanup(c.Close)
	return c
}

func TestSignatureMatchesPublishedAWSVector(t *testing.T) {
	// AWS's published IAM ListUsers vector; credentials are public examples.
	// https://aws.amazon.com/ko/blogs/korea/aws-api-call-1/
	r, e := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	require.NoError(t, e)
	sign(r, "", "iam", "us-east-1", Credential{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	assert.Equal(t, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7", r.Header.Get("Authorization"))
}

func TestAWSInventoryPartitionsPaginationAndMetadata(t *testing.T) {
	for _, provider := range []string{"aws", "aws_cn"} {
		t.Run(provider, func(t *testing.T) {
			cfg := config()
			suffix := "amazonaws.com"
			region := "us-east-1"
			if provider == "aws_cn" {
				suffix += ".cn"
				region = "cn-north-1"
				cfg.Regions = []string{region}
			}
			calls := 0
			c := testClient(t, func(r *http.Request, v url.Values) *http.Response {
				calls++
				if v.Get("Action") == "GetCallerIdentity" {
					assert.Equal(t, "sts."+region+"."+suffix, r.URL.Host)
					body := identityXML
					if provider == "aws_cn" {
						body = strings.ReplaceAll(body, "arn:aws:", "arn:aws-cn:")
					}
					return response(200, body)
				}
				assert.Equal(t, "ec2."+region+"."+suffix, r.URL.Host)
				assert.Equal(t, "DescribeInstances", v.Get("Action"))
				assert.Equal(t, "1000", v.Get("MaxResults"))
				if v.Get("NextToken") == "" {
					return response(200, inventoryXML(instanceXML("i-0123456789abcdef0", "running"), "page+2/=value"))
				}
				assert.Equal(t, "page+2/=value", v.Get("NextToken"))
				return response(200, inventoryXML(instanceXML("i-0123456789abcdef1", "stopped")+instanceXML("i-0123456789abcdef2", "terminated"), ""))
			})
			rows, e := c.List(context.Background(), provider, cfg, credential())
			require.NoError(t, e)
			require.Len(t, rows, 2)
			assert.Equal(t, 3, calls)
			assert.Equal(t, "qa-node", rows[0].Name)
			assert.Equal(t, "10.0.0.7", rows[0].Address("private"))
			assert.Equal(t, "192.0.2.7", rows[0].Address("public"))
			assert.Equal(t, "2001:db8::7", rows[0].Address("ipv6"))
			assert.Equal(t, provider+":123456789012:"+region+":i-0123456789abcdef0", rows[0].ResourceKey())
		})
	}
}

func TestAWSInventoryRejectsPartialMalformedAndWrongAccount(t *testing.T) {
	for _, mode := range []string{"identity", "owner", "wrong-root", "empty-response", "bad-ip", "bad-state", "duplicate", "token-cycle", "second-region", "redirect", "oversized"} {
		t.Run(mode, func(t *testing.T) {
			cfg := config()
			if mode == "second-region" {
				cfg.Regions = append(cfg.Regions, "us-west-2")
			}
			c := testClient(t, func(r *http.Request, v url.Values) *http.Response {
				if v.Get("Action") == "GetCallerIdentity" {
					body := identityXML
					if mode == "identity" {
						body = strings.ReplaceAll(body, "123456789012", "999999999999")
					}
					return response(200, body)
				}
				if mode == "second-region" && strings.Contains(r.URL.Host, "us-west-2") {
					return response(403, "denied")
				}
				body := inventoryXML(instanceXML("i-0123456789abcdef0", "running"), "")
				switch mode {
				case "owner":
					body = strings.ReplaceAll(body, "123456789012", "999999999999")
				case "wrong-root":
					body = `<ErrorResponse><Message>not inventory</Message></ErrorResponse>`
				case "empty-response":
					body = `<DescribeInstancesResponse/>`
				case "bad-ip":
					body = strings.ReplaceAll(body, "10.0.0.7", "127.0.0.1")
				case "bad-state":
					body = strings.ReplaceAll(body, "running", "unknown")
				case "duplicate":
					body = inventoryXML(instanceXML("i-0123456789abcdef0", "running")+instanceXML("i-0123456789abcdef0", "running"), "")
				case "token-cycle":
					body = inventoryXML("", "repeat")
				case "redirect":
					return response(302, "")
				case "oversized":
					body = strings.Repeat("x", (8<<20)+1)
				}
				return response(200, body)
			})
			rows, e := c.List(context.Background(), "aws", cfg, credential())
			assert.Error(t, e)
			assert.Nil(t, rows)
			assert.NotContains(t, fmt.Sprint(e), credential().SecretAccessKey)
		})
	}
}

func TestAWSConfigurationAndThrottlingBounds(t *testing.T) {
	for _, region := range []string{"evil.example/", "us-east-1.evil.example", "cn-north-1", "us-gov-west-1", "us-\r\n-east-1"} {
		cfg := config()
		cfg.Regions = []string{region}
		_, e := Validate("aws", cfg, credential())
		assert.ErrorIs(t, e, ErrConfig, region)
	}
	calls := 0
	c := testClient(t, func(_ *http.Request, v url.Values) *http.Response {
		if v.Get("Action") == "GetCallerIdentity" {
			return response(200, identityXML)
		}
		calls++
		if calls < 3 {
			return response(400, `<Response><Errors><Error><Code>RequestLimitExceeded</Code></Error></Errors></Response>`)
		}
		return response(200, inventoryXML("", ""))
	})
	rows, e := c.List(context.Background(), "aws", config(), credential())
	require.NoError(t, e)
	assert.Empty(t, rows)
	assert.Equal(t, 3, calls)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.http.Transport = roundTrip(func(r *http.Request) (*http.Response, error) { return nil, r.Context().Err() })
	_, e = c.List(ctx, "aws", config(), credential())
	assert.ErrorIs(t, e, context.Canceled)
}

func TestAWSInventoryBoundsNormalizedMetadataBeforePublishing(t *testing.T) {
	var items strings.Builder
	for n := 0; n < 400; n++ {
		items.WriteString(strings.ReplaceAll(instanceXML(fmt.Sprintf("i-%017x", n), "running"), "qa-node", strings.Repeat("&amp;", 1024)))
	}
	c := testClient(t, func(_ *http.Request, values url.Values) *http.Response {
		if values.Get("Action") == "GetCallerIdentity" {
			return response(200, identityXML)
		}
		return response(200, inventoryXML(items.String(), ""))
	})
	rows, e := c.List(context.Background(), "aws", config(), credential())
	assert.ErrorIs(t, e, ErrCapacity)
	assert.Nil(t, rows)
}

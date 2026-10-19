// Package cloudinventory implements bounded, read-only cloud inventory clients.
// Cloud credentials never leave the provider's canonical HTTPS endpoints.
package cloudinventory

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	ErrConfig       = errors.New("invalid cloud inventory configuration")
	ErrUnavailable  = errors.New("cloud inventory unavailable")
	ErrIdentity     = errors.New("cloud inventory account mismatch")
	ErrCapacity     = errors.New("cloud inventory capacity reached")
	accountPattern  = regexp.MustCompile(`^[0-9]{12}$`)
	keyPattern      = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
	regionPattern   = regexp.MustCompile(`^(af|ap|ca|eu|il|me|mx|sa|us)-(central|north|northeast|northwest|south|southeast|southwest|east|west)-[1-9][0-9]?$`)
	instancePattern = regexp.MustCompile(`^i-([0-9a-f]{8}|[0-9a-f]{17})$`)
)

const MaxInstances = 8192
const MaxMetadataBytes = 4 << 20

type Config struct {
	AccountID   string   `json:"account_id"`
	Regions     []string `json:"regions"`
	AddressMode string   `json:"address_mode"`
}

// Credential is write-only at the API boundary and encrypted by its owner.
type Credential struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

type Instance struct {
	Provider  string            `json:"provider"`
	AccountID string            `json:"account_id"`
	Region    string            `json:"region"`
	ID        string            `json:"instance_id"`
	Name      string            `json:"name"`
	State     string            `json:"state"`
	Zone      string            `json:"zone,omitempty"`
	PrivateIP string            `json:"private_ip,omitempty"`
	PublicIP  string            `json:"public_ip,omitempty"`
	IPv6      string            `json:"ipv6,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Missing   bool              `json:"missing,omitempty"`
}

func (i Instance) Address(mode string) string {
	if mode == "public" {
		return i.PublicIP
	}
	if mode == "ipv6" {
		return i.IPv6
	}
	return i.PrivateIP
}

func (i Instance) EncodedSize() int { data, _ := json.Marshal(i); return len(data) }

func Validate(provider string, in Config, credential Credential) (Config, error) {
	if provider != "aws" && provider != "aws_cn" || !accountPattern.MatchString(in.AccountID) || len(in.Regions) < 1 || len(in.Regions) > 32 {
		return in, ErrConfig
	}
	in.Regions = slices.Clone(in.Regions)
	for n, region := range in.Regions {
		region = strings.TrimSpace(region)
		if provider == "aws_cn" {
			if region != "cn-north-1" && region != "cn-northwest-1" {
				return in, ErrConfig
			}
		} else if !regionPattern.MatchString(region) {
			return in, ErrConfig
		}
		in.Regions[n] = region
	}
	slices.Sort(in.Regions)
	in.Regions = slices.Compact(in.Regions)
	if in.AddressMode == "" {
		in.AddressMode = "private"
	}
	if in.AddressMode != "private" && in.AddressMode != "public" && in.AddressMode != "ipv6" {
		return in, ErrConfig
	}
	if !keyPattern.MatchString(credential.AccessKeyID) || len(credential.SecretAccessKey) < 16 || len(credential.SecretAccessKey) > 256 || len(credential.SessionToken) > 16384 {
		return in, ErrConfig
	}
	for _, value := range []string{credential.SecretAccessKey, credential.SessionToken} {
		for _, c := range value {
			if c < 33 || c > 126 {
				return in, ErrConfig
			}
		}
	}
	return in, nil
}

type Client struct {
	http *http.Client
	now  func() time.Time
}

func NewClient() *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxConnsPerHost = 4
	transport.MaxIdleConnsPerHost = 2
	transport.ResponseHeaderTimeout = 15 * time.Second
	return &Client{http: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, now: time.Now}
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

func hmac256(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}
func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// sign implements AWS Signature Version 4 for the POST Query APIs used here.
func sign(request *http.Request, body, service, region string, credential Credential, now time.Time) {
	stamp := now.UTC().Format("20060102T150405Z")
	day := stamp[:8]
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	request.Header.Set("X-Amz-Date", stamp)
	headers := "content-type:" + request.Header.Get("Content-Type") + "\nhost:" + request.URL.Host + "\nx-amz-date:" + stamp + "\n"
	signed := "content-type;host;x-amz-date"
	if credential.SessionToken != "" {
		request.Header.Set("X-Amz-Security-Token", credential.SessionToken)
		headers += "x-amz-security-token:" + credential.SessionToken + "\n"
		signed += ";x-amz-security-token"
	}
	canonical := request.Method + "\n" + request.URL.EscapedPath() + "\n" + request.URL.RawQuery + "\n" + headers + "\n" + signed + "\n" + hash(body)
	scope := day + "/" + region + "/" + service + "/aws4_request"
	key := hmac256([]byte("AWS4"+credential.SecretAccessKey), day)
	key = hmac256(key, region)
	key = hmac256(key, service)
	key = hmac256(key, "aws4_request")
	signature := hex.EncodeToString(hmac256(key, "AWS4-HMAC-SHA256\n"+stamp+"\n"+scope+"\n"+hash(canonical)))
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+credential.AccessKeyID+"/"+scope+", SignedHeaders="+signed+", Signature="+signature)
}

func (c *Client) query(ctx context.Context, provider, region, service string, credential Credential, values url.Values, out any) error {
	suffix := "amazonaws.com"
	if provider == "aws_cn" {
		suffix += ".cn"
	}
	endpoint := "https://" + service + "." + region + "." + suffix + "/"
	body := values.Encode()
	for attempt := 0; attempt < 3; attempt++ {
		request, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
		if e != nil {
			return ErrUnavailable
		}
		sign(request, body, service, region, credential, c.now())
		response, e := c.http.Do(request)
		if e != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrUnavailable
		}
		data, readError := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
		_ = response.Body.Close()
		if readError != nil || len(data) > 8<<20 {
			return ErrUnavailable
		}
		var failure struct {
			Code string `xml:"Errors>Error>Code"`
		}
		if response.StatusCode != http.StatusOK {
			_ = xml.Unmarshal(data, &failure)
		}
		retry := failure.Code == "RequestLimitExceeded" || failure.Code == "Throttling" || failure.Code == "ThrottlingException" || failure.Code == "ServiceUnavailable"
		if retry || response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
			if attempt == 2 {
				return ErrUnavailable
			}
			timer := time.NewTimer(time.Duration(attempt+1) * 200 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if response.StatusCode != http.StatusOK {
			return ErrUnavailable
		}
		if xml.Unmarshal(data, out) != nil {
			return ErrUnavailable
		}
		return nil
	}
	return ErrUnavailable
}

type ec2Instance struct {
	ID         string `xml:"instanceId"`
	Name       string
	State      string `xml:"instanceState>name"`
	Zone       string `xml:"placement>availabilityZone"`
	PrivateIP  string `xml:"privateIpAddress"`
	PublicIP   string `xml:"ipAddress"`
	Interfaces []struct {
		IPv6 []struct {
			IP string `xml:"ipv6Address"`
		} `xml:"ipv6AddressesSet>item"`
	} `xml:"networkInterfaceSet>item"`
	Tags []struct {
		Key   string `xml:"key"`
		Value string `xml:"value"`
	} `xml:"tagSet>item"`
}

// List checks STS identity before enumerating every selected region and page.
// It returns no inventory on partial failure: callers must not release assets.
func (c *Client) List(ctx context.Context, provider string, config Config, credential Credential) ([]Instance, error) {
	config, e := Validate(provider, config, credential)
	if e != nil {
		return nil, e
	}
	var identity struct {
		XMLName xml.Name `xml:"GetCallerIdentityResponse"`
		Account string   `xml:"GetCallerIdentityResult>Account"`
		ARN     string   `xml:"GetCallerIdentityResult>Arn"`
	}
	if e = c.query(ctx, provider, config.Regions[0], "sts", credential, url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}, &identity); e != nil {
		return nil, e
	}
	partition := "aws"
	if provider == "aws_cn" {
		partition = "aws-cn"
	}
	arn := strings.SplitN(identity.ARN, ":", 6)
	if identity.Account != config.AccountID || len(arn) != 6 || arn[0] != "arn" || arn[1] != partition || arn[4] != config.AccountID || arn[5] == "" {
		return nil, ErrIdentity
	}
	out := []Instance{}
	metadataBytes := 0
	seen := map[string]bool{}
	for _, region := range config.Regions {
		token := ""
		tokens := map[string]bool{}
		for page := 0; ; page++ {
			if page >= 500 {
				return nil, ErrCapacity
			}
			values := url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "MaxResults": {"1000"}}
			if token != "" {
				values.Set("NextToken", token)
			}
			var response struct {
				XMLName      xml.Name `xml:"DescribeInstancesResponse"`
				RequestID    string   `xml:"requestId"`
				Next         string   `xml:"nextToken"`
				Reservations []struct {
					Owner     string        `xml:"ownerId"`
					Instances []ec2Instance `xml:"instancesSet>item"`
				} `xml:"reservationSet>item"`
			}
			if e = c.query(ctx, provider, region, "ec2", credential, values, &response); e != nil {
				return nil, e
			}
			if response.RequestID == "" || len(response.Next) > 16384 {
				return nil, ErrUnavailable
			}
			for _, reservation := range response.Reservations {
				if reservation.Owner != config.AccountID {
					return nil, ErrIdentity
				}
				for _, item := range reservation.Instances {
					key := region + ":" + item.ID
					if !instancePattern.MatchString(item.ID) || seen[key] {
						return nil, ErrUnavailable
					}
					seen[key] = true
					if len(seen) > MaxInstances {
						return nil, ErrCapacity
					}
					switch item.State {
					case "terminated", "shutting-down":
						continue
					case "pending", "running", "stopping", "stopped":
					default:
						return nil, ErrUnavailable
					}
					v := Instance{Provider: provider, AccountID: config.AccountID, Region: region, ID: item.ID, Name: item.ID, State: item.State, Zone: item.Zone, Tags: map[string]string{}}
					if len(item.Zone) > 128 || len(item.Tags) > 50 {
						return nil, ErrUnavailable
					}
					for _, tag := range item.Tags {
						if len(tag.Key) > 256 || len(tag.Value) > 1024 || strings.ContainsAny(tag.Key+tag.Value, "\x00\r\n") {
							return nil, ErrUnavailable
						}
						v.Tags[tag.Key] = tag.Value
						if tag.Key == "Name" && tag.Value != "" {
							v.Name = tag.Value
						}
					}
					ips := []*string{&v.PrivateIP, &v.PublicIP}
					for n, raw := range []string{item.PrivateIP, item.PublicIP} {
						if raw == "" {
							continue
						}
						ip, e := netip.ParseAddr(raw)
						if e != nil || !ip.Is4() || !ip.IsGlobalUnicast() {
							return nil, ErrUnavailable
						}
						*ips[n] = ip.String()
					}
					for _, nic := range item.Interfaces {
						for _, raw := range nic.IPv6 {
							ip, e := netip.ParseAddr(raw.IP)
							if e != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() {
								return nil, ErrUnavailable
							}
							if v.IPv6 == "" || ip.Compare(netip.MustParseAddr(v.IPv6)) < 0 {
								v.IPv6 = ip.String()
							}
						}
					}
					metadataBytes += v.EncodedSize()
					if metadataBytes > MaxMetadataBytes {
						return nil, ErrCapacity
					}
					out = append(out, v)
					if len(out) > MaxInstances {
						return nil, ErrCapacity
					}
				}
			}
			if response.Next == "" {
				break
			}
			if tokens[response.Next] {
				return nil, ErrUnavailable
			}
			token = response.Next
			tokens[token] = true
		}
	}
	slices.SortFunc(out, func(a, b Instance) int { return strings.Compare(a.Region+":"+a.ID, b.Region+":"+b.ID) })
	return out, nil
}

func (i Instance) ResourceKey() string {
	return fmt.Sprintf("%s:%s:%s:%s", i.Provider, i.AccountID, i.Region, i.ID)
}
func (i Instance) DisplayName(port int) string {
	name := i.Name
	if len(name) > 80 {
		name = i.ID
	}
	return name + "-" + strconv.Itoa(port)
}

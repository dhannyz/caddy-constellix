package constellix

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xenolf/lego/acme"
)

// DNSProvider is an implementation of the acme.ChallengeProvider interface that uses
// DNSMadeEasy's DNS API to manage TXT records for a domain.
type DNSProvider struct {
	baseURL   string
	apiKey    string
	apiSecret string
}

// Domain holds the DNSMadeEasy API representation of a Domain
type Domain struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Record holds the DNSMadeEasy API representation of a Domain Record
type Record struct {
	ID         int          `json:"id,omitempty"`
	Type       string       `json:"type,omitempty"`
	Name       string       `json:"name,omitempty"`
	RoundRobin []RoundRobin `json:"roundRobin,omitempty"`
	GTDRegion  int          `json:"gtdRegion"`
	Value      string       `json:"value"`
	TTL        string       `json:"ttl"`
	Source     string       `json:"source,omitempty"`
}
type RoundRobin struct {
	Value string `json:"value"`
}

// NewDNSProvider returns a DNSProvider instance configured for DNSMadeEasy DNS.
// Credentials must be passed in the environment variables: DNSMADEEASY_API_KEY
// and DNSMADEEASY_API_SECRET.
func NewDNSProvider() (*DNSProvider, error) {
	constellixAPIKey := os.Getenv("CONSTELLIX_API_KEY")
	constellixAPISecret := os.Getenv("CONSTELLIX_API_SECRET")

	baseURL := "https://api.dns.constellix.com/v1/"

	return NewDNSProviderCredentials(baseURL, constellixAPIKey, constellixAPISecret)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// DNSProvider instance configured for DNSMadeEasy.
func NewDNSProviderCredentials(baseURL, apiKey, apiSecret string) (*DNSProvider, error) {
	if baseURL == "" || apiKey == "" || apiSecret == "" {
		return nil, fmt.Errorf("Constellix credentials missing")
	}

	return &DNSProvider{
		baseURL:   baseURL,
		apiKey:    apiKey,
		apiSecret: apiSecret,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (d *DNSProvider) Present(domainName, token, keyAuth string) error {
	fqdn, value, ttl := acme.DNS01Record(domainName, keyAuth)

	authZone, err := acme.FindZoneByFqdn(fqdn, acme.RecursiveNameservers)

	if err != nil {
		return err
	}

	// fetch the domain details
	domain, err := d.getDomain(authZone)
	if err != nil {
		return err
	}

	// create the TXT record
	name := strings.Replace(fqdn, "."+authZone, "", 1)
	record := &Record{
		Name: name,
		TTL:  fmt.Sprintf("%d", ttl),
		RoundRobin: []RoundRobin{
			RoundRobin{
				Value: value,
			},
		},
	}

	err = d.createRecord(domain, record)
	if err != nil {
		return err
	}

	return nil
}

// CleanUp removes the TXT records matching the specified parameters
func (d *DNSProvider) CleanUp(domainName, token, keyAuth string) error {
	fqdn, _, _ := acme.DNS01Record(domainName, keyAuth)

	authZone, err := acme.FindZoneByFqdn(fqdn, acme.RecursiveNameservers)
	if err != nil {
		return err
	}

	// fetch the domain details
	domain, err := d.getDomain(authZone)
	if err != nil {
		return err
	}

	// find matching records
	name := strings.Replace(fqdn, "."+authZone, "", 1)
	records, err := d.getRecords(domain, name, "TXT")
	if err != nil {
		return err
	}

	// delete records
	for _, record := range *records {
		err = d.deleteRecord(domain, record)
		if err != nil {
			return err
		}
	}

	return nil
}

func (d *DNSProvider) getDomain(authZone string) (*Domain, error) {
	domainName := authZone[0 : len(authZone)-1]
	// Get all domains
	resp, err := d.sendRequest("GET", "domains", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	domains := []*Domain{}
	err = json.NewDecoder(resp.Body).Decode(&domains)
	if err != nil {
		return nil, err
	}
	for _, domain := range domains {
		if domain.Name == domainName {
			return domain, nil
		}
	}
	return nil, errors.New("Could not find domain name at constellix.")
}

func (d *DNSProvider) getRecords(domain *Domain, recordName, recordType string) (*[]Record, error) {
	//TODO GET all records and filter to the one we want to remove
	resource := fmt.Sprintf("%s/%d/%s", "domains/", domain.ID, "/records/?gtdRegion=1")

	resp, err := d.sendRequest("GET", resource, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	type recordsResponse struct {
		Records *[]Record `json:"data"`
	}

	var records []Record
	err = json.NewDecoder(resp.Body).Decode(&records)
	if err != nil {
		return nil, err
	}
	res := make([]Record, 0)
	for _, rec := range records {
		if rec.Type == recordType && rec.Name == recordName {
			res = append(res, rec)
		}
	}

	return &res, nil
}

func (d *DNSProvider) createRecord(domain *Domain, record *Record) error {
	url := fmt.Sprintf("%s%d%s", "domains/", domain.ID, "/records/txt")

	resp, err := d.sendRequest("POST", url, record)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (d *DNSProvider) deleteRecord(domain *Domain, record Record) error {
	resource := fmt.Sprintf("%s%d%s%d", "domains/", domain.ID, "/records/txt/", record.ID)

	resp, err := d.sendRequest("DELETE", resource, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

func (d *DNSProvider) sendRequest(method, resource string, payload interface{}) (*http.Response, error) {
	url := fmt.Sprintf("%s%s", d.baseURL, resource)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix()*1000)
	// timestamp := "1523597905844"
	signature := computeHMAC(timestamp, d.apiSecret)

	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	token := fmt.Sprintf("%s:%s:%s", d.apiKey, signature, timestamp)
	// req.Header.Set("x-cnsdns-apiKey", d.apiKey)
	// req.Header.Set("x-cnsdns-requestDate", timestamp)
	// req.Header.Set("x-cnsdns-hmac", signature)
	req.Header.Set("x-cns-security-token", token)
	req.Header.Set("accept", "application/json")
	req.Header.Set("content-type", "application/json")

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(10 * time.Second),
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode > 299 {
		return nil, fmt.Errorf("Constellix API request to %s with token %s body %s, failed with HTTP status code %d", url, token, body, resp.StatusCode)
	}

	return resp, nil
}

func computeHMAC(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha1.New, key)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

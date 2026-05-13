package rdap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kwkuh/whois-engine/internal/normalize"
)

const bootstrapURL = "https://data.iana.org/rdap/dns.json"

type bootstrap struct {
	Services [][]interface{} `json:"services"`
}

type Registry struct {
	mu       sync.RWMutex
	loaded   bool
	tldToURL map[string]string
	client   *http.Client
}

func NewRegistry() *Registry {
	return &Registry{
		tldToURL: map[string]string{},
		client:   &http.Client{Timeout: 20 * time.Second},
	}
}

func (r *Registry) Load() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded {
		return nil
	}
	resp, err := r.client.Get(bootstrapURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var b bootstrap
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	for _, svc := range b.Services {
		if len(svc) != 2 {
			continue
		}
		tlds, ok1 := svc[0].([]interface{})
		urls, ok2 := svc[1].([]interface{})
		if !ok1 || !ok2 || len(urls) == 0 {
			continue
		}
		base, _ := urls[0].(string)
		base = strings.TrimRight(base, "/")
		for _, t := range tlds {
			if ts, ok := t.(string); ok {
				r.tldToURL[strings.ToLower(ts)] = base
			}
		}
	}
	r.loaded = true
	return nil
}

func (r *Registry) EndpointFor(domain string) (string, bool) {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for i := 1; i < len(parts); i++ {
		tld := strings.Join(parts[i:], ".")
		if u, ok := r.tldToURL[tld]; ok {
			return u, true
		}
	}
	return "", false
}

type rdapResponse struct {
	ObjectClassName string        `json:"objectClassName"`
	Handle          string        `json:"handle"`
	LDHName         string        `json:"ldhName"`
	Status          []string      `json:"status"`
	Events          []rdapEvent   `json:"events"`
	Entities        []rdapEntity  `json:"entities"`
	Nameservers     []rdapNS      `json:"nameservers"`
	SecureDNS       *secureDNS    `json:"secureDNS"`
	ErrorCode       int           `json:"errorCode"`
	Title           string        `json:"title"`
	Notices         []interface{} `json:"notices"`
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Handle    string       `json:"handle"`
	Roles     []string     `json:"roles"`
	VCardArray []interface{} `json:"vcardArray"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type secureDNS struct {
	DelegationSigned bool `json:"delegationSigned"`
}

func (r *Registry) Lookup(domain string) (*normalize.DomainInfo, error) {
	start := time.Now()
	if err := r.Load(); err != nil {
		return nil, err
	}
	base, ok := r.EndpointFor(domain)
	if !ok {
		return nil, fmt.Errorf("no RDAP endpoint for %s", domain)
	}
	url := base + "/domain/" + domain
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/rdap+json")
	req.Header.Set("User-Agent", "whois-engine/0.1")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	info := &normalize.DomainInfo{
		Domain:   strings.ToLower(domain),
		Source:   normalize.SourceRDAP,
		LookupMS: time.Since(start).Milliseconds(),
	}

	if resp.StatusCode == 404 {
		info.Available = true
		return info, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("rdap status %d: %s", resp.StatusCode, string(body))
	}

	var rr rdapResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		return nil, err
	}
	info.Status = rr.Status
	if rr.SecureDNS != nil {
		info.DNSSEC = rr.SecureDNS.DelegationSigned
	}
	for _, ns := range rr.Nameservers {
		if ns.LDHName != "" {
			info.Nameservers = append(info.Nameservers, strings.ToLower(ns.LDHName))
		}
	}
	for _, ev := range rr.Events {
		t, err := time.Parse(time.RFC3339, ev.EventDate)
		if err != nil {
			continue
		}
		switch ev.EventAction {
		case "registration":
			info.CreatedAt = t
		case "expiration":
			info.ExpiresAt = t
		case "last changed", "last update of RDAP database":
			if ev.EventAction == "last changed" {
				info.UpdatedAt = t
			}
		}
	}
	for _, ent := range rr.Entities {
		for _, role := range ent.Roles {
			if role == "registrar" {
				if name := extractVCardName(ent.VCardArray); name != "" {
					info.Registrar = name
				}
			}
		}
	}
	info.LookupMS = time.Since(start).Milliseconds()
	return info, nil
}

func extractVCardName(v []interface{}) string {
	if len(v) < 2 {
		return ""
	}
	entries, ok := v[1].([]interface{})
	if !ok {
		return ""
	}
	for _, e := range entries {
		arr, ok := e.([]interface{})
		if !ok || len(arr) < 4 {
			continue
		}
		key, _ := arr[0].(string)
		if key == "fn" {
			if s, ok := arr[3].(string); ok {
				return s
			}
		}
	}
	return ""
}

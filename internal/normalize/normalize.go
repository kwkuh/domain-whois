package normalize

import (
	"time"

	"github.com/kwkuh/whois-engine/internal/dnsx"
)

type Source string

const (
	SourceRDAP  Source = "rdap"
	SourceWHOIS Source = "whois"
	SourceDNS   Source = "dns"
)

type DomainInfo struct {
	Domain      string    `json:"domain"`
	Available   bool      `json:"available"`
	Registrar   string    `json:"registrar,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Nameservers []string  `json:"nameservers,omitempty"`
	Status      []string  `json:"status,omitempty"`
	DNSSEC      bool      `json:"dnssec"`
	Source      Source    `json:"source"`
	Raw         string    `json:"raw,omitempty"`
	Error       string    `json:"error,omitempty"`
	LookupMS    int64     `json:"lookup_ms"`
	DNS         *dnsx.Record `json:"dns,omitempty"`
}

func (d *DomainInfo) DaysToExpiry() int {
	if d.ExpiresAt.IsZero() {
		return 0
	}
	return int(time.Until(d.ExpiresAt).Hours() / 24)
}

func (d *DomainInfo) Lifecycle() string {
	if d.Available {
		return "AVAILABLE"
	}
	for _, s := range d.Status {
		switch s {
		case "pending delete", "pendingDelete":
			return "PENDING_DELETE"
		case "redemption period", "redemptionPeriod":
			return "REDEMPTION"
		}
	}
	if !d.ExpiresAt.IsZero() && time.Now().After(d.ExpiresAt) {
		return "EXPIRED"
	}
	return "ACTIVE"
}

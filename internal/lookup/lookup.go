package lookup

import (
	"strings"

	"github.com/kwkuh/whois-engine/internal/cache"
	"github.com/kwkuh/whois-engine/internal/dnsx"
	"github.com/kwkuh/whois-engine/internal/normalize"
	"github.com/kwkuh/whois-engine/internal/rdap"
	"github.com/kwkuh/whois-engine/internal/whois"
)

type Engine struct {
	rdap      *rdap.Registry
	cache     *cache.Store
	rdapOnly  bool
	whoisOnly bool
	withDNS   bool
}

type Options struct {
	RDAPOnly  bool
	WHOISOnly bool
	WithDNS   bool
	Cache     *cache.Store
}

func New(opts Options) *Engine {
	return &Engine{
		rdap:      rdap.NewRegistry(),
		cache:     opts.Cache,
		rdapOnly:  opts.RDAPOnly,
		whoisOnly: opts.WHOISOnly,
		withDNS:   opts.WithDNS,
	}
}

func (e *Engine) Lookup(domain string) *normalize.DomainInfo {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return &normalize.DomainInfo{Error: "empty domain"}
	}

	if e.cache != nil {
		if hit, ok := e.cache.Get(domain); ok {
			return hit
		}
	}

	info := e.fetch(domain)

	if e.withDNS && info != nil {
		rec := dnsx.Probe(domain)
		info.DNS = rec
		if info.Available && rec.HasDNS {
			// Domain resolves but RDAP/WHOIS said unavailable — likely transient
			// network state or stale "not found"; mark as registered.
			info.Available = false
		}
	}

	if e.cache != nil && info != nil && info.Error == "" {
		_ = e.cache.Set(domain, info)
	}
	return info
}

func (e *Engine) fetch(domain string) *normalize.DomainInfo {
	if !e.whoisOnly {
		info, err := e.rdap.Lookup(domain)
		if err == nil {
			return info
		}
		if e.rdapOnly {
			return &normalize.DomainInfo{Domain: domain, Error: err.Error(), Source: normalize.SourceRDAP}
		}
	}
	info, err := whois.Lookup(domain)
	if err != nil {
		return &normalize.DomainInfo{Domain: domain, Error: err.Error(), Source: normalize.SourceWHOIS}
	}
	return info
}

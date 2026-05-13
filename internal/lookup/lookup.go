package lookup

import (
	"strings"

	"github.com/kwkuh/whois-engine/internal/normalize"
	"github.com/kwkuh/whois-engine/internal/rdap"
	"github.com/kwkuh/whois-engine/internal/whois"
)

type Engine struct {
	rdap     *rdap.Registry
	rdapOnly bool
	whoisOnly bool
}

type Options struct {
	RDAPOnly  bool
	WHOISOnly bool
}

func New(opts Options) *Engine {
	return &Engine{
		rdap:      rdap.NewRegistry(),
		rdapOnly:  opts.RDAPOnly,
		whoisOnly: opts.WHOISOnly,
	}
}

func (e *Engine) Lookup(domain string) *normalize.DomainInfo {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return &normalize.DomainInfo{Error: "empty domain"}
	}

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

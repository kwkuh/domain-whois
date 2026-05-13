package dnsx

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

type Record struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	CNAME string   `json:"cname,omitempty"`
	HasDNS bool    `json:"has_dns"`
	HostingHint string `json:"hosting_hint,omitempty"`
	NSProvider  string `json:"ns_provider,omitempty"`
}

var resolver = &net.Resolver{PreferGo: true}

func Probe(domain string) *Record {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	r := &Record{}

	if ips, err := resolver.LookupHost(ctx, domain); err == nil {
		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				r.AAAA = append(r.AAAA, ip)
			} else {
				r.A = append(r.A, ip)
			}
		}
	}
	if mxs, err := resolver.LookupMX(ctx, domain); err == nil {
		for _, m := range mxs {
			r.MX = append(r.MX, strings.TrimSuffix(m.Host, "."))
		}
	}
	if nss, err := resolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			r.NS = append(r.NS, strings.ToLower(strings.TrimSuffix(ns.Host, ".")))
		}
		sort.Strings(r.NS)
	}
	if txts, err := resolver.LookupTXT(ctx, domain); err == nil {
		r.TXT = txts
	}
	if cn, err := resolver.LookupCNAME(ctx, domain); err == nil {
		r.CNAME = strings.TrimSuffix(cn, ".")
		if r.CNAME == domain+"." || r.CNAME == domain {
			r.CNAME = ""
		}
	}
	r.HasDNS = len(r.A) > 0 || len(r.AAAA) > 0 || len(r.NS) > 0 || len(r.MX) > 0
	r.NSProvider = detectNSProvider(r.NS)
	r.HostingHint = detectHostingHint(r)
	return r
}

func detectNSProvider(ns []string) string {
	for _, n := range ns {
		ln := strings.ToLower(n)
		switch {
		case strings.Contains(ln, "cloudflare"):
			return "Cloudflare"
		case strings.Contains(ln, "awsdns"):
			return "AWS Route53"
		case strings.Contains(ln, "google") || strings.Contains(ln, "googledomains"):
			return "Google"
		case strings.Contains(ln, "azure-dns"):
			return "Azure DNS"
		case strings.Contains(ln, "nsone.net"):
			return "NS1"
		case strings.Contains(ln, "vercel-dns"):
			return "Vercel"
		case strings.Contains(ln, "netlify"):
			return "Netlify"
		case strings.Contains(ln, "dnsimple"):
			return "DNSimple"
		case strings.Contains(ln, "digitalocean"):
			return "DigitalOcean"
		case strings.Contains(ln, "name-services.com"), strings.Contains(ln, "registrar-servers.com"):
			return "Namecheap"
		case strings.Contains(ln, "dynadot"):
			return "Dynadot"
		case strings.Contains(ln, "godaddy") || strings.Contains(ln, "domaincontrol.com"):
			return "GoDaddy"
		case strings.Contains(ln, "sedoparking") || strings.Contains(ln, "parkingcrew") || strings.Contains(ln, "bodis.com"):
			return "Domain Parking"
		}
	}
	return ""
}

func detectHostingHint(r *Record) string {
	for _, ip := range r.A {
		switch {
		case strings.HasPrefix(ip, "104.21.") || strings.HasPrefix(ip, "172.67."):
			return "Cloudflare proxy"
		case strings.HasPrefix(ip, "76.76.21."), strings.HasPrefix(ip, "76.76.19."):
			return "Vercel"
		case strings.HasPrefix(ip, "75.2."), strings.HasPrefix(ip, "99.83."):
			return "Netlify"
		case strings.HasPrefix(ip, "185.199."):
			return "GitHub Pages"
		case strings.HasPrefix(ip, "151.101."):
			return "Fastly"
		}
	}
	if r.CNAME != "" {
		ln := strings.ToLower(r.CNAME)
		switch {
		case strings.Contains(ln, "vercel"):
			return "Vercel"
		case strings.Contains(ln, "netlify"):
			return "Netlify"
		case strings.Contains(ln, "github.io"):
			return "GitHub Pages"
		case strings.Contains(ln, "pages.dev"):
			return "Cloudflare Pages"
		case strings.Contains(ln, "workers.dev"):
			return "Cloudflare Workers"
		}
	}
	return ""
}

package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/kwkuh/whois-engine/internal/bulk"
	"github.com/kwkuh/whois-engine/internal/cache"
	"github.com/kwkuh/whois-engine/internal/diff"
	"github.com/kwkuh/whois-engine/internal/lookup"
	"github.com/kwkuh/whois-engine/internal/rdap"
	"github.com/kwkuh/whois-engine/internal/watch"
)

const usage = `whoisctl — universal RDAP/WHOIS engine

Usage:
  whoisctl lookup <domain> [--json] [--dns] [--rdap-only] [--whois-only] [--no-cache]
  whoisctl bulk <file|-> [--format csv|json|ndjson] [--concurrency N] [--dns] [--no-cache]
  whoisctl check <keyword> --tlds=com,io,ai,id [--concurrency N]
  whoisctl expiry <file|-> [--warn-days N] [--critical-days N] [--format csv|json]
  whoisctl diff <before.ndjson> <after.ndjson> [--format json|text]
  whoisctl watch <file|-> [--interval 1h] [--concurrency N] [--once]
  whoisctl tld-info <tld>
  whoisctl cache clear|purge|path

Global flags:
  --cache-dir <path>       override cache directory (default ~/.cache/whois-engine)
  --cache-ttl <duration>   force fixed TTL (default: adaptive by lifecycle)

Examples:
  whoisctl lookup example.com --dns
  whoisctl bulk domains.txt --format csv --concurrency 64 > out.csv
  whoisctl expiry portfolio.txt --warn-days 30 --critical-days 7
  whoisctl diff snapshot-2026-05-13.ndjson snapshot-2026-05-14.ndjson
  whoisctl watch portfolio.txt --interval 30m
`

// reorder moves positional args after flags so Go's flag.Parse works
// regardless of position. Known bool flags must be listed so we don't
// accidentally consume a positional as their value.
var boolFlags = map[string]bool{
	"json": true, "rdap-only": true, "whois-only": true,
	"dns": true, "no-cache": true, "once": true,
	"h": true, "help": true,
}

func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.Contains(name, "=") {
				continue
			}
			if boolFlags[name] {
				continue
			}
			if i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	args := reorder(os.Args[2:])
	switch os.Args[1] {
	case "lookup":
		cmdLookup(args)
	case "bulk":
		cmdBulk(args)
	case "check":
		cmdCheck(args)
	case "expiry":
		cmdExpiry(args)
	case "diff":
		cmdDiff(args)
	case "watch":
		cmdWatch(args)
	case "tld-info":
		cmdTLDInfo(args)
	case "cache":
		cmdCache(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

type globalOpts struct {
	cacheDir string
	cacheTTL time.Duration
	noCache  bool
}

func registerGlobal(fs *flag.FlagSet, g *globalOpts) {
	fs.StringVar(&g.cacheDir, "cache-dir", "", "cache directory")
	fs.DurationVar(&g.cacheTTL, "cache-ttl", 0, "fixed cache TTL (0 = adaptive)")
	fs.BoolVar(&g.noCache, "no-cache", false, "disable cache")
}

func openCache(g *globalOpts) *cache.Store {
	if g.noCache {
		return nil
	}
	s, err := cache.Open(g.cacheDir, g.cacheTTL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cache open:", err)
		return nil
	}
	return s
}

func cmdLookup(args []string) {
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	rdapOnly := fs.Bool("rdap-only", false, "skip WHOIS fallback")
	whoisOnly := fs.Bool("whois-only", false, "WHOIS only")
	withDNS := fs.Bool("dns", false, "include DNS intelligence probe")
	var g globalOpts
	registerGlobal(fs, &g)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "lookup: domain required")
		os.Exit(2)
	}
	eng := lookup.New(lookup.Options{
		RDAPOnly: *rdapOnly, WHOISOnly: *whoisOnly, WithDNS: *withDNS,
		Cache: openCache(&g),
	})
	info := eng.Lookup(fs.Arg(0))

	if *asJSON {
		info.Raw = ""
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(info)
		return
	}

	fmt.Printf("Domain:      %s\n", info.Domain)
	fmt.Printf("Lifecycle:   %s\n", info.Lifecycle())
	fmt.Printf("Available:   %v\n", info.Available)
	if info.Registrar != "" {
		fmt.Printf("Registrar:   %s\n", info.Registrar)
	}
	if !info.CreatedAt.IsZero() {
		fmt.Printf("Created:     %s\n", info.CreatedAt.Format("2006-01-02"))
	}
	if !info.ExpiresAt.IsZero() {
		fmt.Printf("Expires:     %s  (%d days)\n", info.ExpiresAt.Format("2006-01-02"), info.DaysToExpiry())
	}
	if !info.UpdatedAt.IsZero() {
		fmt.Printf("Updated:     %s\n", info.UpdatedAt.Format("2006-01-02"))
	}
	if len(info.Nameservers) > 0 {
		fmt.Printf("Nameservers: %s\n", strings.Join(info.Nameservers, ", "))
	}
	if len(info.Status) > 0 {
		fmt.Printf("Status:      %s\n", strings.Join(info.Status, ", "))
	}
	fmt.Printf("DNSSEC:      %v\n", info.DNSSEC)
	fmt.Printf("Source:      %s (%d ms)\n", info.Source, info.LookupMS)
	if info.DNS != nil {
		fmt.Println("DNS:")
		if len(info.DNS.A) > 0 {
			fmt.Printf("  A:           %s\n", strings.Join(info.DNS.A, ", "))
		}
		if len(info.DNS.AAAA) > 0 {
			fmt.Printf("  AAAA:        %s\n", strings.Join(info.DNS.AAAA, ", "))
		}
		if len(info.DNS.MX) > 0 {
			fmt.Printf("  MX:          %s\n", strings.Join(info.DNS.MX, ", "))
		}
		if len(info.DNS.NS) > 0 {
			fmt.Printf("  NS:          %s\n", strings.Join(info.DNS.NS, ", "))
		}
		if info.DNS.CNAME != "" {
			fmt.Printf("  CNAME:       %s\n", info.DNS.CNAME)
		}
		if info.DNS.NSProvider != "" {
			fmt.Printf("  NS provider: %s\n", info.DNS.NSProvider)
		}
		if info.DNS.HostingHint != "" {
			fmt.Printf("  Hosting:     %s\n", info.DNS.HostingHint)
		}
	}
	if info.Error != "" {
		fmt.Printf("Error:       %s\n", info.Error)
		os.Exit(1)
	}
}

func cmdBulk(args []string) {
	fs := flag.NewFlagSet("bulk", flag.ExitOnError)
	format := fs.String("format", "ndjson", "csv|json|ndjson")
	concurrency := fs.Int("concurrency", 32, "concurrent workers")
	rdapOnly := fs.Bool("rdap-only", false, "skip WHOIS fallback")
	whoisOnly := fs.Bool("whois-only", false, "WHOIS only")
	withDNS := fs.Bool("dns", false, "include DNS probe")
	var g globalOpts
	registerGlobal(fs, &g)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "bulk: file path required (use - for stdin)")
		os.Exit(2)
	}
	domains, err := bulk.ReadDomains(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "loaded %d domains, concurrency=%d, format=%s\n", len(domains), *concurrency, *format)
	eng := lookup.New(lookup.Options{
		RDAPOnly: *rdapOnly, WHOISOnly: *whoisOnly, WithDNS: *withDNS,
		Cache: openCache(&g),
	})
	cfg := bulk.Config{
		Concurrency: *concurrency,
		Format:      bulk.Format(*format),
		Out:         os.Stdout,
		Progress:    os.Stderr,
	}
	if err := bulk.Run(domains, eng, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "bulk:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr)
}

func cmdCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	tlds := fs.String("tlds", "com,net,io,ai,id", "comma-separated TLDs")
	concurrency := fs.Int("concurrency", 16, "concurrent workers")
	var g globalOpts
	registerGlobal(fs, &g)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "check: keyword required")
		os.Exit(2)
	}
	kw := strings.ToLower(fs.Arg(0))
	var domains []string
	for _, t := range strings.Split(*tlds, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		domains = append(domains, kw+"."+t)
	}
	eng := lookup.New(lookup.Options{Cache: openCache(&g)})
	cfg := bulk.Config{Concurrency: *concurrency, Format: bulk.FormatCSV, Out: os.Stdout}
	if err := bulk.Run(domains, eng, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		os.Exit(1)
	}
}

func cmdExpiry(args []string) {
	fs := flag.NewFlagSet("expiry", flag.ExitOnError)
	warnDays := fs.Int("warn-days", 30, "warning threshold")
	critDays := fs.Int("critical-days", 7, "critical threshold")
	concurrency := fs.Int("concurrency", 16, "concurrent workers")
	format := fs.String("format", "table", "table|csv|json")
	var g globalOpts
	registerGlobal(fs, &g)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "expiry: file required (use - for stdin)")
		os.Exit(2)
	}
	domains, err := bulk.ReadDomains(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	eng := lookup.New(lookup.Options{Cache: openCache(&g)})

	type row struct {
		Domain    string `json:"domain"`
		Expires   string `json:"expires_at"`
		DaysLeft  int    `json:"days_left"`
		Status    string `json:"status"`
		Registrar string `json:"registrar"`
		Error     string `json:"error,omitempty"`
	}
	var rows []row

	jobs := make(chan string, *concurrency)
	resCh := make(chan row, *concurrency)
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				info := eng.Lookup(d)
				r := row{
					Domain:    info.Domain,
					DaysLeft:  info.DaysToExpiry(),
					Registrar: info.Registrar,
				}
				if !info.ExpiresAt.IsZero() {
					r.Expires = info.ExpiresAt.UTC().Format("2006-01-02")
				}
				switch {
				case info.Error != "":
					r.Status = "ERROR"
					r.Error = info.Error
				case info.Available:
					r.Status = "AVAILABLE"
				case r.DaysLeft < 0:
					r.Status = "EXPIRED"
				case r.DaysLeft <= *critDays:
					r.Status = "CRITICAL"
				case r.DaysLeft <= *warnDays:
					r.Status = "WARN"
				default:
					r.Status = "OK"
				}
				resCh <- r
			}
		}()
	}
	go func() {
		for _, d := range domains {
			jobs <- d
		}
		close(jobs)
		wg.Wait()
		close(resCh)
	}()
	for r := range resCh {
		rows = append(rows, r)
	}

	sort.Slice(rows, func(i, j int) bool {
		return rows[i].DaysLeft < rows[j].DaysLeft
	})

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
	case "csv":
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"domain", "expires_at", "days_left", "status", "registrar", "error"})
		for _, r := range rows {
			_ = w.Write([]string{r.Domain, r.Expires, fmt.Sprintf("%d", r.DaysLeft), r.Status, r.Registrar, r.Error})
		}
		w.Flush()
	default:
		fmt.Printf("%-35s %-12s %6s  %-10s %s\n", "DOMAIN", "EXPIRES", "DAYS", "STATUS", "REGISTRAR")
		for _, r := range rows {
			fmt.Printf("%-35s %-12s %6d  %-10s %s\n", r.Domain, r.Expires, r.DaysLeft, r.Status, r.Registrar)
		}
	}
}

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	format := fs.String("format", "text", "text|json")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "diff: requires <before> <after>")
		os.Exit(2)
	}
	before, err := diff.LoadSnapshot(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "load before:", err)
		os.Exit(1)
	}
	after, err := diff.LoadSnapshot(fs.Arg(1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "load after:", err)
		os.Exit(1)
	}
	r := diff.Compare(before, after)
	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
	fmt.Printf("added=%d removed=%d changed=%d unchanged=%d\n", len(r.Added), len(r.Removed), len(r.Changed), r.Unchanged)
	for _, d := range r.Added {
		fmt.Printf("  + %s\n", d)
	}
	for _, d := range r.Removed {
		fmt.Printf("  - %s\n", d)
	}
	for _, c := range r.Changed {
		fmt.Printf("  ~ %s\n", c.Domain)
		for _, f := range c.Fields {
			fmt.Printf("      %s: %v → %v\n", f, c.Before[f], c.After[f])
		}
	}
}

func cmdWatch(args []string) {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	interval := fs.Duration("interval", 1*time.Hour, "poll interval")
	concurrency := fs.Int("concurrency", 16, "concurrent workers")
	once := fs.Bool("once", false, "run a single scan and exit")
	var g globalOpts
	registerGlobal(fs, &g)
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "watch: file required")
		os.Exit(2)
	}
	domains, err := bulk.ReadDomains(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	eng := lookup.New(lookup.Options{Cache: openCache(&g)})
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	err = watch.Run(ctx, eng, watch.Config{
		Domains:     domains,
		Interval:    *interval,
		Concurrency: *concurrency,
		OnceAndExit: *once,
		Out:         os.Stdout,
	})
	if err != nil && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "watch:", err)
		os.Exit(1)
	}
}

func cmdTLDInfo(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "tld-info: tld required")
		os.Exit(2)
	}
	tld := strings.TrimPrefix(strings.ToLower(args[0]), ".")
	reg := rdap.NewRegistry()
	if err := reg.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(1)
	}
	endpoint, ok := reg.EndpointFor("example." + tld)
	fmt.Printf("TLD:           .%s\n", tld)
	fmt.Printf("RDAP support:  %v\n", ok)
	if ok {
		fmt.Printf("RDAP endpoint: %s\n", endpoint)
	} else {
		fmt.Printf("Fallback:      WHOIS via whois.iana.org referral\n")
	}
}

func cmdCache(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "cache: subcommand required (clear|purge|path)")
		os.Exit(2)
	}
	s, err := cache.Open("", 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cache open:", err)
		os.Exit(1)
	}
	switch args[0] {
	case "clear":
		if err := s.Clear(); err != nil {
			fmt.Fprintln(os.Stderr, "clear:", err)
			os.Exit(1)
		}
		fmt.Println("cache cleared")
	case "purge":
		n, err := s.Purge()
		if err != nil {
			fmt.Fprintln(os.Stderr, "purge:", err)
			os.Exit(1)
		}
		fmt.Printf("purged %d expired entries\n", n)
	case "path":
		fmt.Println(cache.DefaultDir())
	default:
		fmt.Fprintln(os.Stderr, "unknown cache subcommand:", args[0])
		os.Exit(2)
	}
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kwkuh/whois-engine/internal/bulk"
	"github.com/kwkuh/whois-engine/internal/lookup"
)

const usage = `whoisctl — universal RDAP/WHOIS engine

Usage:
  whoisctl lookup <domain> [--json] [--rdap-only] [--whois-only]
  whoisctl bulk <file|-> [--format csv|json|ndjson] [--concurrency N] [--rdap-only] [--whois-only]
  whoisctl check <keyword> --tlds=com,io,ai,id [--concurrency N]

Examples:
  whoisctl lookup example.com
  whoisctl lookup example.com --json
  whoisctl bulk domains.txt --format csv --concurrency 64 > out.csv
  whoisctl check startuphub --tlds=com,io,ai,id
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "lookup":
		cmdLookup(reorder(os.Args[2:]))
	case "bulk":
		cmdBulk(reorder(os.Args[2:]))
	case "check":
		cmdCheck(reorder(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// reorder moves positional args to the end so flag.Parse sees flags first.
// Boolean flags must be known so we don't accidentally treat the next token as their value.
var boolFlags = map[string]bool{
	"json": true, "rdap-only": true, "whois-only": true,
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
			if idx := strings.Index(name, "="); idx >= 0 {
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

func cmdLookup(args []string) {
	fs := flag.NewFlagSet("lookup", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	rdapOnly := fs.Bool("rdap-only", false, "skip WHOIS fallback")
	whoisOnly := fs.Bool("whois-only", false, "skip RDAP, use WHOIS only")
	_ = fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "lookup: domain required")
		os.Exit(2)
	}
	eng := lookup.New(lookup.Options{RDAPOnly: *rdapOnly, WHOISOnly: *whoisOnly})
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
	if info.Error != "" {
		fmt.Printf("Error:       %s\n", info.Error)
		os.Exit(1)
	}
}

func cmdBulk(args []string) {
	fs := flag.NewFlagSet("bulk", flag.ExitOnError)
	format := fs.String("format", "ndjson", "output: csv|json|ndjson")
	concurrency := fs.Int("concurrency", 32, "concurrent workers")
	rdapOnly := fs.Bool("rdap-only", false, "skip WHOIS fallback")
	whoisOnly := fs.Bool("whois-only", false, "WHOIS only")
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
	eng := lookup.New(lookup.Options{RDAPOnly: *rdapOnly, WHOISOnly: *whoisOnly})
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
	eng := lookup.New(lookup.Options{})
	cfg := bulk.Config{
		Concurrency: *concurrency,
		Format:      bulk.FormatCSV,
		Out:         os.Stdout,
	}
	if err := bulk.Run(domains, eng, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		os.Exit(1)
	}
}

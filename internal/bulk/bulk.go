package bulk

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kwkuh/whois-engine/internal/lookup"
	"github.com/kwkuh/whois-engine/internal/normalize"
)

type Format string

const (
	FormatJSON   Format = "json"
	FormatNDJSON Format = "ndjson"
	FormatCSV    Format = "csv"
)

type Config struct {
	Concurrency int
	Format      Format
	Out         io.Writer
	Progress    io.Writer
}

func ReadDomains(path string) ([]string, error) {
	var f *os.File
	var err error
	if path == "-" {
		f = os.Stdin
	} else {
		f, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}

func Run(domains []string, eng *lookup.Engine, cfg Config) error {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 32
	}
	jobs := make(chan string, cfg.Concurrency)
	results := make(chan *normalize.DomainInfo, cfg.Concurrency)

	var wg sync.WaitGroup
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				results <- eng.Lookup(d)
			}
		}()
	}

	go func() {
		for _, d := range domains {
			jobs <- d
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	switch cfg.Format {
	case FormatCSV:
		return writeCSV(results, cfg)
	case FormatJSON:
		return writeJSON(results, cfg)
	default:
		return writeNDJSON(results, cfg)
	}
}

func writeNDJSON(results <-chan *normalize.DomainInfo, cfg Config) error {
	enc := json.NewEncoder(cfg.Out)
	n := 0
	start := time.Now()
	for r := range results {
		r.Raw = ""
		if err := enc.Encode(r); err != nil {
			return err
		}
		n++
		progress(cfg.Progress, n, start)
	}
	return nil
}

func writeJSON(results <-chan *normalize.DomainInfo, cfg Config) error {
	var all []*normalize.DomainInfo
	n := 0
	start := time.Now()
	for r := range results {
		r.Raw = ""
		all = append(all, r)
		n++
		progress(cfg.Progress, n, start)
	}
	enc := json.NewEncoder(cfg.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(all)
}

func writeCSV(results <-chan *normalize.DomainInfo, cfg Config) error {
	w := csv.NewWriter(cfg.Out)
	defer w.Flush()
	_ = w.Write([]string{"domain", "available", "lifecycle", "registrar", "created_at", "expires_at", "updated_at", "days_to_expiry", "nameservers", "status", "dnssec", "source", "lookup_ms", "error"})
	n := 0
	start := time.Now()
	for r := range results {
		_ = w.Write([]string{
			r.Domain,
			fmt.Sprintf("%v", r.Available),
			r.Lifecycle(),
			r.Registrar,
			fmtTime(r.CreatedAt),
			fmtTime(r.ExpiresAt),
			fmtTime(r.UpdatedAt),
			fmt.Sprintf("%d", r.DaysToExpiry()),
			strings.Join(r.Nameservers, ";"),
			strings.Join(r.Status, ";"),
			fmt.Sprintf("%v", r.DNSSEC),
			string(r.Source),
			fmt.Sprintf("%d", r.LookupMS),
			r.Error,
		})
		n++
		progress(cfg.Progress, n, start)
	}
	return nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func progress(w io.Writer, n int, start time.Time) {
	if w == nil {
		return
	}
	if n%10 == 0 {
		rate := float64(n) / time.Since(start).Seconds()
		fmt.Fprintf(w, "\r[%d done | %.1f/s]", n, rate)
	}
}

package watch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kwkuh/whois-engine/internal/diff"
	"github.com/kwkuh/whois-engine/internal/lookup"
	"github.com/kwkuh/whois-engine/internal/normalize"
)

type Config struct {
	Domains     []string
	Interval    time.Duration
	Concurrency int
	StateDir    string
	Out         io.Writer
	OnceAndExit bool
}

func Run(ctx context.Context, eng *lookup.Engine, cfg Config) error {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 16
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	if cfg.StateDir == "" {
		h, _ := os.UserHomeDir()
		cfg.StateDir = filepath.Join(h, ".cache", "whois-engine", "watch")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o755); err != nil {
		return err
	}
	if cfg.Out == nil {
		cfg.Out = os.Stdout
	}

	statePath := filepath.Join(cfg.StateDir, "latest.ndjson")
	previous, _ := diff.LoadSnapshot(statePath)

	for {
		current := scan(eng, cfg.Domains, cfg.Concurrency)
		if len(previous) > 0 {
			emit(cfg.Out, diff.Compare(previous, current))
		} else {
			fmt.Fprintf(cfg.Out, "[%s] initial snapshot: %d domains\n",
				time.Now().UTC().Format(time.RFC3339), len(current))
		}
		if err := saveSnapshot(statePath, current); err != nil {
			fmt.Fprintln(os.Stderr, "snapshot save:", err)
		}
		previous = current

		if cfg.OnceAndExit {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.Interval):
		}
	}
}

func scan(eng *lookup.Engine, domains []string, n int) map[string]*normalize.DomainInfo {
	out := sync.Map{}
	jobs := make(chan string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				r := eng.Lookup(d)
				out.Store(r.Domain, r)
			}
		}()
	}
	for _, d := range domains {
		jobs <- d
	}
	close(jobs)
	wg.Wait()
	m := map[string]*normalize.DomainInfo{}
	out.Range(func(k, v any) bool {
		m[k.(string)] = v.(*normalize.DomainInfo)
		return true
	})
	return m
}

func emit(w io.Writer, r diff.Report) {
	now := time.Now().UTC().Format(time.RFC3339)
	if len(r.Added) == 0 && len(r.Removed) == 0 && len(r.Changed) == 0 {
		fmt.Fprintf(w, "[%s] no changes (%d domains unchanged)\n", now, r.Unchanged)
		return
	}
	fmt.Fprintf(w, "[%s] changes — added=%d removed=%d changed=%d unchanged=%d\n",
		now, len(r.Added), len(r.Removed), len(r.Changed), r.Unchanged)
	for _, d := range r.Added {
		fmt.Fprintf(w, "  + %s\n", d)
	}
	for _, d := range r.Removed {
		fmt.Fprintf(w, "  - %s\n", d)
	}
	for _, c := range r.Changed {
		fmt.Fprintf(w, "  ~ %s\n", c.Domain)
		for _, f := range c.Fields {
			fmt.Fprintf(w, "      %s: %v → %v\n", f, c.Before[f], c.After[f])
		}
	}
}

func saveSnapshot(path string, m map[string]*normalize.DomainInfo) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, v := range m {
		v.Raw = ""
		if err := enc.Encode(v); err != nil {
			return err
		}
	}
	return nil
}

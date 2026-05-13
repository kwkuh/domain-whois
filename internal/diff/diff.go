package diff

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kwkuh/whois-engine/internal/normalize"
)

type Change struct {
	Domain  string   `json:"domain"`
	Fields  []string `json:"fields"`
	Before  map[string]any `json:"before"`
	After   map[string]any `json:"after"`
}

type Report struct {
	Added    []string `json:"added"`
	Removed  []string `json:"removed"`
	Unchanged int     `json:"unchanged"`
	Changed  []Change `json:"changed"`
}

func LoadSnapshot(path string) (map[string]*normalize.DomainInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]*normalize.DomainInfo{}

	br := bufio.NewReader(f)
	first, err := br.Peek(1)
	if err == io.EOF {
		return out, nil
	}
	if err != nil {
		return nil, err
	}

	if first[0] == '[' {
		var arr []*normalize.DomainInfo
		if err := json.NewDecoder(br).Decode(&arr); err != nil {
			return nil, err
		}
		for _, it := range arr {
			out[it.Domain] = it
		}
		return out, nil
	}

	dec := json.NewDecoder(br)
	for {
		var it normalize.DomainInfo
		if err := dec.Decode(&it); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		out[it.Domain] = &it
	}
	return out, nil
}

func Compare(before, after map[string]*normalize.DomainInfo) Report {
	r := Report{}
	seen := map[string]bool{}
	for d := range before {
		if _, ok := after[d]; !ok {
			r.Removed = append(r.Removed, d)
		}
		seen[d] = true
	}
	for d := range after {
		if _, ok := before[d]; !ok {
			r.Added = append(r.Added, d)
		}
		seen[d] = true
	}
	for d := range seen {
		b, okB := before[d]
		a, okA := after[d]
		if !okA || !okB {
			continue
		}
		fields, beforeM, afterM := diffOne(b, a)
		if len(fields) == 0 {
			r.Unchanged++
			continue
		}
		r.Changed = append(r.Changed, Change{Domain: d, Fields: fields, Before: beforeM, After: afterM})
	}
	sort.Strings(r.Added)
	sort.Strings(r.Removed)
	sort.Slice(r.Changed, func(i, j int) bool { return r.Changed[i].Domain < r.Changed[j].Domain })
	return r
}

func diffOne(b, a *normalize.DomainInfo) (fields []string, beforeM, afterM map[string]any) {
	beforeM = map[string]any{}
	afterM = map[string]any{}
	check := func(name string, bv, av any) {
		if fmt.Sprint(bv) != fmt.Sprint(av) {
			fields = append(fields, name)
			beforeM[name] = bv
			afterM[name] = av
		}
	}
	check("available", b.Available, a.Available)
	check("registrar", b.Registrar, a.Registrar)
	check("expires_at", fmtT(b.ExpiresAt), fmtT(a.ExpiresAt))
	check("nameservers", joinSorted(b.Nameservers), joinSorted(a.Nameservers))
	check("status", joinSorted(b.Status), joinSorted(a.Status))
	check("dnssec", b.DNSSEC, a.DNSSEC)
	return
}

func joinSorted(s []string) string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

func fmtT(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

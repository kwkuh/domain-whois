package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/kwkuh/whois-engine/internal/normalize"
)

type entry struct {
	StoredAt time.Time             `json:"stored_at"`
	TTL      int64                 `json:"ttl_seconds"`
	Data     *normalize.DomainInfo `json:"data"`
}

type Store struct {
	dir string
	ttl time.Duration
}

func DefaultDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".cache", "whois-engine")
	}
	return ".whois-cache"
}

func Open(dir string, ttl time.Duration) (*Store, error) {
	if dir == "" {
		dir = DefaultDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir, ttl: ttl}, nil
}

func (s *Store) keyPath(domain string) string {
	h := sha256.Sum256([]byte(domain))
	hex := hex.EncodeToString(h[:])
	return filepath.Join(s.dir, hex[:2], hex+".json")
}

func (s *Store) Get(domain string) (*normalize.DomainInfo, bool) {
	p := s.keyPath(domain)
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var e entry
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, false
	}
	if e.TTL > 0 && time.Since(e.StoredAt) > time.Duration(e.TTL)*time.Second {
		return nil, false
	}
	return e.Data, true
}

func (s *Store) Set(domain string, info *normalize.DomainInfo) error {
	if info == nil || info.Error != "" {
		return errors.New("refusing to cache empty or errored result")
	}
	p := s.keyPath(domain)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	ttl := s.chooseTTL(info)
	e := entry{StoredAt: time.Now().UTC(), TTL: int64(ttl.Seconds()), Data: info}
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o644)
}

// chooseTTL: short for availability (might get registered), medium for
// near-expiry domains, long for stable registered domains.
func (s *Store) chooseTTL(info *normalize.DomainInfo) time.Duration {
	if s.ttl > 0 {
		return s.ttl
	}
	if info.Available {
		return 1 * time.Hour
	}
	if !info.ExpiresAt.IsZero() {
		d := info.DaysToExpiry()
		switch {
		case d < 0:
			return 6 * time.Hour
		case d < 30:
			return 6 * time.Hour
		case d < 180:
			return 24 * time.Hour
		}
	}
	return 7 * 24 * time.Hour
}

func (s *Store) Purge() (int, error) {
	n := 0
	err := filepath.Walk(s.dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".json" {
			b, _ := os.ReadFile(path)
			var e entry
			if json.Unmarshal(b, &e) == nil && e.TTL > 0 && time.Since(e.StoredAt) > time.Duration(e.TTL)*time.Second {
				os.Remove(path)
				n++
			}
		}
		return nil
	})
	return n, err
}

func (s *Store) Clear() error {
	return os.RemoveAll(s.dir)
}

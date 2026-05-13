package whois

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/kwkuh/whois-engine/internal/normalize"
)

const (
	ianaServer  = "whois.iana.org"
	defaultPort = "43"
	dialTimeout = 8 * time.Second
	readTimeout = 12 * time.Second
)

var (
	refRe       = regexp.MustCompile(`(?i)(?:refer|whois server|registrar whois server):\s*(\S+)`)
	availableRe = regexp.MustCompile(`(?i)^(no match|not found|no data found|no entries found|domain not found|status:\s*free|status:\s*available|available|the queried object does not exist)`)
)

func Query(server, query string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, defaultPort), dialTimeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(readTimeout))
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	if err != nil && len(b) == 0 {
		return "", err
	}
	return string(b), nil
}

func Lookup(domain string) (*normalize.DomainInfo, error) {
	start := time.Now()
	info := &normalize.DomainInfo{
		Domain: strings.ToLower(domain),
		Source: normalize.SourceWHOIS,
	}

	ianaResp, err := Query(ianaServer, domain)
	if err != nil {
		return nil, fmt.Errorf("iana: %w", err)
	}
	server := extractRefer(ianaResp)
	if server == "" {
		info.Raw = ianaResp
		info.Available = looksAvailable(ianaResp)
		parse(info, ianaResp)
		info.LookupMS = time.Since(start).Milliseconds()
		return info, nil
	}

	resp, err := Query(server, domain)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", server, err)
	}

	// Follow registrar referral one hop (common for .com/.net)
	if reg := extractRefer(resp); reg != "" && reg != server {
		if r2, err := Query(reg, domain); err == nil && len(r2) > 0 {
			resp = r2
		}
	}

	info.Raw = resp
	info.Available = looksAvailable(resp)
	parse(info, resp)
	info.LookupMS = time.Since(start).Milliseconds()
	return info, nil
}

func extractRefer(text string) string {
	m := refRe.FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	s := strings.TrimSpace(m[1])
	s = strings.TrimPrefix(s, "rwhois://")
	s = strings.TrimPrefix(s, "whois://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

func looksAvailable(text string) bool {
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") {
			continue
		}
		if availableRe.MatchString(line) {
			return true
		}
	}
	return false
}

var (
	dateLayouts = []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
		"02.01.2006",
		"02/01/2006",
	}
)

func parseDate(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func parse(info *normalize.DomainInfo, text string) {
	sc := bufio.NewScanner(strings.NewReader(text))
	nsSet := map[string]struct{}{}
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, ":"); i > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:i]))
			val := strings.TrimSpace(line[i+1:])
			if val == "" {
				continue
			}
			switch {
			case strings.Contains(key, "registrar") && !strings.Contains(key, "whois") && !strings.Contains(key, "url") && !strings.Contains(key, "iana"):
				if info.Registrar == "" {
					info.Registrar = val
				}
			case strings.Contains(key, "creation date"), strings.Contains(key, "created"), strings.Contains(key, "registered on"), strings.Contains(key, "registration time"):
				if info.CreatedAt.IsZero() {
					info.CreatedAt = parseDate(val)
				}
			case strings.Contains(key, "expir") || strings.Contains(key, "renewal date") || strings.Contains(key, "paid-till"):
				if info.ExpiresAt.IsZero() {
					info.ExpiresAt = parseDate(val)
				}
			case strings.Contains(key, "updated") || strings.Contains(key, "last modified") || strings.Contains(key, "changed"):
				if info.UpdatedAt.IsZero() {
					info.UpdatedAt = parseDate(val)
				}
			case key == "name server" || key == "nameserver" || key == "nserver" || strings.HasPrefix(key, "name server"):
				fields := strings.Fields(val)
				if len(fields) > 0 {
					nsSet[strings.ToLower(fields[0])] = struct{}{}
				}
			case key == "domain status" || key == "status":
				info.Status = append(info.Status, val)
			case strings.Contains(key, "dnssec"):
				lv := strings.ToLower(val)
				if strings.Contains(lv, "signed") || lv == "yes" || lv == "active" {
					info.DNSSEC = true
				}
			}
		}
	}
	for ns := range nsSet {
		info.Nameservers = append(info.Nameservers, ns)
	}
}

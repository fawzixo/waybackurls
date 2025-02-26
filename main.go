package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}
	dateFormats = []string{
		"20060102150405",         // Wayback
		"2006-01-02 15:04:05",    // VirusTotal
		time.RFC3339,             // Common Crawl alternative
		"2006-01-02T15:04:05Z07:00", // Another possible format
	}
)

func main() {
	var (
		dates          bool
		noSubs         bool
		getVersionsFlag bool
		vtAPIKey       string
	)

	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")
	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")
	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")
	flag.StringVar(&vtAPIKey, "vt-api-key", os.Getenv("VT_API_KEY"), "VirusTotal API key (defaults to VT_API_KEY environment variable)")
	flag.Parse()

	domains := collectDomains()
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "error: no domains specified")
		os.Exit(1)
	}

	if getVersionsFlag {
		handleGetVersions(domains)
		return
	}

	fetchFns := []fetchFn{
		makeFetchFn(getWaybackURLs),
		makeFetchFn(getCommonCrawlURLs),
		makeFetchFnWithAPIKey(getVirusTotalURLs, vtAPIKey),
	}

	processDomains(domains, fetchFns, dates, noSubs)
}

func collectDomains() []string {
	if flag.NArg() > 0 {
		return []string{flag.Arg(0)}
	}

	var domains []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		domains = append(domains, strings.TrimSpace(sc.Text()))
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
	}
	return domains
}

func handleGetVersions(domains []string) {
	for _, u := range domains {
		versions, err := getVersions(u)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting versions for %s: %v\n", u, err)
			continue
		}
		fmt.Println(strings.Join(versions, "\n"))
	}
}

func processDomains(domains []string, fetchFns []fetchFn, dates bool, noSubs bool) {
	for _, domain := range domains {
		var wg sync.WaitGroup
		wurls := make(chan wurl)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		for _, fn := range fetchFns {
			wg.Add(1)
			go func(f fetchFn) {
				defer wg.Done()
				resp, err := f(ctx, domain, noSubs)
				if err != nil && !errors.Is(err, context.DeadlineExceeded) {
					fmt.Fprintf(os.Stderr, "error fetching %s: %v\n", domain, err)
					return
				}
				for _, r := range resp {
					if noSubs && isSubdomain(r.url, domain) {
						continue
					}
					select {
					case wurls <- r:
					case <-ctx.Done():
						return
					}
				}
			}(fn)
		}

		go func() {
			wg.Wait()
			close(wurls)
		}()

		seen := make(map[string]bool)
		for w := range wurls {
			if seen[w.url] {
				continue
			}
			seen[w.url] = true

			if dates {
				dateStr := parseDate(w.date)
				fmt.Printf("%s %s\n", dateStr, w.url)
			} else {
				fmt.Println(w.url)
			}
		}
	}
}

type wurl struct {
	date string
	url  string
}

type fetchFn func(context.Context, string, bool) ([]wurl, error)

func makeFetchFn(fn func(context.Context, string, bool) ([]wurl, error)) fetchFn {
	return fn
}

func makeFetchFnWithAPIKey(fn func(context.Context, string, bool, string) ([]wurl, error), apiKey string) fetchFn {
	return func(ctx context.Context, domain string, noSubs bool) ([]wurl, error) {
		return fn(ctx, domain, noSubs, apiKey)
	}
}

func getWaybackURLs(ctx context.Context, domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	u, err := url.Parse("https://web.archive.org/cdx/search/cdx")
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("url", fmt.Sprintf("%s%s/*", subsWildcard, domain))
	q.Set("output", "json")
	q.Set("collapse", "urlkey")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	var wrapper [][]string
	if err := json.NewDecoder(res.Body).Decode(&wrapper); err != nil {
		return nil, err
	}

	out := make([]wurl, 0, len(wrapper)-1) // Skip header
	for i, urls := range wrapper {
		if i == 0 { // Skip header
			continue
		}
		if len(urls) < 3 {
			continue
		}
		out = append(out, wurl{date: urls[1], url: urls[2]})
	}

	return out, nil
}

func getCommonCrawlURLs(ctx context.Context, domain string, noSubs bool) ([]wurl, error) {
	subsWildcard := "*."
	if noSubs {
		subsWildcard = ""
	}

	u, err := url.Parse("https://index.commoncrawl.org/CC-MAIN-2018-22-index")
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("url", fmt.Sprintf("%s%s/*", subsWildcard, domain))
	q.Set("output", "json")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	sc := bufio.NewScanner(res.Body)
	out := make([]wurl, 0)

	for sc.Scan() {
		var result struct {
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
		}
		if err := json.Unmarshal(sc.Bytes(), &result); err != nil {
			continue
		}
		out = append(out, wurl{date: result.Timestamp, url: result.URL})
	}

	return out, nil
}

func getVirusTotalURLs(ctx context.Context, domain string, noSubs bool, apiKey string) ([]wurl, error) {
	out := make([]wurl, 0)
	if apiKey == "" {
		return out, nil
	}

	u, err := url.Parse("https://www.virustotal.com/vtapi/v2/domain/report")
	if err != nil {
		return out, err
	}

	q := u.Query()
	q.Set("apikey", apiKey)
	q.Set("domain", domain)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return out, err
	}

	res, err := httpClient.Do(req)
	if err != nil {
		return out, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return out, fmt.Errorf("virustotal request failed with status code: %d", res.StatusCode)
	}

	var wrapper struct {
		URLs []struct {
			URL  string `json:"url"`
			Date string `json:"scan_date"`
		} `json:"detected_urls"`
	}

	if err := json.NewDecoder(res.Body).Decode(&wrapper); err != nil {
		return out, err
	}

	for _, u := range wrapper.URLs {
		out = append(out, wurl{date: u.Date, url: u.URL})
	}

	return out, nil
}

func isSubdomain(rawUrl, domain string) bool {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return false
	}
	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
}

func getVersions(u string) ([]string, error) {
	req, err := http.NewRequest("GET", "https://web.archive.org/cdx/search/cdx", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("url", u)
	q.Add("output", "json")
	req.URL.RawQuery = q.Encode()

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", res.StatusCode)
	}

	var results [][]string
	if err := json.NewDecoder(res.Body).Decode(&results); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var versions []string
	for i, record := range results {
		if i == 0 { // Skip header
			continue
		}
		if len(record) < 6 {
			continue
		}
		if seen[record[5]] { // Digest
			continue
		}
		seen[record[5]] = true
		versions = append(versions, 
			fmt.Sprintf("https://web.archive.org/web/%sif_/%s", record[1], record[2]))
	}
	return versions, nil
}

func parseDate(dateStr string) string {
	if dateStr == "" {
		return ""
	}

	for _, format := range dateFormats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t.Format(time.RFC3339)
		}
	}

	// Try parsing as Unix timestamp
	if ts, err := strconv.ParseFloat(dateStr, 64); err == nil {
		return time.Unix(int64(ts), 0).Format(time.RFC3339)
	}

	return dateStr // Return raw string if all parsing fails
}

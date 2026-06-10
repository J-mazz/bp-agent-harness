// gl-global-search — instance-wide GitLab secret/code search WITHOUT Elasticsearch.
//
// GitLab's global blob search (`GET /api/v4/search?scope=blobs`) requires
// advanced search (Elasticsearch) and returns HTTP 400 otherwise. This tool
// works around that FUNCTIONAL limitation (not a security control) by composing
// authorized PER-PROJECT blob searches into a single global result set.
//
// SAFETY (bug-bounty harness RoE):
//   - Hard host allowlist (default 192.168.122.7). Any other host is REFUSED.
//     There is intentionally NO flag to disable the allowlist.
//   - Redirects to out-of-scope hosts are refused.
//   - Read-only: only HTTP GET is issued. No mutation.
//   - Token read from $GL_TOKEN or --token-file; never printed/logged.
//   - Courteous: small worker pool + per-request delay.
//
// Build: go build -o gl-global-search .
// Run:   GL_TOKEN=$(cat ~/.gl_ro_token) ./gl-global-search --base http://192.168.122.7 --out report.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultPatterns = "PRIVATE KEY,BEGIN OPENSSH,password,secret,api_key,client_secret,access_token,AKIA,glpat-,AWS_SECRET_ACCESS_KEY"

type project struct {
	ID            int    `json:"id"`
	PathNamespace string `json:"path_with_namespace"`
}

type blobHit struct {
	Path      string `json:"path"`
	Basename  string `json:"basename"`
	Ref       string `json:"ref"`
	Startline int    `json:"startline"`
	Data      string `json:"data"`
}

type finding struct {
	ProjectID  int      `json:"project_id"`
	Project    string   `json:"project"`
	Pattern    string   `json:"pattern"`
	Path       string   `json:"path"`
	Ref        string   `json:"ref"`
	Startline  int      `json:"startline"`
	Classified []string `json:"classified"`
	Snippet    string   `json:"snippet"`
}

type report struct {
	Target          string    `json:"target"`
	Generated       string    `json:"generated"`
	Method          string    `json:"method"`
	ProjectsScanned int       `json:"projects_scanned"`
	Patterns        []string  `json:"patterns"`
	RequestsMade    int64     `json:"requests_made"`
	RateLimited     int64     `json:"rate_limited_429"`
	Errors          int64     `json:"errors"`
	Partial         bool      `json:"partial"`
	TotalHits       int       `json:"total_hits"`
	TrueSecretHits  int       `json:"true_secret_hits"`
	Findings        []finding `json:"findings"`
}

var classifiers = []struct {
	name string
	re   *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"gitlab_pat", regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"ssh_priv_key", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`)},
	{"assignment", regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|client_secret|access[_-]?token|token)\s*[:=]\s*['"]?[^'"\s]{6,}`)},
}

func classify(s string) []string {
	var out []string
	for _, c := range classifiers {
		if c.re.MatchString(s) {
			out = append(out, c.name)
		}
	}
	return out
}

func splitCSV(s string) []string {
	var o []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			o = append(o, p)
		}
	}
	return o
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", "\\n"), "\r", "")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func parseRetryAfter(h string) time.Duration {
	if n, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && n > 0 {
		if n > 120 {
			n = 120
		}
		return time.Duration(n) * time.Second
	}
	return 30 * time.Second
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "[gl-global-search] ERROR:", err)
	os.Exit(1)
}

func main() {
	base := flag.String("base", "http://192.168.122.7", "GitLab base URL (host must be in --allow)")
	allowCSV := flag.String("allow", "192.168.122.7", "comma-separated allowlist of permitted hosts (scope guard)")
	tokenFile := flag.String("token-file", os.Getenv("HOME")+"/.gl_ro_token", "file containing the PRIVATE-TOKEN")
	outPath := flag.String("out", "", "write JSON report here (default: stdout)")
	perPage := flag.Int("per-page", 50, "search results per project/pattern")
	concurrency := flag.Int("concurrency", 2, "parallel project workers (search rate limit is per-user/global)")
	rate := flag.Int("rate", 25, "max requests/min shared across workers (GitLab search limit defaults to 30/min)")
	maxRetries := flag.Int("max-retries", 4, "retries on HTTP 429 (honors Retry-After)")
	patternsCSV := flag.String("patterns", defaultPatterns, "comma-separated search terms")
	onlySecrets := flag.Bool("only-secrets", false, "report only classifier-positive (true-secret) hits")
	dryRun := flag.Bool("dry-run", false, "list projects only; issue no search requests")
	flag.Parse()

	u, err := url.Parse(*base)
	if err != nil {
		die(fmt.Errorf("bad --base: %w", err))
	}
	host := u.Hostname()
	allow := splitCSV(*allowCSV)
	if !contains(allow, host) {
		fmt.Fprintf(os.Stderr, "[gl-global-search] REFUSED: host %q not in allowlist %v — scope guard.\n", host, allow)
		os.Exit(2)
	}

	token := strings.TrimSpace(os.Getenv("GL_TOKEN"))
	if token == "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			die(fmt.Errorf("no $GL_TOKEN and cannot read %s: %w", *tokenFile, err))
		}
		token = strings.TrimSpace(string(b))
	}
	if token == "" {
		die(fmt.Errorf("empty token"))
	}

	var limiter <-chan time.Time
	if *rate > 0 {
		limiter = time.Tick(time.Minute / time.Duration(*rate))
	}
	var reqMade, rate429, reqErr int64

	client := &http.Client{
		Timeout: 25 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !contains(allow, req.URL.Hostname()) {
				return fmt.Errorf("refusing redirect to out-of-scope host %q", req.URL.Hostname())
			}
			return nil
		},
	}

	getRaw := func(path string) (int, []byte, error) {
		full := *base + path
		for attempt := 0; ; attempt++ {
			if limiter != nil {
				<-limiter
			}
			req, err := http.NewRequest("GET", full, nil)
			if err != nil {
				return 0, nil, err
			}
			if !contains(allow, req.URL.Hostname()) { // belt & suspenders
				return 0, nil, fmt.Errorf("scope violation: %s", req.URL.Hostname())
			}
			req.Header.Set("PRIVATE-TOKEN", token)
			req.Header.Set("Accept", "application/json")
			req.Header.Set("User-Agent", "gl-global-search/1.0 (authorized lab recon)")
			resp, err := client.Do(req)
			atomic.AddInt64(&reqMade, 1)
			if err != nil {
				atomic.AddInt64(&reqErr, 1)
				return 0, nil, err
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
			status := resp.StatusCode
			retryAfter := resp.Header.Get("Retry-After")
			resp.Body.Close()
			if status == 429 {
				atomic.AddInt64(&rate429, 1)
				if attempt < *maxRetries {
					wait := parseRetryAfter(retryAfter)
					fmt.Fprintf(os.Stderr, "[gl-global-search] 429 on %s — backoff %s (retry %d/%d)\n", path, wait, attempt+1, *maxRetries)
					time.Sleep(wait)
					continue
				}
			}
			return status, body, nil
		}
	}

	// --- enumerate all projects (admin-visible) -------------------------------
	var projects []project
	for page := 1; page <= 100; page++ {
		st, body, err := getRaw(fmt.Sprintf("/api/v4/projects?simple=true&per_page=100&page=%d&order_by=id&sort=asc", page))
		if err != nil {
			die(err)
		}
		if st != 200 {
			fmt.Fprintf(os.Stderr, "[gl-global-search] projects page %d -> HTTP %d (stop)\n", page, st)
			break
		}
		var batch []project
		if err := json.Unmarshal(body, &batch); err != nil {
			die(err)
		}
		if len(batch) == 0 {
			break
		}
		projects = append(projects, batch...)
	}
	fmt.Fprintf(os.Stderr, "[gl-global-search] enumerated %d projects on %s\n", len(projects), host)

	if *dryRun {
		for _, p := range projects {
			fmt.Printf("%d\t%s\n", p.ID, p.PathNamespace)
		}
		return
	}

	patterns := splitCSV(*patternsCSV)
	// --- per-project blob search, aggregated ----------------------------------
	jobs := make(chan project)
	var mu sync.Mutex
	var findings []finding
	var wg sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				for _, pat := range patterns {
					q := url.Values{}
					q.Set("scope", "blobs")
					q.Set("search", pat)
					q.Set("per_page", strconv.Itoa(*perPage))
					st, body, err := getRaw(fmt.Sprintf("/api/v4/projects/%d/search?%s", p.ID, q.Encode()))
					if err != nil || st != 200 {
						continue
					}
					var hits []blobHit
					if json.Unmarshal(body, &hits) != nil {
						continue
					}
					for _, h := range hits {
						cls := classify(h.Data)
						if *onlySecrets && len(cls) == 0 {
							continue
						}
						mu.Lock()
						findings = append(findings, finding{
							ProjectID: p.ID, Project: p.PathNamespace, Pattern: pat,
							Path: h.Path, Ref: h.Ref, Startline: h.Startline,
							Classified: cls, Snippet: clip(h.Data, 160),
						})
						mu.Unlock()
					}
				}
			}
		}()
	}
	for _, p := range projects {
		jobs <- p
	}
	close(jobs)
	wg.Wait()

	trueSecrets := 0
	for _, f := range findings {
		if len(f.Classified) > 0 {
			trueSecrets++
		}
	}

	partial := atomic.LoadInt64(&rate429) > 0 || atomic.LoadInt64(&reqErr) > 0
	rep := report{
		Target:          *base,
		Generated:       time.Now().UTC().Format(time.RFC3339),
		Method:          "per-project blob search composed into global view (no Elasticsearch)",
		ProjectsScanned: len(projects),
		Patterns:        patterns,
		RequestsMade:    atomic.LoadInt64(&reqMade),
		RateLimited:     atomic.LoadInt64(&rate429),
		Errors:          atomic.LoadInt64(&reqErr),
		Partial:         partial,
		TotalHits:       len(findings),
		TrueSecretHits:  trueSecrets,
		Findings:        findings,
	}
	out, _ := json.MarshalIndent(rep, "", "  ")
	if *outPath != "" {
		if err := os.WriteFile(*outPath, out, 0o600); err != nil {
			die(err)
		}
		fmt.Fprintf(os.Stderr, "[gl-global-search] wrote %s\n", *outPath)
	} else {
		fmt.Println(string(out))
	}
	fmt.Fprintf(os.Stderr, "[gl-global-search] projects=%d patterns=%d requests=%d rate_limited=%d errors=%d hits=%d true_secret_hits=%d partial=%v\n",
		len(projects), len(patterns), rep.RequestsMade, rep.RateLimited, rep.Errors, len(findings), trueSecrets, partial)
}

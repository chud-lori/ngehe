package replay

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/chud-lori/ngehe/internal/config"
	"github.com/chud-lori/ngehe/internal/har"
	"github.com/chud-lori/ngehe/internal/session"
)

// Result groups a captured request with every replayed response,
// keyed by session name. The original response is always under "_origin".
type Result struct {
	Req       har.Request
	Responses map[string]Response // session.Name -> response
}

type Response struct {
	Session string
	Status  int
	Body    []byte
	Bytes   int
	MS      int64
}

const OriginKey = "_origin"

// Run replays each request once per session (plus anon if configured).
func Run(reqs []har.Request, sessions []session.Session, cfg *config.Config) ([]Result, error) {
	if cfg.Replay.IncludeAnon {
		sessions = append([]session.Session{session.Anon()}, sessions...)
	}
	client := newClient(cfg.Replay.TimeoutMS)
	maxBody := cfg.Replay.MaxBodyBytes

	type job struct {
		i   int
		sn  int
		req har.Request
		ses session.Session
	}

	var firstAuth session.Session
	for _, s := range sessions {
		if s.Name != session.AnonName {
			firstAuth = s
			break
		}
	}

	baselineFor := make([]string, len(reqs))
	results := make([]Result, len(reqs))
	for i, r := range reqs {
		origStatus, origBody := r.OrigStatus, r.OrigBody
		baselineFor[i] = session.IdentifyBaseline(r.Headers["Authorization"], sessions)
		// Synthesized inputs (OpenAPI) don't carry a baseline response.
		// Fire one upfront so the differ has something to compare against.
		if origStatus == 0 && firstAuth.Name != "" {
			resp := send(client, r, firstAuth, maxBody)
			origStatus, origBody = resp.Status, resp.Body
			if baselineFor[i] == "" {
				baselineFor[i] = firstAuth.Name
			}
		}
		results[i] = Result{
			Req: r,
			Responses: map[string]Response{
				OriginKey: {Session: OriginKey, Status: origStatus, Body: origBody, Bytes: len(origBody)},
			},
		}
	}

	jobs := make(chan job)
	var wg sync.WaitGroup
	conc := cfg.Replay.Concurrency
	if conc < 1 {
		conc = 1
	}

	var mu sync.Mutex
	for w := 0; w < conc; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				resp := send(client, j.req, j.ses, maxBody)
				mu.Lock()
				results[j.i].Responses[j.ses.Name] = resp
				mu.Unlock()
			}
		}()
	}

	for i, r := range reqs {
		for sn, s := range sessions {
			if s.Name == baselineFor[i] {
				continue
			}
			jobs <- job{i: i, sn: sn, req: r, ses: s}
		}
	}
	close(jobs)
	wg.Wait()

	return results, nil
}

func newClient(timeoutMS int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutMS) * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func send(client *http.Client, r har.Request, s session.Session, maxBody int) Response {
	start := time.Now()
	resp := Response{Session: s.Name}

	var body io.Reader
	if len(r.Body) > 0 {
		body = bytes.NewReader(r.Body)
	}
	req, err := http.NewRequest(r.Method, r.URL, body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build request %s %s: %v\n", r.Method, r.URL, err)
		return resp
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	if r.ContentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", r.ContentType)
	}
	s.Apply(req)

	httpResp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "send %s %s as %s: %v\n", r.Method, r.URL, s.Name, err)
		resp.MS = time.Since(start).Milliseconds()
		return resp
	}
	defer httpResp.Body.Close()

	limited := io.LimitReader(httpResp.Body, int64(maxBody)+1)
	b, _ := io.ReadAll(limited)
	resp.Status = httpResp.StatusCode
	resp.Bytes = len(b)
	if len(b) > maxBody {
		b = b[:maxBody]
	}
	resp.Body = b
	resp.MS = time.Since(start).Milliseconds()
	return resp
}

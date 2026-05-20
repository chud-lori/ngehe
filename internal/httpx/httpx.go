// Package httpx is a thin HTTP client wrapper shared by every detector.
package httpx

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"time"
)

func NewClient(timeoutMS int) *http.Client {
	if timeoutMS <= 0 {
		timeoutMS = 10000
	}
	return &http.Client{
		Timeout:   time.Duration(timeoutMS) * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

type Response struct {
	Status  int
	Headers http.Header
	Body    []byte
	MS      int64
}

func Do(client *http.Client, method, url string, headers map[string]string, body []byte, maxBody int) Response {
	start := time.Now()
	var r io.Reader
	if len(body) > 0 {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return Response{MS: time.Since(start).Milliseconds()}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return Response{MS: time.Since(start).Milliseconds()}
	}
	defer resp.Body.Close()
	limit := int64(maxBody)
	if limit <= 0 {
		limit = 256 * 1024
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return Response{
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Body:    b,
		MS:      time.Since(start).Milliseconds(),
	}
}

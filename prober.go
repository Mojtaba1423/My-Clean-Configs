package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type ProbeRequest struct {
	Version        string        `json:"version"`
	Mode           string        `json:"mode"`
	Concurrency    int           `json:"concurrency"`
	TimeoutMS      int           `json:"timeout_ms"`
	Attempts       int           `json:"attempts"`
	TCPAttempts    int           `json:"tcp_attempts"`
	TLSAttempts    int           `json:"tls_attempts"`
	AttemptPauseMS int           `json:"attempt_pause_ms"`
	Targets        []ProbeTarget `json:"targets"`
}

type ProbeTarget struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
	SNI  string `json:"sni"`
}

type ProbeResponse struct {
	Results []ProbeResult `json:"results"`
}

type ProbeResult struct {
	ID        string `json:"id"`
	Host      string `json:"host,omitempty"`
	Port      int    `json:"port,omitempty"`
	SNI       string `json:"sni,omitempty"`
	TCPOk     bool   `json:"tcp_ok"`
	TLSOk     bool   `json:"tls_ok"`
	LatencyMS int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
	TLSError  string `json:"tls_error,omitempty"`
}

func clampConcurrency(n int) int {
	if n <= 0 {
		return 100
	}
	if n > 1000 {
		return 1000
	}
	return n
}

func clampTimeoutMS(n int) int {
	if n <= 0 {
		return 3000
	}
	if n < 500 {
		return 500
	}
	if n > 15000 {
		return 15000
	}
	return n
}

func clampAttempts(n int) int {
	if n <= 0 {
		return 1
	}
	if n > 5 {
		return 5
	}
	return n
}

func clampPauseMS(n int) int {
	if n < 0 {
		return 0
	}
	if n > 3000 {
		return 3000
	}
	return n
}

func readRequest() (ProbeRequest, error) {
	var req ProbeRequest
	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, err
	}

	req.Concurrency = clampConcurrency(req.Concurrency)
	req.TimeoutMS = clampTimeoutMS(req.TimeoutMS)
	req.Attempts = clampAttempts(req.Attempts)
	req.TCPAttempts = clampAttempts(req.TCPAttempts)
	req.TLSAttempts = clampAttempts(req.TLSAttempts)
	req.AttemptPauseMS = clampPauseMS(req.AttemptPauseMS)

	if req.TCPAttempts <= 0 {
		req.TCPAttempts = req.Attempts
	}
	if req.TLSAttempts <= 0 {
		req.TLSAttempts = req.Attempts
	}

	return req, nil
}

func writeResponse(resp ProbeResponse) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(resp)
}

func writeFatal(err error) {
	fmt.Fprintln(os.Stderr, "fatal:", err)
	resp := ProbeResponse{
		Results: []ProbeResult{},
	}
	writeResponse(resp)
}

func firstNonEmpty(parts ...string) string {
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s != "" {
			return s
		}
	}
	return ""
}

func singleAttempt(target ProbeTarget, timeout time.Duration, doTLS bool) ProbeResult {
	result := ProbeResult{
		ID:   target.ID,
		Host: target.Host,
		Port: target.Port,
		SNI:  target.SNI,
	}

	host := strings.TrimSpace(target.Host)
	if host == "" {
		result.Error = "empty_host"
		return result
	}
	if target.Port <= 0 || target.Port > 65535 {
		result.Error = "invalid_port"
		return result
	}

	sni := firstNonEmpty(target.SNI, target.Host)
	address := net.JoinHostPort(host, fmt.Sprintf("%d", target.Port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.TCPOk = true

	if !doTLS {
		result.LatencyMS = time.Since(start).Milliseconds()
		_ = conn.Close()
		return result
	}

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	_ = tlsConn.SetDeadline(time.Now().Add(timeout))
	if err := tlsConn.Handshake(); err != nil {
		result.TLSError = err.Error()
		_ = tlsConn.Close()
		result.LatencyMS = time.Since(start).Milliseconds()
		return result
	}

	result.TLSOk = true
	result.LatencyMS = time.Since(start).Milliseconds()
	_ = tlsConn.Close()
	return result
}

func betterResult(a, b ProbeResult) ProbeResult {
	score := func(r ProbeResult) int {
		s := 0
		if r.TCPOk {
			s += 1
		}
		if r.TLSOk {
			s += 10
		}
		if r.Error == "" {
			s += 1
		}
		if r.TLSError == "" {
			s += 1
		}
		if r.LatencyMS > 0 && r.LatencyMS < 400 {
			s += 2
		}
		return s
	}

	if score(b) > score(a) {
		return b
	}
	if score(b) == score(a) {
		if a.LatencyMS == 0 {
			return b
		}
		if b.LatencyMS > 0 && b.LatencyMS < a.LatencyMS {
			return b
		}
	}
	return a
}

func probeTarget(req ProbeRequest, target ProbeTarget) ProbeResult {
	result := ProbeResult{
		ID:   target.ID,
		Host: target.Host,
		Port: target.Port,
		SNI:  firstNonEmpty(target.SNI, target.Host),
	}

	host := strings.TrimSpace(target.Host)
	if host == "" {
		result.Error = "empty_host"
		return result
	}
	if target.Port <= 0 || target.Port > 65535 {
		result.Error = "invalid_port"
		return result
	}

	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	pause := time.Duration(req.AttemptPauseMS) * time.Millisecond

	bestTCP := ProbeResult{
		ID:   target.ID,
		Host: target.Host,
		Port: target.Port,
		SNI:  firstNonEmpty(target.SNI, target.Host),
	}
	for i := 0; i < req.TCPAttempts; i++ {
		r := singleAttempt(target, timeout, false)
		bestTCP = betterResult(bestTCP, r)
		if r.TCPOk {
			break
		}
		if pause > 0 && i+1 < req.TCPAttempts {
			time.Sleep(pause)
		}
	}

	if !bestTCP.TCPOk {
		return bestTCP
	}

	bestTLS := bestTCP
	for i := 0; i < req.TLSAttempts; i++ {
		r := singleAttempt(target, timeout, true)
		bestTLS = betterResult(bestTLS, r)
		if r.TLSOk {
			break
		}
		if pause > 0 && i+1 < req.TLSAttempts {
			time.Sleep(pause)
		}
	}

	return bestTLS
}

func worker(req ProbeRequest, jobs <-chan ProbeTarget, results chan<- ProbeResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range jobs {
		results <- probeTarget(req, target)
	}
}

func main() {
	req, err := readRequest()
	if err != nil {
		writeFatal(err)
		return
	}

	if len(req.Targets) == 0 {
		writeResponse(ProbeResponse{Results: []ProbeResult{}})
		return
	}

	jobs := make(chan ProbeTarget)
	results := make(chan ProbeResult, len(req.Targets))

	var wg sync.WaitGroup
	for i := 0; i < req.Concurrency; i++ {
		wg.Add(1)
		go worker(req, jobs, results, &wg)
	}

	go func() {
		for _, t := range req.Targets {
			jobs <- t
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	out := ProbeResponse{
		Results: make([]ProbeResult, 0, len(req.Targets)),
	}
	for r := range results {
		out.Results = append(out.Results, r)
	}

	writeResponse(out)
}

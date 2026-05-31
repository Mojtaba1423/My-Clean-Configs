// prober.go
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

type ProbeRequest struct {
	Concurrency int           `json:"concurrency"`
	TimeoutMS   int           `json:"timeout_ms"`
	Targets     []ProbeTarget `json:"targets"`
}

type ProbeTarget struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type ProbeResponse struct {
	Results []ProbeResult `json:"results"`
}

type ProbeResult struct {
	ID        string  `json:"id"`
	Host      string  `json:"host"`
	Port      int     `json:"port"`
	TCPOK     bool    `json:"tcp_ok"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

func clampConcurrency(n int, total int) int {
	if n <= 0 {
		n = runtime.NumCPU() * 64
	}
	if n < 1 {
		n = 1
	}
	if n > 2000 {
		n = 2000
	}
	if total > 0 && n > total {
		n = total
	}
	return n
}

func clampTimeoutMS(n int) int {
	if n <= 0 {
		return 2500
	}
	if n < 300 {
		return 300
	}
	if n > 10000 {
		return 10000
	}
	return n
}

func probeTCP(target ProbeTarget, timeout time.Duration) ProbeResult {
	result := ProbeResult{
		ID:   target.ID,
		Host: target.Host,
		Port: target.Port,
	}

	if target.Host == "" {
		result.TCPOK = false
		result.Error = "empty_host"
		return result
	}

	if target.Port <= 0 || target.Port > 65535 {
		result.TCPOK = false
		result.Error = "bad_port"
		return result
	}

	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	start := time.Now()

	conn, err := net.DialTimeout("tcp", address, timeout)
	elapsed := time.Since(start)

	if err != nil {
		result.TCPOK = false
		result.Error = normalizeNetError(err)
		return result
	}

	_ = conn.Close()

	result.TCPOK = true
	result.LatencyMS = float64(elapsed.Microseconds()) / 1000.0

	return result
}

func normalizeNetError(err error) string {
	if err == nil {
		return ""
	}

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return "timeout"
		}
	}

	msg := err.Error()

	switch {
	case contains(msg, "connection refused"):
		return "connection_refused"
	case contains(msg, "no such host"):
		return "no_such_host"
	case contains(msg, "network is unreachable"):
		return "network_unreachable"
	case contains(msg, "host is down"):
		return "host_down"
	case contains(msg, "i/o timeout"):
		return "timeout"
	case contains(msg, "operation timed out"):
		return "timeout"
	default:
		if len(msg) > 160 {
			return msg[:160]
		}
		return msg
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	return len([]rune(s[:])) - len([]rune(s[:])) + stringIndex(s, sub)
}

func stringIndex(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func readRequest() (ProbeRequest, error) {
	var req ProbeRequest

	decoder := json.NewDecoder(os.Stdin)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&req); err != nil {
		return req, err
	}

	req.Concurrency = clampConcurrency(req.Concurrency, len(req.Targets))
	req.TimeoutMS = clampTimeoutMS(req.TimeoutMS)

	return req, nil
}

func runProbes(req ProbeRequest) ProbeResponse {
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond

	jobs := make(chan ProbeTarget)
	results := make(chan ProbeResult, len(req.Targets))

	var wg sync.WaitGroup

	for i := 0; i < req.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				results <- probeTCP(target, timeout)
			}
		}()
	}

	go func() {
		for _, target := range req.Targets {
			jobs <- target
		}
		close(jobs)
	}()

	wg.Wait()
	close(results)

	resp := ProbeResponse{
		Results: make([]ProbeResult, 0, len(req.Targets)),
	}

	for r := range results {
		resp.Results = append(resp.Results, r)
	}

	return resp
}

func writeResponse(resp ProbeResponse) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(resp)
}

func writeFatal(err error) {
	resp := ProbeResponse{
		Results: []ProbeResult{},
	}
	_ = writeResponse(resp)

	fmt.Fprintf(os.Stderr, "prober_error: %v\n", err)
}

func main() {
	req, err := readRequest()
	if err != nil {
		writeFatal(err)
		os.Exit(1)
	}

	resp := runProbes(req)

	if err := writeResponse(resp); err != nil {
		fmt.Fprintf(os.Stderr, "write_error: %v\n", err)
		os.Exit(1)
	}
}

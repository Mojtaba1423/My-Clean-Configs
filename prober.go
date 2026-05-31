package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type ProbeRequest struct {
	Version     string        `json:"version,omitempty"`
	Mode        string        `json:"mode,omitempty"`
	Concurrency int           `json:"concurrency"`
	TimeoutMS   int           `json:"timeout_ms"`
	Targets     []ProbeTarget `json:"targets"`
}

type ProbeTarget struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	Port int    `json:"port"`
	SNI  string `json:"sni,omitempty"`
}

type ProbeResponse struct {
	Results []ProbeResult `json:"results"`
}

type ProbeResult struct {
	ID           string  `json:"id"`
	Host         string  `json:"host"`
	Port         int     `json:"port"`
	TCPOK        bool    `json:"tcp_ok"`
	TCPLatencyMS float64 `json:"tcp_latency_ms,omitempty"`
	TLSOK        bool    `json:"tls_ok"`
	TLSLatencyMS float64 `json:"tls_latency_ms,omitempty"`
	Error        string  `json:"error,omitempty"`
	TLSError     string  `json:"tls_error,omitempty"`
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

func splitTimeouts(total time.Duration) (time.Duration, time.Duration) {
	if total <= 0 {
		total = 2500 * time.Millisecond
	}

	tcpTimeout := total / 2
	tlsTimeout := total - tcpTimeout

	minPart := 250 * time.Millisecond

	if tcpTimeout < minPart {
		tcpTimeout = minPart
	}
	if tlsTimeout < minPart {
		tlsTimeout = minPart
	}

	return tcpTimeout, tlsTimeout
}

func probeTarget(target ProbeTarget, totalTimeout time.Duration) ProbeResult {
	result := ProbeResult{
		ID:   target.ID,
		Host: target.Host,
		Port: target.Port,
	}

	if target.Host == "" {
		result.TCPOK = false
		result.TLSOK = false
		result.Error = "empty_host"
		return result
	}

	if target.Port <= 0 || target.Port > 65535 {
		result.TCPOK = false
		result.TLSOK = false
		result.Error = "bad_port"
		return result
	}

	sni := strings.TrimSpace(target.SNI)
	if sni == "" {
		result.TCPOK = false
		result.TLSOK = false
		result.Error = "empty_sni"
		return result
	}

	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	tcpTimeout, tlsTimeout := splitTimeouts(totalTimeout)

	tcpStart := time.Now()
	rawConn, err := net.DialTimeout("tcp", address, tcpTimeout)
	tcpElapsed := time.Since(tcpStart)

	if err != nil {
		result.TCPOK = false
		result.TLSOK = false
		result.Error = normalizeNetError(err)
		return result
	}

	result.TCPOK = true
	result.TCPLatencyMS = float64(tcpElapsed.Microseconds()) / 1000.0

	_ = rawConn.SetDeadline(time.Now().Add(tlsTimeout))

	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)

	tlsStart := time.Now()
	err = tlsConn.Handshake()
	tlsElapsed := time.Since(tlsStart)

	if err != nil {
		result.TLSOK = false
		result.TLSError = normalizeTLSError(err)
		_ = tlsConn.Close()
		return result
	}

	result.TLSOK = true
	result.TLSLatencyMS = float64(tlsElapsed.Microseconds()) / 1000.0

	_ = tlsConn.Close()
	return result
}

func normalizeNetError(err error) string {
	if err == nil {
		return ""
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "timeout"
	}

	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "connection refused"):
		return "connection_refused"
	case strings.Contains(msg, "no such host"):
		return "no_such_host"
	case strings.Contains(msg, "network is unreachable"):
		return "network_unreachable"
	case strings.Contains(msg, "host is down"):
		return "host_down"
	case strings.Contains(msg, "i/o timeout"):
		return "timeout"
	case strings.Contains(msg, "operation timed out"):
		return "timeout"
	default:
		if len(msg) > 160 {
			return msg[:160]
		}
		return msg
	}
}

func normalizeTLSError(err error) string {
	if err == nil {
		return ""
	}

	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return "tls_timeout"
	}

	msg := strings.ToLower(err.Error())

	switch {
	case strings.Contains(msg, "handshake failure"):
		return "tls_handshake_failure"
	case strings.Contains(msg, "first record does not look like a tls handshake"):
		return "not_tls"
	case strings.Contains(msg, "protocol version not supported"):
		return "tls_version_unsupported"
	case strings.Contains(msg, "remote error: tls: internal error"):
		return "tls_internal_error"
	case strings.Contains(msg, "remote error: tls: unrecognized name"):
		return "tls_unrecognized_name"
	case strings.Contains(msg, "unexpected eof"):
		return "tls_unexpected_eof"
	case strings.Contains(msg, "eof"):
		return "tls_eof"
	case strings.Contains(msg, "i/o timeout"):
		return "tls_timeout"
	default:
		if len(msg) > 160 {
			return msg[:160]
		}
		return msg
	}
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
				results <- probeTarget(target, timeout)
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

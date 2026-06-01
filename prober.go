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
	Version        string        `json:"version,omitempty"`
	Mode           string        `json:"mode,omitempty"`
	Concurrency    int           `json:"concurrency"`
	TimeoutMS      int           `json:"timeout_ms"`
	Attempts       int           `json:"attempts,omitempty"`
	TCPAttempts    int           `json:"tcp_attempts,omitempty"`
	TLSAttempts    int           `json:"tls_attempts,omitempty"`
	AttemptPauseMS int           `json:"attempt_pause_ms,omitempty"`
	Targets        []ProbeTarget `json:"targets"`
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

	TCPAttempts  int `json:"tcp_attempts,omitempty"`
	TCPSuccesses int `json:"tcp_successes,omitempty"`
	TLSAttempts  int `json:"tls_attempts,omitempty"`
	TLSSuccesses int `json:"tls_successes,omitempty"`

	Error    string `json:"error,omitempty"`
	TLSError string `json:"tls_error,omitempty"`
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
	if n > 2000 {
		return 2000
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

func singleAttempt(target ProbeTarget, totalTimeout time.Duration) ProbeResult {
	result := ProbeResult{
		ID:   target.ID,
		Host: target.Host,
		Port: target.Port,
	}

	if target.Host == "" {
		result.Error = "empty_host"
		return result
	}
	if target.Port <= 0 || target.Port > 65535 {
		result.Error = "bad_port"
		return result
	}

	sni := strings.TrimSpace(target.SNI)
	if sni == "" {
		result.Error = "empty_sni"
		return result
	}

	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	tcpTimeout, tlsTimeout := splitTimeouts(totalTimeout)

	tcpStart := time.Now()
	rawConn, err := net.DialTimeout("tcp", address, tcpTimeout)
	tcpElapsed := time.Since(tcpStart)

	if err != nil {
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
		result.TLSError = normalizeTLSError(err)
		_ = tlsConn.Close()
		return result
	}

	result.TLSOK = true
	result.TLSLatencyMS = float64(tlsElapsed.Microseconds()) / 1000.0

	_ = tlsConn.Close()
	return result
}

func probeTarget(target ProbeTarget, totalTimeout time.Duration, tcpAttempts int, tlsAttempts int, pause time.Duration) ProbeResult {
	result := ProbeResult{
		ID:   target.ID,
		Host: target.Host,
		Port: target.Port,
	}

	if target.Host == "" {
		result.Error = "empty_host"
		return result
	}
	if target.Port <= 0 || target.Port > 65535 {
		result.Error = "bad_port"
		return result
	}
	if strings.TrimSpace(target.SNI) == "" {
		result.Error = "empty_sni"
		return result
	}

	if tcpAttempts < 1 {
		tcpAttempts = 1
	}
	if tlsAttempts < 1 {
		tlsAttempts = 1
	}

	var bestTCPLat *float64
	var bestTLSLat *float64
	var lastNetErr string
	var lastTLSErr string

	// TCP/TLS are measured together per attempt,
	// but success accounting is separated so caller gets ratios.
	maxAttempts := tcpAttempts
	if tlsAttempts > maxAttempts {
		maxAttempts = tlsAttempts
	}

	for i := 0; i < maxAttempts; i++ {
		r := singleAttempt(target, totalTimeout)

		if i < tcpAttempts {
			result.TCPAttempts++
			if r.TCPOK {
				result.TCPSuccesses++
				result.TCPOK = true
				if bestTCPLat == nil || r.TCPLatencyMS < *bestTCPLat {
					v := r.TCPLatencyMS
					bestTCPLat = &v
				}
			} else if r.Error != "" {
				lastNetErr = r.Error
			}
		}

		if i < tlsAttempts {
			result.TLSAttempts++
			if r.TLSOK {
				result.TLSSuccesses++
				result.TLSOK = true
				if bestTLSLat == nil || r.TLSLatencyMS < *bestTLSLat {
					v := r.TLSLatencyMS
					bestTLSLat = &v
				}
			} else if r.TLSError != "" {
				lastTLSErr = r.TLSError
			}
		}

		if pause > 0 && i+1 < maxAttempts {
			time.Sleep(pause)
		}
	}

	if bestTCPLat != nil {
		result.TCPLatencyMS = *bestTCPLat
	}
	if bestTLSLat != nil {
		result.TLSLatencyMS = *bestTLSLat
	}

	if !result.TCPOK && lastNetErr != "" {
		result.Error = lastNetErr
	}
	if !result.TLSOK && lastTLSErr != "" {
		result.TLSError = lastTLSErr
	}

	return result
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
	if req.Attempts <= 0 {
		req.Attempts = 1
	}
	if req.TCPAttempts <= 0 {
		req.TCPAttempts = 1
	}
	if req.TLSAttempts <= 0 {
		req.TLSAttempts = 1
	}

	return req, nil
}

func runProbes(req ProbeRequest) ProbeResponse {
	timeout := time.Duration(req.TimeoutMS) * time.Millisecond
	pause := time.Duration(req.AttemptPauseMS) * time.Millisecond

	jobs := make(chan ProbeTarget)
	results := make(chan ProbeResult, len(req.Targets))

	var wg sync.WaitGroup

	for i := 0; i < req.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				results <- probeTarget(target, timeout, req.TCPAttempts, req.TLSAttempts, pause)
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

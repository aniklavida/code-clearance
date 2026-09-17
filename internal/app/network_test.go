package app

import (
	"context"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
)

// Constraint 3: No source code leaves the machine under the default configuration.
// Assert this with a test that fails if a default-configured run opens a network connection.

type monitoringRoundTripper struct {
	attempts *int32
}

func (m *monitoringRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(m.attempts, 1)
	return nil, net.UnknownNetworkError("network blocked by security guard")
}

func TestDefaultScan_OpensNoNetworkConnection(t *testing.T) {
	// 1. Start a honeypot TCP listener
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	honeypotAddr := ln.Addr().String()
	var connectionAttempts int32

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt32(&connectionAttempts, 1)
			_ = conn.Close()
		}
	}()

	// 2. Set proxy environment variables so any child process attempting outbound HTTP
	// routes directly to the honeypot listener
	origHTTPProxy := os.Getenv("HTTP_PROXY")
	origHTTPSProxy := os.Getenv("HTTPS_PROXY")
	origAllProxy := os.Getenv("ALL_PROXY")
	origHttpProxyLower := os.Getenv("http_proxy")
	origHttpsProxyLower := os.Getenv("https_proxy")

	proxyURL := "http://" + honeypotAddr
	t.Setenv("HTTP_PROXY", proxyURL)
	t.Setenv("HTTPS_PROXY", proxyURL)
	t.Setenv("ALL_PROXY", proxyURL)
	t.Setenv("http_proxy", proxyURL)
	t.Setenv("https_proxy", proxyURL)

	defer func() {
		os.Setenv("HTTP_PROXY", origHTTPProxy)
		os.Setenv("HTTPS_PROXY", origHTTPSProxy)
		os.Setenv("ALL_PROXY", origAllProxy)
		os.Setenv("http_proxy", origHttpProxyLower)
		os.Setenv("https_proxy", origHttpsProxyLower)
	}()

	// 3. Monitor Go-level http.DefaultTransport
	origTransport := http.DefaultTransport
	var httpAttempts int32
	http.DefaultTransport = &monitoringRoundTripper{attempts: &httpAttempts}
	defer func() {
		http.DefaultTransport = origTransport
	}()

	// 4. Run default-configured scan on a test repo
	dir := initTestGitRepo(t)
	engine := NewEngine()

	report, err := engine.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("engine.Scan failed: %v", err)
	}

	if report.SchemaVersion == "" {
		t.Fatal("empty report returned")
	}

	// 5. Assert NO network connections were made
	if attempts := atomic.LoadInt32(&connectionAttempts); attempts > 0 {
		t.Fatalf("SECURITY VIOLATION: default-configured scan opened %d network connection(s) to honeypot!", attempts)
	}
	if httpCalls := atomic.LoadInt32(&httpAttempts); httpCalls > 0 {
		t.Fatalf("SECURITY VIOLATION: default-configured scan made %d outbound HTTP request(s)!", httpCalls)
	}
}

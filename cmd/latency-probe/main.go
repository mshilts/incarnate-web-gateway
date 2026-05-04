package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ",")
}

func (h *headerFlags) Set(value string) error {
	if !strings.Contains(value, ":") {
		return fmt.Errorf("header must be in Name: value form")
	}
	*h = append(*h, value)
	return nil
}

type probeConfig struct {
	gatewayURL        string
	baselineURL       string
	method            string
	body              []byte
	headers           http.Header
	requests          int
	warmup            int
	concurrency       int
	timeout           time.Duration
	expectStatus      int
	disableKeepAlives bool
	jsonOutput        bool
}

type sample struct {
	duration time.Duration
	status   int
	err      error
}

type targetResult struct {
	Name         string
	URL          string
	Requests     int
	Errors       int
	StatusCounts map[int]int
	ErrorCounts  map[string]int
	Stats        latencyStats
}

type latencyStats struct {
	Count  int     `json:"count"`
	MinMS  float64 `json:"minMs"`
	MeanMS float64 `json:"meanMs"`
	P50MS  float64 `json:"p50Ms"`
	P90MS  float64 `json:"p90Ms"`
	P95MS  float64 `json:"p95Ms"`
	P99MS  float64 `json:"p99Ms"`
	MaxMS  float64 `json:"maxMs"`
}

type report struct {
	Method      string        `json:"method"`
	Requests    int           `json:"requests"`
	Warmup      int           `json:"warmup"`
	Concurrency int           `json:"concurrency"`
	TimeoutMS   float64       `json:"timeoutMs"`
	Baseline    *targetResult `json:"baseline,omitempty"`
	Gateway     targetResult  `json:"gateway"`
	Delta       *deltaReport  `json:"delta,omitempty"`
}

type deltaReport struct {
	P50MS       float64 `json:"p50Ms"`
	P50Percent  float64 `json:"p50Percent"`
	P95MS       float64 `json:"p95Ms"`
	P95Percent  float64 `json:"p95Percent"`
	P99MS       float64 `json:"p99Ms"`
	P99Percent  float64 `json:"p99Percent"`
	MeanMS      float64 `json:"meanMs"`
	MeanPercent float64 `json:"meanPercent"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var headers headerFlags
	cfg := probeConfig{}
	fs := flag.NewFlagSet("latency-probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.gatewayURL, "gateway", "", "gateway URL to measure")
	fs.StringVar(&cfg.baselineURL, "baseline", "", "optional baseline URL to subtract from gateway latency")
	fs.StringVar(&cfg.method, "method", http.MethodGet, "HTTP method")
	fs.String("body", "", "request body")
	fs.Var(&headers, "header", "request header in Name: value form; repeatable")
	fs.IntVar(&cfg.requests, "requests", 200, "measured requests per target")
	fs.IntVar(&cfg.requests, "n", 200, "alias for -requests")
	fs.IntVar(&cfg.warmup, "warmup", 20, "warmup requests per target before measurement")
	fs.IntVar(&cfg.concurrency, "concurrency", 1, "concurrent requests")
	fs.DurationVar(&cfg.timeout, "timeout", 5*time.Second, "per-request timeout")
	fs.IntVar(&cfg.expectStatus, "expect-status", 0, "expected HTTP status; 0 accepts any status")
	fs.BoolVar(&cfg.disableKeepAlives, "disable-keepalive", false, "disable HTTP keep-alives")
	fs.BoolVar(&cfg.jsonOutput, "json", false, "emit JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	body := fs.Lookup("body").Value.String()
	cfg.body = []byte(body)
	var err error
	cfg.headers, err = parseHeaders(headers)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid headers: %v\n", err)
		return 2
	}
	if err := validateConfig(cfg); err != nil {
		_, _ = fmt.Fprintf(stderr, "invalid probe config: %v\n", err)
		return 2
	}

	rep, err := measure(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "latency probe failed: %v\n", err)
		return 1
	}
	if cfg.jsonOutput {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(rep); err != nil {
			_, _ = fmt.Fprintf(stderr, "write report: %v\n", err)
			return 1
		}
	} else {
		writeTextReport(stdout, rep)
	}
	if rep.Gateway.Errors > 0 || (rep.Baseline != nil && rep.Baseline.Errors > 0) {
		return 1
	}
	return 0
}

func validateConfig(cfg probeConfig) error {
	if cfg.gatewayURL == "" {
		return errors.New("-gateway is required")
	}
	for label, rawURL := range map[string]string{"gateway": cfg.gatewayURL, "baseline": cfg.baselineURL} {
		if rawURL == "" {
			continue
		}
		parsed, err := url.ParseRequestURI(rawURL)
		if err != nil {
			return fmt.Errorf("%s URL: %w", label, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("%s URL must use http or https", label)
		}
	}
	if strings.TrimSpace(cfg.method) == "" {
		return errors.New("method is required")
	}
	if cfg.requests <= 0 {
		return errors.New("requests must be positive")
	}
	if cfg.warmup < 0 {
		return errors.New("warmup must be zero or positive")
	}
	if cfg.concurrency <= 0 {
		return errors.New("concurrency must be positive")
	}
	if cfg.timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if cfg.expectStatus < 0 || cfg.expectStatus > 999 {
		return errors.New("expect-status must be between 0 and 999")
	}
	return nil
}

func parseHeaders(values []string) (http.Header, error) {
	header := make(http.Header)
	for _, value := range values {
		name, rawValue, ok := strings.Cut(value, ":")
		if !ok {
			return nil, fmt.Errorf("%q must be in Name: value form", value)
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("%q has an empty header name", value)
		}
		header.Add(name, strings.TrimSpace(rawValue))
	}
	return header, nil
}

func measure(cfg probeConfig) (report, error) {
	rep := report{
		Method:      cfg.method,
		Requests:    cfg.requests,
		Warmup:      cfg.warmup,
		Concurrency: cfg.concurrency,
		TimeoutMS:   ms(cfg.timeout),
	}
	if cfg.baselineURL != "" {
		baseline, err := measureTarget(cfg, "baseline", cfg.baselineURL)
		if err != nil {
			return report{}, err
		}
		rep.Baseline = &baseline
	}
	gateway, err := measureTarget(cfg, "gateway", cfg.gatewayURL)
	if err != nil {
		return report{}, err
	}
	rep.Gateway = gateway
	if rep.Baseline != nil {
		rep.Delta = calculateDelta(rep.Baseline.Stats, rep.Gateway.Stats)
	}
	return rep, nil
}

func measureTarget(cfg probeConfig, name, rawURL string) (targetResult, error) {
	client := &http.Client{
		Timeout: cfg.timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        max(100, cfg.concurrency),
			MaxIdleConnsPerHost: max(100, cfg.concurrency),
			DisableKeepAlives:   cfg.disableKeepAlives,
		},
	}
	for i := 0; i < cfg.warmup; i++ {
		if got := probeOnce(client, cfg, rawURL); got.err != nil {
			return targetResult{}, fmt.Errorf("%s warmup request failed: %w", name, got.err)
		}
	}

	samples := make(chan sample, cfg.requests)
	jobs := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				samples <- probeOnce(client, cfg, rawURL)
			}
		}()
	}
	for i := 0; i < cfg.requests; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
	close(samples)

	result := targetResult{
		Name:         name,
		URL:          rawURL,
		Requests:     cfg.requests,
		StatusCounts: make(map[int]int),
		ErrorCounts:  make(map[string]int),
	}
	durations := make([]time.Duration, 0, cfg.requests)
	for got := range samples {
		if got.status != 0 {
			result.StatusCounts[got.status]++
		}
		if got.duration > 0 {
			durations = append(durations, got.duration)
		}
		if got.err != nil {
			result.Errors++
			result.ErrorCounts[got.err.Error()]++
		}
	}
	if len(durations) == 0 {
		return targetResult{}, fmt.Errorf("%s produced no measured responses", name)
	}
	result.Stats = summarize(durations)
	return result, nil
}

func probeOnce(client *http.Client, cfg probeConfig, rawURL string) sample {
	var body io.Reader
	if len(cfg.body) > 0 {
		body = bytes.NewReader(cfg.body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, cfg.method, rawURL, body)
	if err != nil {
		return sample{err: err}
	}
	for name, values := range cfg.headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample{duration: time.Since(start), err: err}
	}
	defer resp.Body.Close()
	_, readErr := io.Copy(io.Discard, resp.Body)
	duration := time.Since(start)
	if readErr != nil {
		return sample{duration: duration, status: resp.StatusCode, err: readErr}
	}
	if cfg.expectStatus != 0 && resp.StatusCode != cfg.expectStatus {
		return sample{
			duration: duration,
			status:   resp.StatusCode,
			err:      fmt.Errorf("status %d, want %d", resp.StatusCode, cfg.expectStatus),
		}
	}
	return sample{duration: duration, status: resp.StatusCode}
}

func summarize(values []time.Duration) latencyStats {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	var total time.Duration
	for _, value := range values {
		total += value
	}
	return latencyStats{
		Count:  len(values),
		MinMS:  ms(values[0]),
		MeanMS: ms(total / time.Duration(len(values))),
		P50MS:  ms(percentile(values, 50)),
		P90MS:  ms(percentile(values, 90)),
		P95MS:  ms(percentile(values, 95)),
		P99MS:  ms(percentile(values, 99)),
		MaxMS:  ms(values[len(values)-1]),
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil((p/100)*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func calculateDelta(baseline, gateway latencyStats) *deltaReport {
	return &deltaReport{
		P50MS:       gateway.P50MS - baseline.P50MS,
		P50Percent:  percentDelta(baseline.P50MS, gateway.P50MS),
		P95MS:       gateway.P95MS - baseline.P95MS,
		P95Percent:  percentDelta(baseline.P95MS, gateway.P95MS),
		P99MS:       gateway.P99MS - baseline.P99MS,
		P99Percent:  percentDelta(baseline.P99MS, gateway.P99MS),
		MeanMS:      gateway.MeanMS - baseline.MeanMS,
		MeanPercent: percentDelta(baseline.MeanMS, gateway.MeanMS),
	}
}

func percentDelta(baseline, gateway float64) float64 {
	if baseline == 0 {
		return 0
	}
	return ((gateway - baseline) / baseline) * 100
}

func writeTextReport(w io.Writer, rep report) {
	_, _ = fmt.Fprintf(w, "method=%s requests=%d warmup=%d concurrency=%d timeout=%.3fms\n", rep.Method, rep.Requests, rep.Warmup, rep.Concurrency, rep.TimeoutMS)
	if rep.Baseline != nil {
		writeTarget(w, *rep.Baseline)
	}
	writeTarget(w, rep.Gateway)
	if rep.Delta != nil {
		_, _ = fmt.Fprintf(w, "delta gateway-baseline:\n")
		_, _ = fmt.Fprintf(w, "  mean=%+.3fms (%+.1f%%) p50=%+.3fms (%+.1f%%) p95=%+.3fms (%+.1f%%) p99=%+.3fms (%+.1f%%)\n",
			rep.Delta.MeanMS, rep.Delta.MeanPercent,
			rep.Delta.P50MS, rep.Delta.P50Percent,
			rep.Delta.P95MS, rep.Delta.P95Percent,
			rep.Delta.P99MS, rep.Delta.P99Percent,
		)
	}
}

func writeTarget(w io.Writer, result targetResult) {
	_, _ = fmt.Fprintf(w, "%s %s:\n", result.Name, result.URL)
	_, _ = fmt.Fprintf(w, "  responses=%d errors=%d statuses=%s\n", result.Stats.Count, result.Errors, formatStatusCounts(result.StatusCounts))
	_, _ = fmt.Fprintf(w, "  min=%.3fms mean=%.3fms p50=%.3fms p90=%.3fms p95=%.3fms p99=%.3fms max=%.3fms\n",
		result.Stats.MinMS,
		result.Stats.MeanMS,
		result.Stats.P50MS,
		result.Stats.P90MS,
		result.Stats.P95MS,
		result.Stats.P99MS,
		result.Stats.MaxMS,
	)
	if len(result.ErrorCounts) > 0 {
		_, _ = fmt.Fprintf(w, "  errors=%v\n", result.ErrorCounts)
	}
}

func formatStatusCounts(counts map[int]int) string {
	if len(counts) == 0 {
		return "{}"
	}
	statuses := make([]int, 0, len(counts))
	for status := range counts {
		statuses = append(statuses, status)
	}
	sort.Ints(statuses)
	parts := make([]string, 0, len(statuses))
	for _, status := range statuses {
		parts = append(parts, fmt.Sprintf("%d:%d", status, counts[status]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

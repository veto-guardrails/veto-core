package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type inferReq struct {
	Text string `json:"text"`
}

type inferResp struct {
	Injection float64 `json:"injection"`
	Label     string  `json:"label"`
}

// inferClient — defense-in-depth on top of the per-call context timeout.
// Bounds total request duration and idle keepalive lifetime so a misbehaving
// inference service can't starve the gateway of connections.
var inferClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        16,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
	},
}

// detectInjection returns findings + the wall-clock time spent waiting on
// the inference service. The caller (handleCheck) attributes that time to
// the metering event's inference_ms field so we can separate ML cost from
// gateway overhead.
func detectInjection(ctx context.Context, text string) ([]Finding, time.Duration, error) {
	start := time.Now()
	body, err := json.Marshal(inferReq{Text: text})
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("marshal infer req: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", inferenceURL+"/detect/injection", bytes.NewReader(body))
	if err != nil {
		return nil, time.Since(start), err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := inferClient.Do(req)
	if err != nil {
		return nil, time.Since(start), err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, time.Since(start), fmt.Errorf("inference status %d", resp.StatusCode)
	}
	var r inferResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, time.Since(start), err
	}
	if r.Injection < 0.5 {
		return nil, time.Since(start), nil
	}
	sev := "medium"
	if r.Injection > 0.8 {
		sev = "high"
	}
	return []Finding{{
		Category: "injection",
		Rule:     "ml_injection_classifier",
		Severity: sev,
		Score:    r.Injection,
	}}, time.Since(start), nil
}

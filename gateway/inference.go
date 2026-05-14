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

func detectInjection(ctx context.Context, text string) ([]Finding, error) {
	body, _ := json.Marshal(inferReq{Text: text})
	req, err := http.NewRequestWithContext(ctx, "POST", inferenceURL+"/detect/injection", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := inferClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inference status %d", resp.StatusCode)
	}
	var r inferResp
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.Injection < 0.5 {
		return nil, nil
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
	}}, nil
}

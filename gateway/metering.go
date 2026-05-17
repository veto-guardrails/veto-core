package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// streamKey — single Redis stream the gateway writes to and the cloud
// aggregator reads from. Two consumers (Stripe meter ship + usage analytics
// rollups) read the same stream via different consumer groups.
const streamKey = "events:requests"

// streamMaxLen caps the stream so a stalled aggregator can't grow Redis
// without bound. Approx-trim (~) keeps XADD O(1).
const streamMaxLen int64 = 1_000_000

// queueCapacity bounds the in-process buffer between request handlers and
// the Redis writer. On overflow we drop and log loud — never block /v1/check.
const queueCapacity = 4096

// xaddTimeout — Redis call must finish quickly; a stalled Redis cannot be
// allowed to back up the worker indefinitely.
const xaddTimeout = 1 * time.Second

// Event mirrors SPEC §4.14's normative collected-fields list. Anything not
// on that list does not get emitted — no prompt text, no redacted output,
// no finding match substrings. Read §4.14 before adding a field.
type Event struct {
	OrgID       string
	ProjectID   string
	KeyID       string
	Action      string
	Categories  []string
	Rules       []string
	// Pairs is the (rule, category) tuples that fired, deduped on Rule.
	// Equivalent in content to (Rules, Categories) but preserves the
	// rule→category mapping the analytics rollup needs.
	Pairs       []FindingPair
	LatencyMs   float64
	InferenceMs float64
	Status      int
	BytesIn     int
	BytesOut    int
}

// FindingPair is one (rule, category) tuple. Encoded on the wire as
// "rule:category"; the aggregator splits on the first colon. Rule and
// category names are constrained to the catalog (rules.go), neither
// contains ':' or ',' so no escaping is needed.
type FindingPair struct {
	Rule     string
	Category string
}

type Metering struct {
	rdb    *redis.Client
	region string
	ch     chan Event
}

// newMetering opens its OWN Redis connection — separate from Lookup's so
// the metering pool, timeouts and (eventually) metrics are scoped to this
// concern. Same Redis instance, two clients. This makes peeling metering
// into its own binary later a copy-paste move.
func newMetering(redisURL, region string) (*Metering, error) {
	if redisURL == "" {
		return nil, errors.New("VETO_REDIS_URL required")
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}
	rdb := redis.NewClient(opt)
	pingCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return &Metering{
		rdb:    rdb,
		region: region,
		ch:     make(chan Event, queueCapacity),
	}, nil
}

// Emit hands the event to the worker. Non-blocking: drops on full queue
// rather than slow down /v1/check. A persistent drop pattern means the
// worker can't keep up with Redis — alert on it. Nil receiver is a no-op:
// the OSS standalone path (static keys, no Redis) has no Metering at all.
func (m *Metering) Emit(e Event) {
	if m == nil {
		return
	}
	select {
	case m.ch <- e:
	default:
		slog.Warn("metering queue full — event dropped",
			"org_id", e.OrgID, "queue_cap", queueCapacity)
	}
}

// Run pulls events from the queue and XADDs them. Drains the queue on ctx
// done so a graceful shutdown doesn't lose the last few events that handlers
// already stuffed into the channel. Nil receiver is a no-op.
func (m *Metering) Run(ctx context.Context) {
	if m == nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			m.drain()
			return
		case e := <-m.ch:
			m.publish(ctx, e)
		}
	}
}

func (m *Metering) drain() {
	for {
		select {
		case e := <-m.ch:
			// Parent ctx is already done — give each remaining publish its
			// own bounded budget so shutdown can't hang on a stalled Redis.
			m.publish(context.Background(), e)
		default:
			return
		}
	}
}

func (m *Metering) publish(parent context.Context, e Event) {
	ctx, cancel := context.WithTimeout(parent, xaddTimeout)
	defer cancel()
	pairs := make([]string, 0, len(e.Pairs))
	for _, p := range e.Pairs {
		pairs = append(pairs, p.Rule+":"+p.Category)
	}
	args := &redis.XAddArgs{
		Stream: streamKey,
		MaxLen: streamMaxLen,
		Approx: true,
		Values: map[string]any{
			"org_id":             e.OrgID,
			"project_id":         e.ProjectID,
			"key_id":             e.KeyID,
			"action":             e.Action,
			"finding_categories": strings.Join(e.Categories, ","),
			"finding_rules":      strings.Join(e.Rules, ","),
			"finding_rule_pairs": strings.Join(pairs, ","),
			"latency_ms":         strconv.FormatFloat(e.LatencyMs, 'f', 3, 64),
			"inference_ms":       strconv.FormatFloat(e.InferenceMs, 'f', 3, 64),
			"region":             m.region,
			"status":             strconv.Itoa(e.Status),
			"byte_count_in":      strconv.Itoa(e.BytesIn),
			"byte_count_out":     strconv.Itoa(e.BytesOut),
		},
	}
	if err := m.rdb.XAdd(ctx, args).Err(); err != nil {
		slog.WarnContext(ctx, "metering xadd", "err", err, "org_id", e.OrgID)
	}
}

func (m *Metering) Close() error {
	if m == nil || m.rdb == nil {
		return nil
	}
	return m.rdb.Close()
}

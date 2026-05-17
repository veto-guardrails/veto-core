package config

import "testing"

// TestLatencyBucketsPinned pins the exact bucket boundaries. Changing them
// requires a data-aware migration: rows in usage_rollups_latency carry
// historical bucket_upper_ms values that the percentile helper interprets
// according to whatever slice it has at runtime. A silent edit here would
// distort historical chart math. If you must change buckets, update this
// test in the same change set so the intent is explicit.
func TestLatencyBucketsPinned(t *testing.T) {
	want := []int{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, infBucket}
	if len(LatencyBuckets) != len(want) {
		t.Fatalf("bucket count drift: got %d, want %d", len(LatencyBuckets), len(want))
	}
	for i, b := range LatencyBuckets {
		if b != want[i] {
			t.Errorf("LatencyBuckets[%d] = %d, want %d", i, b, want[i])
		}
	}
}

func TestBucketForLatency(t *testing.T) {
	cases := []struct {
		ms   float64
		want int
	}{
		{0, 10},
		{1, 10},
		{10, 10},
		{10.0001, 25},
		{25, 25},
		{99.9, 100},
		{100, 100},
		{500, 500},
		{1500, 2500},
		{5000, 5000},
		{5001, infBucket},
		{1_000_000, infBucket},
	}
	for _, tc := range cases {
		got := BucketForLatency(tc.ms)
		if got != tc.want {
			t.Errorf("BucketForLatency(%g) = %d, want %d", tc.ms, got, tc.want)
		}
	}
}

func TestPercentileFromBuckets_Empty(t *testing.T) {
	if v := PercentileFromBuckets(nil, 0.5); v != 0 {
		t.Errorf("empty input: got %d, want 0", v)
	}
	all := []LatencyBucket{{UpperMs: 10, Count: 0}, {UpperMs: 100, Count: 0}}
	if v := PercentileFromBuckets(all, 0.5); v != 0 {
		t.Errorf("all-zero counts: got %d, want 0", v)
	}
}

func TestPercentileFromBuckets_SingleBucket(t *testing.T) {
	bs := []LatencyBucket{{UpperMs: 100, Count: 10}}
	if v := PercentileFromBuckets(bs, 0.5); v < 45 || v > 55 {
		t.Errorf("p50 single bucket: got %d, want ~50", v)
	}
	if v := PercentileFromBuckets(bs, 0.99); v < 95 || v > 100 {
		t.Errorf("p99 single bucket: got %d, want ~99", v)
	}
}

func TestPercentileFromBuckets_TwoBuckets(t *testing.T) {
	bs := []LatencyBucket{
		{UpperMs: 100, Count: 10},
		{UpperMs: 500, Count: 10},
	}
	p50 := PercentileFromBuckets(bs, 0.5)
	if p50 < 95 || p50 > 105 {
		t.Errorf("p50 two-bucket: got %d, want ~100", p50)
	}
	p95 := PercentileFromBuckets(bs, 0.95)
	if p95 < 440 || p95 > 480 {
		t.Errorf("p95 two-bucket: got %d, want ~460", p95)
	}
}

func TestPercentileFromBuckets_InfinityBucket(t *testing.T) {
	bs := []LatencyBucket{
		{UpperMs: 10, Count: 0},
		{UpperMs: 25, Count: 0},
		{UpperMs: 50, Count: 0},
		{UpperMs: 100, Count: 0},
		{UpperMs: 250, Count: 0},
		{UpperMs: 500, Count: 0},
		{UpperMs: 1000, Count: 0},
		{UpperMs: 2500, Count: 0},
		{UpperMs: 5000, Count: 0},
		{UpperMs: infBucket, Count: 1},
	}
	p99 := PercentileFromBuckets(bs, 0.99)
	if p99 < 5000 || p99 > 25000 {
		t.Errorf("p99 inf bucket: got %d, want in (5000, 25000]", p99)
	}
}

func TestPercentileFromBuckets_ClampedTarget(t *testing.T) {
	bs := []LatencyBucket{{UpperMs: 100, Count: 10}}
	if v := PercentileFromBuckets(bs, 0); v != 0 {
		t.Errorf("target=0: got %d, want 0", v)
	}
	if v := PercentileFromBuckets(bs, 1); v < 95 || v > 100 {
		t.Errorf("target=1: got %d, want ~100", v)
	}
	if v := PercentileFromBuckets(bs, -0.5); v != 0 {
		t.Errorf("negative target: got %d, want 0 (clamped)", v)
	}
	if v := PercentileFromBuckets(bs, 1.5); v < 95 || v > 100 {
		t.Errorf("over-1 target: got %d, want ~100 (clamped)", v)
	}
}

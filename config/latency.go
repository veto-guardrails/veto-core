package config

// Latency histogram support for usage_rollups_latency.
//
// The bucket boundaries (upper-inclusive, in ms) are coordinated with the
// veto-cloud migration 0006 schema. Changing them requires backfilling
// existing rows because aggregation queries group on bucket_upper_ms —
// old buckets would stay readable but newly-written rows would land in
// different bins, distorting percentile interpolation across the
// boundary day. The pinning test in this package fails loud on edits so
// the intent must be explicit.
//
// Chosen for display, not tail debugging: p99 resolution is ~20% (e.g. a
// p99 in the (500, 1000] bucket interpolates to ~750 ms). Sufficient for
// "are we fine?" and explicitly deferred for hardening (HDR / TDigest).
// SPEC §13 / PLAN §3.

const infBucket = 999_999_999

// LatencyBuckets are the upper bounds, ascending. The last entry is the
// "infinity" sentinel — anything slower than 5s lands there.
var LatencyBuckets = []int{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, infBucket}

// BucketForLatency returns the smallest bucket upper bound that the
// observed latency (ms) fits into.
func BucketForLatency(ms float64) int {
	for _, b := range LatencyBuckets {
		if ms <= float64(b) {
			return b
		}
	}
	return infBucket
}

// LatencyBucket is one row of the histogram, ordered by UpperMs ascending.
// Counts are cumulative-friendly: the percentile helper walks them in
// order and accumulates.
type LatencyBucket struct {
	UpperMs int
	Count   int64
}

// PercentileFromBuckets returns the linear-interpolated percentile in ms.
// `target` is in [0, 1]. Assumes buckets are ordered ascending by UpperMs
// and that the last bucket is the infinity sentinel (or a finite cap).
//
// Within a bucket we assume requests are uniformly distributed between
// the previous bucket's upper (exclusive) and this bucket's upper
// (inclusive). Crude but matches what the dashboard advertises (display,
// not tail debugging).
//
// Empty input or zero total returns 0 — the caller should hide the strip
// in that case rather than render meaningless marks.
func PercentileFromBuckets(buckets []LatencyBucket, target float64) int {
	var total int64
	for _, b := range buckets {
		total += b.Count
	}
	if total == 0 {
		return 0
	}
	if target < 0 {
		target = 0
	}
	if target > 1 {
		target = 1
	}

	rank := target * float64(total)
	var cum int64
	prevUpper := 0
	for _, b := range buckets {
		next := cum + b.Count
		if float64(next) >= rank && b.Count > 0 {
			into := rank - float64(cum)
			frac := into / float64(b.Count)
			upper := b.UpperMs
			if upper >= infBucket {
				// Avoid reporting 999_999_999 ms in the UI. Treat the
				// infinity bucket as "5x the previous upper" for display
				// purposes — caller still sees the warn tone when p99
				// crosses 500 ms.
				upper = prevUpper * 5
				if upper == 0 {
					upper = 5000
				}
			}
			return prevUpper + int(frac*float64(upper-prevUpper))
		}
		cum = next
		prevUpper = b.UpperMs
	}
	for i := len(buckets) - 1; i >= 0; i-- {
		if buckets[i].UpperMs < infBucket {
			return buckets[i].UpperMs
		}
	}
	return 0
}

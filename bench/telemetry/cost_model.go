package main

import "math"

// cost_model.go turns the resource counters instrumented during a run
// into an extrapolated monthly cost per tenant/user.
//
// HONESTY: every dollar figure here is a list-price AWS estimate
// (us-east-1, on-demand, no committed-use / savings-plan discount) and
// a steady-state extrapolation from a short measurement window. Real
// bills depend on reserved capacity, data-transfer, replication factor,
// and the actual retention mix. Treat the output as an order-of-
// magnitude model, not a quote.

// HoursPerMonth is the AWS billing convention for a month (730h ≈
// 365×24/12). EC2 / EBS monthly costs use this.
const HoursPerMonth = 730.0

// SecondsPerMonth is the window→month scale base for throughput-derived
// volumes (30-day month).
const SecondsPerMonth = 30.0 * 24.0 * 3600.0

const bytesPerGB = 1_000_000_000.0 // AWS bills storage in GB (10^9), not GiB.

// AWSPricing holds the list-price rates the model multiplies against.
// Defaults are us-east-1 on-demand list prices; callers can override
// for another region or a negotiated rate.
type AWSPricing struct {
	// EC2NodeHourlyUSD is the per-hour cost of one compute node in the
	// NATS / ClickHouse clusters. Default models an m6i.large
	// ($0.096/hr) — a conservative per-node baseline.
	EC2NodeHourlyUSD float64
	// EBSGBMonthUSD is the gp3 EBS rate per GB-month.
	EBSGBMonthUSD float64
	// S3StorageGBMonthUSD is the S3 storage rate per GB-month for the
	// archive storage class in use.
	S3StorageGBMonthUSD float64
	// S3PutPer1000USD is the cost per 1,000 S3 PUT requests.
	S3PutPer1000USD float64
}

// DefaultPricing returns us-east-1 on-demand list prices (2024). The
// S3 storage rate is STANDARD_IA — the archive writer's default class.
func DefaultPricing() AWSPricing {
	return AWSPricing{
		EC2NodeHourlyUSD:    0.096,  // m6i.large
		EBSGBMonthUSD:       0.08,   // gp3
		S3StorageGBMonthUSD: 0.0125, // STANDARD_IA
		S3PutPer1000USD:     0.01,   // STANDARD_IA PUT
	}
}

// ResourceUsage is the set of counters instrumented during a run, plus
// the window dimensions needed to extrapolate them to a month.
type ResourceUsage struct {
	// DurationSecs is the measured window length. Must be > 0.
	DurationSecs float64
	// EventsProcessed is the total events that crossed the pipeline in
	// the window.
	EventsProcessed uint64
	// Tenants is the tenant pool size the events were spread across.
	Tenants int
	// UsersPerTenant scales tenant-level cost down to per-user. Default
	// applied when <= 0.
	UsersPerTenant int
	// RetentionDays is the hot-tier (ClickHouse) + archive retention
	// horizon; storage cost is the steady-state retained volume, which
	// is the monthly ingest volume times retention months.
	RetentionDays int

	// NATSNodeCount is the JetStream cluster node count (EC2).
	NATSNodeCount int
	// CHNodeCount is the ClickHouse cluster node count (EC2 + EBS).
	CHNodeCount int

	// CHDiskBytes is the on-disk bytes ClickHouse wrote during the
	// window (post-compression, as reported by system.parts).
	CHDiskBytes uint64

	// S3Objects is the number of archive objects PUT during the window.
	S3Objects uint64
	// S3CompressedBytes is the total compressed archive bytes uploaded.
	S3CompressedBytes uint64
	// S3UncompressedBytes is the pre-gzip JSONL size, for the
	// compression-ratio metric.
	S3UncompressedBytes uint64
}

// CostBreakdown is the per-component and total monthly cost, plus the
// per-user figure the PRD's $0.30–1.20 band is judged against.
type CostBreakdown struct {
	NATSMonthlyUSD       float64
	ClickHouseMonthlyUSD float64
	S3MonthlyUSD         float64
	TotalMonthlyUSD      float64
	PerUserMonthlyUSD    float64
	// EventsPerMonth is the extrapolated monthly event volume.
	EventsPerMonth float64
	// CompressionRatio is S3 uncompressed/compressed (>= 1 means the
	// gzip archive shrinks the payload). 0 when no S3 bytes observed.
	CompressionRatio float64
	// BytesPerEventCH is the average on-disk ClickHouse bytes per event.
	BytesPerEventCH float64
}

// retentionMonths converts the retention horizon to months, defaulting
// to the writer's 60-day default when unset.
func (u ResourceUsage) retentionMonths() float64 {
	days := u.RetentionDays
	if days <= 0 {
		days = 60
	}
	return float64(days) / 30.0
}

// ComputeCost extrapolates the window's resource usage to a monthly
// cost breakdown under the given pricing. It never divides by zero: a
// zero-duration or zero-tenant window yields zeroed throughput-derived
// figures rather than NaN/Inf.
func (u ResourceUsage) ComputeCost(p AWSPricing) CostBreakdown {
	var b CostBreakdown
	if u.DurationSecs <= 0 {
		return b
	}
	windowToMonth := SecondsPerMonth / u.DurationSecs
	b.EventsPerMonth = float64(u.EventsProcessed) * windowToMonth

	// Compute (EC2 + EBS): nodes run continuously, billed per node-hour.
	nodeMonthly := func(nodes int) float64 {
		return float64(nodes) * p.EC2NodeHourlyUSD * HoursPerMonth
	}
	b.NATSMonthlyUSD = nodeMonthly(u.NATSNodeCount)

	// ClickHouse: EC2 nodes + EBS for the retained hot-tier volume. The
	// retained volume is the monthly ingest (window bytes scaled to a
	// month) held for `retentionMonths`.
	monthlyCHBytes := float64(u.CHDiskBytes) * windowToMonth
	retainedCHGB := monthlyCHBytes / bytesPerGB * u.retentionMonths()
	b.ClickHouseMonthlyUSD = nodeMonthly(u.CHNodeCount) + retainedCHGB*p.EBSGBMonthUSD

	// S3: retained archive storage + PUT request cost. Archive bytes
	// also accrue at the monthly ingest rate and are held for
	// retention; PUTs are charged per object at the monthly object rate.
	monthlyS3Bytes := float64(u.S3CompressedBytes) * windowToMonth
	retainedS3GB := monthlyS3Bytes / bytesPerGB * u.retentionMonths()
	monthlyObjects := float64(u.S3Objects) * windowToMonth
	b.S3MonthlyUSD = retainedS3GB*p.S3StorageGBMonthUSD +
		monthlyObjects/1000.0*p.S3PutPer1000USD

	b.TotalMonthlyUSD = b.NATSMonthlyUSD + b.ClickHouseMonthlyUSD + b.S3MonthlyUSD

	users := u.Tenants * u.UsersPerTenant
	if u.UsersPerTenant <= 0 {
		users = u.Tenants // fall back to one user per tenant
	}
	if users > 0 {
		b.PerUserMonthlyUSD = b.TotalMonthlyUSD / float64(users)
	}

	if u.S3CompressedBytes > 0 {
		b.CompressionRatio = float64(u.S3UncompressedBytes) / float64(u.S3CompressedBytes)
	}
	if u.EventsProcessed > 0 {
		b.BytesPerEventCH = float64(u.CHDiskBytes) / float64(u.EventsProcessed)
	}
	return b
}

// CostSection renders the breakdown as a report section. The
// per-user/month row is judged against the PRD's upper bound; the
// component rows are INFO (no per-component target). competitorPerUser
// is a rough industry figure for context only.
func CostSection(b CostBreakdown, targetPerUserUSD, competitorPerUser float64) Section {
	roundCents := func(v float64) float64 { return math.Round(v*100) / 100 }
	return Section{
		Title:   "Cost model (monthly, AWS list price)",
		Summary: "Steady-state extrapolation from the measured window. List-price us-east-1 on-demand; not a quote.",
		Metrics: []MetricRow{
			{
				Name: "events / month (extrapolated)", Unit: "events",
				Actual: math.Round(b.EventsPerMonth), Verdict: VerdictInfo,
			},
			{Name: "NATS cluster", Unit: "$/mo", Actual: roundCents(b.NATSMonthlyUSD), Verdict: VerdictInfo},
			{Name: "ClickHouse (EC2+EBS)", Unit: "$/mo", Actual: roundCents(b.ClickHouseMonthlyUSD), Verdict: VerdictInfo},
			{Name: "S3 archive", Unit: "$/mo", Actual: roundCents(b.S3MonthlyUSD), Verdict: VerdictInfo},
			{Name: "total", Unit: "$/mo", Actual: roundCents(b.TotalMonthlyUSD), Verdict: VerdictInfo},
			{
				Name: "cost / user / month", Unit: "$",
				Actual:      roundCents(b.PerUserMonthlyUSD),
				Theoretical: ptr(targetPerUserUSD),
				Competitor:  ptr(competitorPerUser),
				Verdict:     classify(b.PerUserMonthlyUSD, ptr(targetPerUserUSD), false, DefaultWarnBand),
				Note:        "judged against the PRD upper bound; list-price extrapolation",
			},
			{
				Name: "S3 compression ratio", Unit: "x",
				Actual: math.Round(b.CompressionRatio*100) / 100, Verdict: VerdictInfo,
			},
			{
				Name: "ClickHouse bytes / event", Unit: "B",
				Actual: math.Round(b.BytesPerEventCH*100) / 100, Verdict: VerdictInfo,
			},
		},
	}
}

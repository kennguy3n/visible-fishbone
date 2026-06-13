// Package fleet is the single canonical source of truth for the blog
// evidence fleet's tenant identities — slug, pinned UUID, display name,
// tier, region, country and industry.
//
// Before this package every harness carried its own copy of the nine
// tenant UUIDs (seed/bootstrap.go, usage, capture, anomalies, casb), and
// the usage harness additionally keyed its baseline/run-rate maps by a
// SHORTENED display name ("Maple Health" vs the canonical "Maple Health
// Network") that had to match by eye. A typo in any of those copies
// would silently drift the harnesses apart or, in the usage harness,
// produce zero metering rows with no error. Defining each tenant exactly
// once here removes that fragility: every harness resolves identity by
// slug (a stable, copy-once key) against this list.
//
// The UUIDs are the canonical identities seed/bootstrap.go pins via
// direct SQL (the tenant create API assigns server-side UUIDs and does
// not accept a client-supplied id), and that the committed payloads and
// blog posts reference. The slug, name, region and tier match the rows
// seed actually inserts, so making this the source of truth changes no
// seeded data.
package fleet

import "fmt"

// Tenant is one customer tenant's canonical identity. It deliberately
// holds only identity fields; the seed harness layers its rich per-tenant
// fixtures (sites, devices, policies, DLP, …) on top, keyed by slug.
type Tenant struct {
	Slug     string
	ID       string // canonical UUID, pinned by seed/bootstrap.go
	Name     string
	Tier     string
	Region   string
	Country  string // ISO-3166 alpha-2; empty where the seed skips smart-defaults
	Industry string
}

// The nine canonical customer tenants. They are unexported so a consumer
// can never mutate a shared identity (e.g. fleet.Acme.ID = "…"); callers
// read them through the accessor functions below, each of which returns a
// by-value copy. The ShieldNet Platform system tenant is intentionally not
// a customer and is exposed via the Platform* constants below.
var (
	acme      = Tenant{Slug: "acme-retail", ID: "92112770-7c0a-410b-b0f4-09dde70e063a", Name: "Acme Retail Group", Tier: "enterprise", Region: "us-east-1", Country: "US", Industry: "retail"}
	globex    = Tenant{Slug: "globex-health", ID: "3bd7bb7b-d48a-4569-8f97-46be31ae8e5a", Name: "Globex Health Systems", Tier: "enterprise", Region: "us-west-2", Country: "US", Industry: "healthcare"}
	initech   = Tenant{Slug: "initech-financial", ID: "b6520bda-e7bb-4af9-9c53-7b0051eae65b", Name: "Initech Financial", Tier: "professional", Region: "eu-central-1", Country: "DE", Industry: "finance"}
	umbrella  = Tenant{Slug: "umbrella-logistics", ID: "0c8d2d9d-896d-45b1-8001-6a6776f832b9", Name: "Umbrella Logistics", Tier: "starter", Region: "ap-southeast-1", Country: "", Industry: "general"}
	britannia = Tenant{Slug: "britannia-robotics", ID: "2d0935d3-8c57-4f66-a5a9-0de368f16a7c", Name: "Britannia Robotics", Tier: "enterprise", Region: "eu-west-2", Country: "GB", Industry: "technology"}
	maple     = Tenant{Slug: "maple-health", ID: "cef9c934-507c-4adc-985b-48f3cbe274b0", Name: "Maple Health Network", Tier: "professional", Region: "ca-central-1", Country: "CA", Industry: "healthcare"}
	outback   = Tenant{Slug: "outback-retail", ID: "37619610-53b4-4eab-87f9-45ba902d30c2", Name: "Outback Retail Co", Tier: "professional", Region: "ap-southeast-2", Country: "AU", Industry: "retail"}
	lumiere   = Tenant{Slug: "lumiere-legal", ID: "890486df-98bd-482b-85a8-af361706676f", Name: "Lumière Légal", Tier: "professional", Region: "eu-west-3", Country: "FR", Industry: "legal"}
	nordic    = Tenant{Slug: "nordic-educloud", ID: "8c93e8b9-5710-4f3a-9981-6d2c558bb78f", Name: "Nordic EduCloud", Tier: "starter", Region: "eu-north-1", Country: "SE", Industry: "education"}
)

// Accessor functions for each canonical tenant. They return a by-value
// copy of the unexported identity, so a caller mutating the result cannot
// affect any other consumer.
func Acme() Tenant      { return acme }
func Globex() Tenant    { return globex }
func Initech() Tenant   { return initech }
func Umbrella() Tenant  { return umbrella }
func Britannia() Tenant { return britannia }
func Maple() Tenant     { return maple }
func Outback() Tenant   { return outback }
func Lumiere() Tenant   { return lumiere }
func Nordic() Tenant    { return nordic }

// Platform (system) tenant and managing MSP identities, pinned to the
// stable UUIDs the S1 payloads reference.
const (
	PlatformTenantID   = "f79e9245-24eb-4573-b9f9-7e5b34fd7056"
	PlatformTenantSlug = "platform"
	PlatformTenantName = "ShieldNet Platform"
	PlatformTenantTier = "enterprise"

	MSPID   = "b47fb518-f336-4449-82b0-bd33a1f36833"
	MSPName = "Northwind Managed Security"
	MSPSlug = "northwind-msp"
)

// customers is the canonical ordering used by All(); it mirrors the order
// seed/scenarioTenants() provisions the tenants in.
var customers = []Tenant{acme, globex, initech, umbrella, britannia, maple, outback, lumiere, nordic}

// All returns the nine canonical customer tenants in provisioning order.
// Callers must not mutate the returned slice.
func All() []Tenant {
	out := make([]Tenant, len(customers))
	copy(out, customers)
	return out
}

// BySlug resolves a tenant by its slug, the stable copy-once key.
func BySlug(slug string) (Tenant, bool) {
	for _, t := range customers {
		if t.Slug == slug {
			return t, true
		}
	}
	return Tenant{}, false
}

// MustBySlug is BySlug for call sites with a compile-time-known slug; it
// panics on an unknown slug so a typo fails loudly at startup rather than
// silently resolving to the zero tenant.
func MustBySlug(slug string) Tenant {
	t, ok := BySlug(slug)
	if !ok {
		panic(fmt.Sprintf("fleet: no tenant with slug %q", slug))
	}
	return t
}

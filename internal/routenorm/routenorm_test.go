package routenorm

import "testing"

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"/":                  "/",
		"/api/v1/health":     "/api/v1/health",
		"/api/v1/tenants/42": "/api/v1/tenants/:id",
		"/api/v1/devices/0":  "/api/v1/devices/:id",
		"/api/v1/tenants/9f8b2c1d-1234-4567-89ab-0123456789ab/sites": "/api/v1/tenants/:id/sites",
		"/api/v1/tenants/not-a-uuid":                                 "/api/v1/tenants/not-a-uuid",
		// Multiple variable segments in one path.
		"/api/v1/tenants/42/devices/7": "/api/v1/tenants/:id/devices/:id",
		// Uppercase-hex UUID is still a UUID.
		"/x/9F8B2C1D-1234-4567-89AB-0123456789AB": "/x/:id",
		// A 36-char non-UUID (wrong hyphen positions) is left alone.
		"/x/9f8b2c1d12344567f89ab0123456789ababcd": "/x/9f8b2c1d12344567f89ab0123456789ababcd",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeNoRewriteReturnsInput(t *testing.T) {
	// When nothing is rewritten the original string should be
	// returned (the allocation-light fast path).
	const in = "/api/v1/policy/compile"
	if got := Normalize(in); got != in {
		t.Errorf("Normalize(%q) = %q, want unchanged", in, got)
	}
}

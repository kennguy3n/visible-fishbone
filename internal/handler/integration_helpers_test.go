// Package handler — integration_helpers_test pins internal
// helpers in integration.go that are not reachable via the
// external `handler_test` suite. Currently covers the
// `isSecretSet` semantic-emptiness check (round-4 fix: a
// `{}` JSON object MUST surface as SecretSet=false even though
// len > 0).
package handler

import "testing"

func TestIsSecretSet_SemanticEmptyDetection(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		secret []byte
		want   bool
	}{
		"nil":               {nil, false},
		"zero-length":       {[]byte{}, false},
		"empty-json-object": {[]byte(`{}`), false},
		"empty-json-array":  {[]byte(`[]`), false},
		"json-null":         {[]byte(`null`), false},
		"empty-string":      {[]byte(`""`), false},
		"whitespace":        {[]byte("  \n\t  "), false},
		"populated-object":  {[]byte(`{"api_key":"xxx"}`), true},
		"populated-array":   {[]byte(`["a"]`), true},
		"raw-bytes":         {[]byte{0x01, 0x02, 0x03}, true},
	} {
		t.Run(name, func(t *testing.T) {
			got := isSecretSet(tc.secret)
			if got != tc.want {
				t.Fatalf("isSecretSet(%q) = %v, want %v",
					string(tc.secret), got, tc.want)
			}
		})
	}
}

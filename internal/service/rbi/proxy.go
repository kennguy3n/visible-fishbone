package rbi

import (
	"fmt"
	"net/url"
)

// ProxyConfig describes how the RBI proxy renders pages. The proxy
// is a reverse-proxy in front of a pool of headless Chromium
// containers; the SWG redirects isolated URLs to it and the proxy
// streams the rendering (pixel-pushing or DOM-rewriting) back to the
// user.
//
// This package does NOT embed the actual Chromium orchestration
// (which runs as a separate sidecar or is provided by the
// operator's container platform). It only builds the redirect URLs
// and tracks session state. The container orchestration is
// deployment-specific (Docker, Kubernetes, Firecracker) and
// therefore deliberately left to the operator's infrastructure.
type ProxyConfig struct {
	// BaseURL is the externally-reachable URL of the RBI proxy
	// (e.g. "https://rbi.example.com"). Empty disables RBI.
	BaseURL string
}

// Configured reports whether the proxy is usable.
func (pc ProxyConfig) Configured() bool { return pc.BaseURL != "" }

// SessionURL returns the URL a user should be redirected to in order
// to view a target page through the RBI proxy. The proxy resolves
// the session by id and renders the stored target_url.
func (pc ProxyConfig) SessionURL(sessionID string) string {
	return fmt.Sprintf("%s/rbi/session/%s", pc.BaseURL, url.PathEscape(sessionID))
}

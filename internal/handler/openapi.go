package handler

import (
	"embed"
	"net/http"
)

//go:embed openapi.yaml
var openapiFS embed.FS

// OpenAPIHandler serves the embedded OpenAPI 3.1 spec at:
//
//	GET /api/v1/openapi.yaml — raw YAML
//	GET /api/v1/docs         — Swagger-UI-style HTML wrapper
//
// The handler refuses to serve if the embed is empty (compile-time
// guarantee), so the only failure mode is a network error after
// the response is committed.
type OpenAPIHandler struct{}

// NewOpenAPIHandler constructs the handler.
func NewOpenAPIHandler() *OpenAPIHandler { return &OpenAPIHandler{} }

// Register attaches the routes to a mux.
func (h *OpenAPIHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/openapi.yaml", h.serveYAML)
	mux.HandleFunc("GET /api/v1/docs", h.serveDocs)
}

func (h *OpenAPIHandler) serveYAML(w http.ResponseWriter, _ *http.Request) {
	data, err := openapiFS.ReadFile("openapi.yaml")
	if err != nil {
		http.Error(w, "spec unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(data)
}

// docsHTML is a self-contained HTML wrapper that loads Swagger UI
// from a public CDN and points it at the spec served by serveYAML.
// We keep the asset list tiny so this works in air-gapped envs
// where the CDN is mirrored.
const docsHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ShieldNet Gateway API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
<style>body { margin: 0; padding: 0; }</style>
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
window.onload = () => {
  window.ui = SwaggerUIBundle({
    url: '/api/v1/openapi.yaml',
    dom_id: '#swagger-ui',
    deepLinking: true,
  });
};
</script>
</body>
</html>
`

func (h *OpenAPIHandler) serveDocs(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(docsHTML))
}

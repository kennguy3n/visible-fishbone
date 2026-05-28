// telemetry.go exposes the operator-facing telemetry admin
// endpoints — currently just the DLQ replay trigger. Mounted
// behind the same auth chain as the rest of the operator API.
package handler

import (
	"net/http"

	telreplay "github.com/kennguy3n/visible-fishbone/internal/service/telemetry/replay"
)

// TelemetryHandler hosts the operator-facing endpoints for the
// telemetry pipeline. Currently only the DLQ replay trigger lives
// here; once Prometheus-style /metrics scraping is added, it will
// land on this handler too.
type TelemetryHandler struct {
	replay *telreplay.Worker
}

// NewTelemetryHandler binds the replay worker to an HTTP handler.
// Pass `nil` for `replay` when the telemetry pipeline is disabled —
// the handler will respond 503 on every replay request.
func NewTelemetryHandler(replay *telreplay.Worker) *TelemetryHandler {
	return &TelemetryHandler{replay: replay}
}

// Register attaches the telemetry admin routes onto mux. The
// auth chain in router.go is expected to wrap mux, so callers do
// not need to add their own auth middleware here.
func (h *TelemetryHandler) Register(mux *http.ServeMux) {
	if h == nil {
		return
	}
	mux.HandleFunc("POST /api/v1/admin/telemetry/replay", h.replayHandler)
}

func (h *TelemetryHandler) replayHandler(w http.ResponseWriter, r *http.Request) {
	if h.replay == nil {
		http.Error(w, "telemetry pipeline disabled", http.StatusServiceUnavailable)
		return
	}
	h.replay.Handler().ServeHTTP(w, r)
}

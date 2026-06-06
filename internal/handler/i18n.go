package handler

import (
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/i18n"
)

// bundle is the process-wide message catalog used to localize API
// responses. It is loaded once from the embedded locale files; a
// malformed catalog is a build-time defect and panics at startup
// (MustDefault), which is the correct fail-fast behaviour for a
// self-contained binary.
var bundle = i18n.MustDefault()

// localizedResponseWriter carries the request's negotiated Localizer
// alongside the underlying http.ResponseWriter. LocaleMiddleware
// installs it so the stateless Write* helpers (which only receive a
// ResponseWriter, not the *http.Request) can localize their canonical
// messages without every one of the ~400 call sites threading a
// request or context through.
type localizedResponseWriter struct {
	http.ResponseWriter
	loc *i18n.Localizer
}

// Unwrap exposes the wrapped writer for http.ResponseController
// (flush/hijack passthrough) and for middleware that introspects the
// chain.
func (w *localizedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// LocaleMiddleware negotiates the response locale from the request's
// Accept-Language header, advertises the chosen locale via the
// Content-Language response header, and wraps the ResponseWriter so
// downstream handlers' error/response helpers localize their
// canonical messages. It is placed early in the chain (before the
// API mux) so every JSON response benefits.
func LocaleMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loc := bundle.Match(r.Header.Get("Accept-Language"))
		// Advertise the negotiated locale so caches and clients can
		// vary on it; Vary:Accept-Language tells shared caches the
		// body depends on the request's language.
		w.Header().Set("Content-Language", loc.Locale())
		w.Header().Add("Vary", "Accept-Language")
		next.ServeHTTP(&localizedResponseWriter{ResponseWriter: w, loc: loc}, r)
	})
}

// localizerFromWriter returns the negotiated Localizer carried by the
// response writer, or a fallback (English) Localizer when the
// LocaleMiddleware is not installed — so the helpers degrade to the
// previous English-only behaviour rather than panicking. It walks the
// standard Unwrap() http.ResponseWriter chain so a middleware that
// re-wraps the writer (e.g. a status recorder) between LocaleMiddleware
// and the handler does not hide the carried Localizer.
//
// It intentionally walks only the single-writer Unwrap() variant, not
// the Unwrap() []http.ResponseWriter fan-out form: no middleware in this
// service uses multi-unwrap, and LocaleMiddleware is the innermost
// wrapper so the handler sees the localizedResponseWriter directly. If a
// multi-unwrap middleware is ever inserted between the two, this would
// degrade gracefully to English rather than mis-localize; add the
// []http.ResponseWriter walk here at that point.
func localizerFromWriter(w http.ResponseWriter) *i18n.Localizer {
	for {
		if lw, ok := w.(*localizedResponseWriter); ok && lw.loc != nil {
			return lw.loc
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		next := u.Unwrap()
		if next == nil || next == w {
			break
		}
		w = next
	}
	return bundle.Match("")
}

// LocalizeMessage resolves a catalog message id for the locale
// negotiated on w. Handlers use it to localize ad-hoc messages
// (alert descriptions, validation headlines) keyed by a stable id.
func LocalizeMessage(w http.ResponseWriter, id string) string {
	return localizerFromWriter(w).Message(id)
}

// WriteLocalizedError writes a structured error whose human-readable
// message is the catalog entry msgID resolved for the request locale.
// The machine-readable code is unchanged across locales, so clients
// that branch on `error.code` are unaffected.
func WriteLocalizedError(w http.ResponseWriter, status int, code, msgID string, details ...any) {
	WriteError(w, status, code, localizerFromWriter(w).Message(msgID), details...)
}

package handler

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// AdminSSOHandler exposes the control-plane admin SSO login endpoints
// that front the iam-core OAuth2 authorization-code + PKCE flow
// (Session 2A, Task 3):
//
//	GET /api/v1/auth/sso/login     — 302 to iam-core /oauth2/authorize
//	GET /api/v1/auth/sso/callback  — exchange code, mint SNG session
//
// Both are public (the operator has no SNG session yet — they are
// bootstrapping one), mirroring the public mobile-OIDC + enroll
// endpoints. The transient login state (PKCE verifier + CSRF state +
// nonce) is carried between the two requests in a short-lived, signed,
// http-only cookie so the control plane stays stateless.
type AdminSSOHandler struct {
	sso          *identity.AdminSSOService
	redirectURL  string
	cookieSecret []byte
	secure       bool
	logger       *slog.Logger
}

const (
	ssoStateCookie  = "sng_sso_state"
	ssoSessionCooke = "sng_admin_session"
	ssoStateTTL     = 10 * time.Minute
	ssoCookiePath   = "/api/v1/auth/sso"
)

// NewAdminSSOHandler builds the handler. redirectURL must be the
// callback URL registered with iam-core (cfg.IAMCore.RedirectURL).
// cookieSecret signs the transient login-state cookie (the operator
// console's JWT secret is reused). Cookies are marked Secure when the
// callback is an https URL.
func NewAdminSSOHandler(sso *identity.AdminSSOService, redirectURL string, cookieSecret []byte, logger *slog.Logger) *AdminSSOHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AdminSSOHandler{
		sso:          sso,
		redirectURL:  redirectURL,
		cookieSecret: cookieSecret,
		secure:       strings.HasPrefix(strings.ToLower(redirectURL), "https://"),
		logger:       logger,
	}
}

// RegisterPublic attaches the unauthenticated SSO endpoints.
func (h *AdminSSOHandler) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/auth/sso/login", h.login)
	mux.HandleFunc("GET /api/v1/auth/sso/callback", h.callback)
}

func (h *AdminSSOHandler) login(w http.ResponseWriter, r *http.Request) {
	stepUp := r.URL.Query().Get("step_up") == "true"
	begin, err := h.sso.Begin(r.Context(), h.redirectURL, identity.BeginOptions{StepUp: stepUp})
	if err != nil {
		h.logger.Warn("sso: begin failed", slog.Any("error", err))
		WriteError(w, http.StatusInternalServerError, "sso_begin_failed", "could not start SSO login")
		return
	}
	cookieVal, err := h.encodeState(begin.State)
	if err != nil {
		h.logger.Error("sso: encode state failed", slog.Any("error", err))
		WriteError(w, http.StatusInternalServerError, "sso_begin_failed", "could not start SSO login")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ssoStateCookie,
		Value:    cookieVal,
		Path:     ssoCookiePath,
		MaxAge:   int(ssoStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, begin.AuthorizationURL, http.StatusFound)
}

func (h *AdminSSOHandler) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Surface an upstream authorization error (user denied, etc.)
	// rather than treating the missing code as a generic 400.
	if e := q.Get("error"); e != "" {
		WriteError(w, http.StatusBadRequest, "sso_authorization_error", e)
		return
	}
	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		WriteError(w, http.StatusBadRequest, "sso_missing_param", "code and state are required")
		return
	}

	cookie, err := r.Cookie(ssoStateCookie)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "sso_missing_state", "login state cookie absent or expired")
		return
	}
	stored, err := h.decodeState(cookie.Value)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "sso_invalid_state", "login state cookie invalid")
		return
	}
	// One-shot: clear the state cookie regardless of outcome.
	h.clearCookie(w, ssoStateCookie, ssoCookiePath)

	sess, err := h.sso.Complete(r.Context(), identity.CompleteInput{
		Code:          code,
		ReturnedState: state,
		Stored:        stored,
	})
	if err != nil {
		h.logger.Warn("sso: complete failed", slog.Any("error", err))
		WriteRepositoryError(w, err)
		return
	}

	// Establish the SNG admin session as an http-only cookie the
	// browser replays on subsequent API calls, and also return it in
	// the body for non-browser clients.
	http.SetCookie(w, &http.Cookie{
		Name:     ssoSessionCooke,
		Value:    sess.AccessToken,
		Path:     "/",
		Expires:  sess.ExpiresAt,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
	WriteJSON(w, http.StatusOK, map[string]any{
		"access_token": sess.AccessToken,
		"token_type":   "Bearer",
		"expires_at":   sess.ExpiresAt.UTC().Format(time.RFC3339),
		"tenant_id":    sess.TenantID.String(),
		"user_id":      sess.UserID.String(),
		"email":        sess.Email,
		"mfa":          sess.MFA,
	})
}

// loginStateClaims is the signed cookie payload carrying the transient
// login state between /login and /callback.
type loginStateClaims struct {
	St string `json:"st"`
	No string `json:"no"`
	Cv string `json:"cv"`
	Rd string `json:"rd"`
	jwt.RegisteredClaims
}

func (h *AdminSSOHandler) encodeState(s identity.LoginState) (string, error) {
	now := time.Now()
	claims := loginStateClaims{
		St: s.State,
		No: s.Nonce,
		Cv: s.CodeVerifier,
		Rd: s.RedirectURI,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ssoStateTTL)),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(h.cookieSecret)
}

func (h *AdminSSOHandler) decodeState(raw string) (identity.LoginState, error) {
	var claims loginStateClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) {
		return h.cookieSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return identity.LoginState{}, err
	}
	return identity.LoginState{
		State:        claims.St,
		Nonce:        claims.No,
		CodeVerifier: claims.Cv,
		RedirectURI:  claims.Rd,
	}, nil
}

func (h *AdminSSOHandler) clearCookie(w http.ResponseWriter, name, path string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

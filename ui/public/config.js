// Runtime configuration placeholder.
//
// In production the nginx container entrypoint (docker/docker-entrypoint.sh)
// overwrites this file at container start from environment variables, so a
// single immutable image can be promoted across environments. During local
// `vite dev` this default is served as-is and the app falls back to Vite env
// vars / the dev proxy.
window.__SNG_CONFIG__ = window.__SNG_CONFIG__ || {};

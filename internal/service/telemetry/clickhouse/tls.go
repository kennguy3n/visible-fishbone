package clickhouse

import "crypto/tls"

// newTLSConfig returns the TLS config used by the ClickHouse driver
// when the writer is configured with TLS=true. The config uses the
// system root CA pool (the Go default when RootCAs is nil) and a
// modern minimum TLS version. Operators who need a custom CA bundle
// can set SSL_CERT_FILE in the process environment.
func newTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

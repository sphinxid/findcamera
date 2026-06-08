package onvif

import "crypto/tls"

// insecureTLS returns a TLS config that skips certificate verification.
// ONVIF cameras routinely use self-signed certificates.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

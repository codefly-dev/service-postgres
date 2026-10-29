package postgres

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// ErrServerTrustAnchor reports a declared trust anchor this library will not
// verify against. It is distinct from ErrConnectionProfile because the fault is
// in a configured value rather than in a connection URL, and the operator who
// supplied it cannot act on "invalid connection profile".
var ErrServerTrustAnchor = errors.New("invalid Postgres server trust anchor")

// A managed Postgres server presents a certificate signed by a certificate
// authority that is often private to the instance: Cloud SQL's default mode
// signs with a per-instance, self-signed CA whose root is in no system trust
// store, so `sslmode=verify-full` against system roots cannot verify it at all.
//
// The anchor therefore has to be supplied. pgx reads one from `sslrootcert`, a
// FILE — and a file has to be mounted, which is a seam a service agent may not
// have, and which turns a verifiable connection into a deployment problem. So
// this library takes the anchor as a configured VALUE and builds the trust pool
// itself: the configuration plane already delivers values, and nothing has to
// deliver a file.
//
// A certificate authority is public information, so the anchor is ordinary
// configuration and not a secret. Pinning it is stronger than system trust, not
// weaker: verification then means "this instance's own authority" rather than
// "any authority a public trust store happens to carry".
//
// serverTrustAnchor parses the declared PEM into a pool. It refuses what a
// lenient parse would silently accept, because each of those is a configuration
// mistake that would otherwise surface as an unverifiable connection far from
// its cause.
func serverTrustAnchor(anchor string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	rest := []byte(anchor)
	certificates := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		// x509.CertPool.AppendCertsFromPEM skips any block that is not a
		// certificate, so a pasted private key or a PEM with a typo'd header
		// yields an empty pool and a connection that trusts nothing, reported as
		// a handshake failure. Name it here instead.
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: it carries a %q block, and an anchor is certificates only", ErrServerTrustAnchor, block.Type)
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrServerTrustAnchor, err)
		}
		// A server's own leaf certificate is the thing most easily mistaken for
		// its authority. As an anchor it cannot verify anything (it signs no
		// certificate), so the connection would fail with nothing pointing at
		// the swap.
		if !certificate.IsCA {
			return nil, fmt.Errorf("%w: %q is not a certificate authority", ErrServerTrustAnchor, certificate.Subject.CommonName)
		}
		if now := time.Now(); now.After(certificate.NotAfter) {
			return nil, fmt.Errorf("%w: %q expired on %s", ErrServerTrustAnchor, certificate.Subject.CommonName, certificate.NotAfter.UTC().Format(time.RFC3339))
		}
		pool.AddCert(certificate)
		certificates++
	}
	if certificates == 0 {
		// Including the empty string: an anchor declared as "" is a deployment
		// that meant to pin something and shipped nothing, which must not fall
		// through to system roots that cannot verify a private authority.
		return nil, fmt.Errorf("%w: it contains no certificate", ErrServerTrustAnchor)
	}
	return pool, nil
}

// ServerTrustAnchor parses a declared authority into a trust pool, for a caller
// that builds its own driver configuration rather than going through a
// ConnectionProfile. Same parse, same refusals: one anchor vocabulary for every
// path to the database.
func ServerTrustAnchor(anchor string) (*x509.CertPool, error) { return serverTrustAnchor(anchor) }

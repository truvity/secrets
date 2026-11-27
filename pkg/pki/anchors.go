package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// TrustAnchor is one root certificate the estate trusts: what a verifier
// needs in order to validate a leaf issued anywhere under that root.
// Public material only.
type TrustAnchor struct {
	// GenerationID is the root generation, and the name every distributed
	// copy of this anchor is filed under.
	GenerationID string
	// CertificatePEM is the root certificate, exactly as the ceremony
	// committed it.
	CertificatePEM string
	// FingerprintSHA256 is the certificate's SHA-256, upper-case hex --
	// what an operator compares on a host.
	FingerprintSHA256 string
	// NotAfter is when trusting this anchor stops meaning anything.
	NotAfter time.Time
}

// TrustAnchors returns the committed root certificate of every generation
// Migration.TrustedGenerations names, in the authored order.
//
// This is the join between the contract and what is actually distributed: a
// generation is trusted because it is listed there AND its ceremony
// artifact exists, is the certificate the contract describes, and is
// self-signed. A generation listed before its ceremony ran is a promise
// nothing can keep, so it is an error rather than an empty anchor -- every
// trust bundle is built from this list.
func (c *Contract) TrustAnchors() ([]TrustAnchor, error) {
	anchors := make([]TrustAnchor, 0, len(c.Migration.TrustedGenerations)+len(c.Migration.TrustedExternal))

	// A certificate is trusted once, under one name: an external file that
	// is an authored root, or another external one, is refused rather
	// than distributed twice.
	trusted := map[string]string{}

	for _, id := range c.Migration.TrustedGenerations {
		generation := c.RootGeneration(id)
		if generation == nil {
			// Validate already refuses this; repeated so this method
			// cannot be misused on an unvalidated Contract.
			return nil, fmt.Errorf("pki: migration.trustedGenerations names unknown generation %q", id)
		}

		anchor, err := c.loadTrustAnchor(generation)
		if err != nil {
			return nil, err
		}

		trusted[strings.ToUpper(anchor.FingerprintSHA256)] = anchor.GenerationID
		anchors = append(anchors, *anchor)
	}

	now := time.Now()

	for _, external := range c.Migration.TrustedExternal {
		anchor, err := c.loadExternalAnchor(external, now)
		if err != nil {
			return nil, err
		}

		if name, twice := trusted[anchor.FingerprintSHA256]; twice {
			return nil, fmt.Errorf("pki: external anchor %q is the certificate already trusted as %q (SHA-256 %s): trust it once",
				external.Name, name, anchor.FingerprintSHA256)
		}

		trusted[anchor.FingerprintSHA256] = external.Name
		anchors = append(anchors, *anchor)
	}

	return anchors, nil
}

// loadExternalAnchor reads one external root and holds it to its pinned
// digest and to what an authored root is: one PEM certificate (a regular
// file, reached through no symlink), exactly the fingerprinted one, not
// expired, an ECDSA P-384 key signed with ECDSA SHA-384, a CA whose key
// usage is exactly certificate and CRL signing, its own issuer byte for
// byte, verifying under its own key.
func (c *Contract) loadExternalAnchor(external TrustedExternal, now time.Time) (*TrustAnchor, error) {
	artifactPath := c.ArtifactPath(external.Certificate)

	raw, err := c.readRegularArtifact(external.Certificate)
	if err != nil {
		return nil, fmt.Errorf("pki: external anchor %q: read %s: %w", external.Name, artifactPath, err)
	}

	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("pki: external anchor %q: %s must hold exactly one PEM CERTIFICATE", external.Name, artifactPath)
	}

	digest := sha256.Sum256(block.Bytes)
	fingerprint := strings.ToUpper(hex.EncodeToString(digest[:]))

	if !strings.EqualFold(fingerprint, external.SHA256) {
		return nil, fmt.Errorf("pki: external anchor %q: %s has SHA-256 %s, not the pinned %s",
			external.Name, artifactPath, fingerprint, strings.ToUpper(external.SHA256))
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: external anchor %q: %w", external.Name, err)
	}

	if err := checkExternalCertificate(certificate, now); err != nil {
		return nil, fmt.Errorf("pki: external anchor %q: %w", external.Name, err)
	}

	return &TrustAnchor{
		GenerationID:      external.Name,
		CertificatePEM:    string(pem.EncodeToMemory(block)),
		FingerprintSHA256: fingerprint,
		NotAfter:          certificate.NotAfter,
	}, nil
}

// checkExternalCertificate holds a root authored elsewhere to the shape
// every authored root has: nothing about it is re-derived from a contract
// here, so its own fields are all there is to check.
func checkExternalCertificate(certificate *x509.Certificate, now time.Time) error {
	if certificate.NotAfter.Before(now) {
		return fmt.Errorf("certificate expired at %s", certificate.NotAfter.UTC().Format(time.RFC3339))
	}

	if key, ok := certificate.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P384() {
		return fmt.Errorf("certificate key must be ECDSA P-384")
	}

	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		return fmt.Errorf("certificate must be signed with %s, not %s", x509.ECDSAWithSHA384, certificate.SignatureAlgorithm)
	}

	if !certificate.IsCA || !certificate.BasicConstraintsValid {
		return fmt.Errorf("certificate is not a CA")
	}

	if certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		return fmt.Errorf("certificate key usage must be exactly certificate signing and CRL signing")
	}

	return checkSelfSigned(certificate)
}

// checkSelfSigned: a trust anchor is trusted by being distributed, not by
// anything above it, so it must be its own issuer, compared as the encoded
// names (two names can print alike and differ), and carry its own
// signature.
func checkSelfSigned(certificate *x509.Certificate) error {
	if !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
		return fmt.Errorf("certificate is not self-signed: issuer %q", certificate.Issuer.String())
	}

	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("certificate does not verify against its own key: %w", err)
	}

	return nil
}

// TrustBundlePEM is the one set of CA certificates every client of the
// estate's private services verifies against: the committed root of every
// generation Migration.TrustedGenerations names ([Contract.TrustAnchors]),
// as PEM CERTIFICATE blocks, each newline-terminated, in the authored
// order. One derivation, so no consumer can trust a different set from
// another. An empty set is an error: a bundle that trusts nothing is a
// misconfiguration, never a bundle.
func (c *Contract) TrustBundlePEM() (string, error) {
	anchors, err := c.TrustAnchors()
	if err != nil {
		return "", err
	}

	var out bytes.Buffer

	for _, anchor := range anchors {
		block, _ := pem.Decode([]byte(anchor.CertificatePEM))
		if block == nil {
			return "", fmt.Errorf("pki: trust anchor %s is not PEM", anchor.GenerationID)
		}

		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}); err != nil {
			return "", err
		}
	}

	if out.Len() == 0 {
		return "", fmt.Errorf("pki: the trust bundle is empty: no generation is trusted")
	}

	return out.String(), nil
}

func (c *Contract) loadTrustAnchor(generation *RootGeneration) (*TrustAnchor, error) {
	artifactPath := c.ArtifactPath(RootArtifactName(generation.ID))

	artifact, err := c.loadRootArtifact(artifactPath)
	if err != nil {
		return nil, fmt.Errorf(
			"pki: generation %q is trusted but its ceremony artifact %s cannot be read: %w",
			generation.ID, artifactPath, err,
		)
	}

	if artifact.GenerationID != generation.ID {
		return nil, fmt.Errorf("%s: generationId %q is not %q", artifactPath, artifact.GenerationID, generation.ID)
	}

	// Re-derives the certificate from the artifact and checks that the
	// public metadata beside it (fingerprint, subject key identifier)
	// really was derived from that certificate.
	certificate, err := artifact.Certificate()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", artifactPath, err)
	}

	if err := checkAnchor(generation, certificate); err != nil {
		return nil, fmt.Errorf("%s: %w", artifactPath, err)
	}

	return &TrustAnchor{
		GenerationID:      generation.ID,
		CertificatePEM:    artifact.CertificatePEM,
		FingerprintSHA256: artifact.FingerprintSHA256,
		NotAfter:          certificate.NotAfter,
	}, nil
}

// checkAnchor re-derives from the certificate everything the contract
// authored for it. A swapped or edited file therefore fails here, where it
// is still only a render.
func checkAnchor(generation *RootGeneration, certificate *x509.Certificate) error {
	if !certificate.IsCA || !certificate.BasicConstraintsValid {
		return fmt.Errorf("certificate is not a CA")
	}

	if certificate.Subject.CommonName != generation.Certificate.Subject.CommonName {
		return fmt.Errorf("subject common name %q is not the authored %q",
			certificate.Subject.CommonName, generation.Certificate.Subject.CommonName)
	}

	return checkSelfSigned(certificate)
}

package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const externalName = "vendor-b-private-root-2026-12"

// externalRoot signs a self-signed CA certificate with a key of its own,
// the way another party's root ceremony would, and returns its PEM and its
// SHA-256 fingerprint.
func externalRoot(t *testing.T, isCA bool) ([]byte, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Vendor B Private Root 2026-12", Organization: []string{"Vendor B"}},
		NotBefore:             time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2046, 12, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	digest := sha256.Sum256(der)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), hex.EncodeToString(digest[:])
}

// externalFixture is the ceremony fixture with its own root committed and
// one external root trusted by digest beside it.
func externalFixture(t *testing.T, certificatePEM []byte, sha string) *Contract {
	t.Helper()

	contract := ceremonyFixture(t)
	createTestRoot(t, contract, newFakeKMS(t))

	path := contract.ArtifactPath("external/vendor-b.pem")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := os.WriteFile(path, certificatePEM, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write external root: %v", err)
	}

	contract.Migration.TrustedExternal = []TrustedExternal{{Name: externalName, Certificate: "external/vendor-b.pem", SHA256: sha}}

	return contract
}

// An external root trusted by digest is distributed after the authored
// ones, filed under its own name, in the one bundle every verifier reads.
func TestTrustAnchorsIncludeExternalRoots(t *testing.T) {
	certificatePEM, sha := externalRoot(t, true)
	contract := externalFixture(t, certificatePEM, strings.ToUpper(sha))

	if err := contract.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	anchors, err := contract.TrustAnchors()
	if err != nil {
		t.Fatalf("TrustAnchors: %v", err)
	}

	if len(anchors) != 2 || anchors[0].GenerationID != "example-root-2026-01" || anchors[1].GenerationID != externalName {
		t.Fatalf("anchors = %+v, want the authored root then %s", anchors, externalName)
	}

	if anchors[1].FingerprintSHA256 != strings.ToUpper(sha) {
		t.Fatalf("fingerprint = %s, want %s", anchors[1].FingerprintSHA256, strings.ToUpper(sha))
	}

	bundle, err := contract.TrustBundlePEM()
	if err != nil {
		t.Fatalf("TrustBundlePEM: %v", err)
	}

	if got := strings.Count(bundle, "BEGIN CERTIFICATE"); got != 2 {
		t.Fatalf("bundle has %d certificates, want 2", got)
	}
}

// The pinned digest is the trust: a file that is not exactly the pinned
// certificate, not one certificate, not a CA, or not self-signed is
// refused, never distributed.
func TestExternalAnchorRefusals(t *testing.T) {
	good, sha := externalRoot(t, true)
	other, otherSHA := externalRoot(t, true)
	leaf, leafSHA := externalRoot(t, false)

	for name, fixture := range map[string]struct {
		pem []byte
		sha string
	}{
		"another certificate": {other, sha},
		"two certificates":    {append(append([]byte{}, good...), other...), sha},
		"not a CA":            {leaf, leafSHA},
		"not PEM":             {[]byte("not a certificate"), otherSHA},
	} {
		t.Run(name, func(t *testing.T) {
			contract := externalFixture(t, fixture.pem, fixture.sha)

			if _, err := contract.TrustAnchors(); err == nil {
				t.Fatalf("TrustAnchors accepted %s", name)
			}
		})
	}
}

// What Validate refuses before any file is read.
func TestValidateExternalAnchors(t *testing.T) {
	sha := strings.Repeat("ab", 32)

	for name, external := range map[string][]TrustedExternal{
		"an authored generation": {{Name: "example-root-2026-01", Certificate: "x.pem", SHA256: sha}},
		"a duplicate":            {{Name: externalName, Certificate: "x.pem", SHA256: sha}, {Name: externalName, Certificate: "y.pem", SHA256: sha}},
		"an upper-case name":     {{Name: "Vendor-B", Certificate: "x.pem", SHA256: sha}},
		"a path out":             {{Name: externalName, Certificate: "../x.pem", SHA256: sha}},
		"an absolute path":       {{Name: externalName, Certificate: "/etc/x.pem", SHA256: sha}},
		"an unclean path":        {{Name: externalName, Certificate: "a/../x.pem", SHA256: sha}},
		"no path":                {{Name: externalName, SHA256: sha}},
		"a short digest":         {{Name: externalName, Certificate: "x.pem", SHA256: "abcd"}},
		"a non-hex digest":       {{Name: externalName, Certificate: "x.pem", SHA256: strings.Repeat("zz", 32)}},
	} {
		t.Run(name, func(t *testing.T) {
			contract := validContract()
			contract.Migration.TrustedExternal = external

			if err := contract.Validate(); err == nil || !strings.Contains(err.Error(), "trustedExternal") {
				t.Fatalf("Validate = %v, want a trustedExternal refusal", err)
			}
		})
	}
}

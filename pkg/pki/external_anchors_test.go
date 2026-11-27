package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	externalName = "vendor-b-private-root-2026-12"
	externalCN   = "Vendor B Private Root 2026-12"
	externalFile = "external/vendor-b.pem"
)

// externalShape is what a test varies about another party's root; the
// zero value is a root of exactly the shape an authored one has.
type externalShape struct {
	leaf               bool
	curve              elliptic.Curve
	signatureAlgorithm x509.SignatureAlgorithm
	keyUsage           x509.KeyUsage
	notAfter           time.Time
	// issuerEncodedApart signs with an issuer name that prints as the
	// subject but is encoded differently (PrintableString, not UTF8String).
	issuerEncodedApart bool
}

// externalRoot signs a self-signed CA certificate with a key of its own,
// the way another party's root ceremony would, and returns its PEM and its
// SHA-256 fingerprint.
func externalRoot(t *testing.T, shape externalShape) ([]byte, string) {
	t.Helper()

	curve := shape.curve
	if curve == nil {
		curve = elliptic.P384()
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keyUsage := shape.keyUsage
	if keyUsage == 0 {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	notAfter := shape.notAfter
	if notAfter.IsZero() {
		notAfter = time.Date(2046, 12, 1, 0, 0, 0, 0, time.UTC)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: externalCN},
		NotBefore:             time.Date(2020, 12, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: true,
		IsCA:                  !shape.leaf,
		SignatureAlgorithm:    shape.signatureAlgorithm,
	}

	parent := template

	if shape.issuerEncodedApart {
		// The subject is the CN as a UTF8String; the issuer, from a parent
		// without raw bytes, is the same CN as a PrintableString. Both
		// print "CN=Vendor B Private Root 2026-12".
		cn, err := asn1.MarshalWithParams(externalCN, "utf8")
		if err != nil {
			t.Fatalf("marshal common name: %v", err)
		}

		raw, err := asn1.Marshal(pkix.RDNSequence{{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: asn1.RawValue{FullBytes: cn}}}})
		if err != nil {
			t.Fatalf("marshal subject: %v", err)
		}

		withRaw := *template
		withRaw.RawSubject = raw
		template = &withRaw
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, key)
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

	writeExternal(t, contract.ArtifactPath(externalFile), certificatePEM)

	contract.Migration.TrustedExternal = []TrustedExternal{{Name: externalName, Certificate: externalFile, SHA256: sha}}

	return contract
}

func writeExternal(t *testing.T, path string, certificatePEM []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if err := os.WriteFile(path, certificatePEM, 0o644); err != nil { //nolint:gosec // test fixture
		t.Fatalf("write external root: %v", err)
	}
}

// An external root trusted by digest is distributed after the authored
// ones, filed under its own name, in the one bundle every verifier reads.
func TestTrustAnchorsIncludeExternalRoots(t *testing.T) {
	certificatePEM, sha := externalRoot(t, externalShape{})
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

	// The same tree read through a file system, as a render reads it.
	if _, err := contract.WithFS(os.DirFS(contract.dir), contract.dir).TrustAnchors(); err != nil {
		t.Fatalf("TrustAnchors through a file system: %v", err)
	}
}

// The pinned digest is the trust, and the certificate must still be a root
// of the shape every authored root has: a file that is not exactly the
// pinned certificate, not one certificate, not a CA, expired, not ECDSA
// P-384 signed with ECDSA SHA-384, not exactly a certificate- and
// CRL-signing key, or not its own issuer byte for byte is refused, never
// distributed.
func TestExternalAnchorRefusals(t *testing.T) {
	good, sha := externalRoot(t, externalShape{})
	other, otherSHA := externalRoot(t, externalShape{})

	for name, fixture := range map[string]struct {
		shape externalShape
		pem   []byte
		sha   string
		want  string
	}{
		"another certificate":          {pem: other, sha: sha, want: "not the pinned"},
		"two certificates":             {pem: append(append([]byte{}, good...), other...), sha: sha, want: "exactly one PEM CERTIFICATE"},
		"not PEM":                      {pem: []byte("not a certificate"), sha: otherSHA, want: "exactly one PEM CERTIFICATE"},
		"not a CA":                     {shape: externalShape{leaf: true, keyUsage: x509.KeyUsageDigitalSignature}, want: "not a CA"},
		"expired":                      {shape: externalShape{notAfter: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}, want: "expired at 2025-01-01"},
		"a P-256 key":                  {shape: externalShape{curve: elliptic.P256()}, want: "ECDSA P-384"},
		"a P-384 key signed by SHA256": {shape: externalShape{signatureAlgorithm: x509.ECDSAWithSHA256}, want: "ECDSA-SHA384"},
		"a key that signs data too": {
			shape: externalShape{keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}, want: "key usage",
		},
		"no CRL signing":          {shape: externalShape{keyUsage: x509.KeyUsageCertSign}, want: "key usage"},
		"an issuer encoded apart": {shape: externalShape{issuerEncodedApart: true}, want: "not self-signed"},
	} {
		t.Run(name, func(t *testing.T) {
			if fixture.pem == nil {
				fixture.pem, fixture.sha = externalRoot(t, fixture.shape)
			}

			contract := externalFixture(t, fixture.pem, fixture.sha)

			_, err := contract.TrustAnchors()
			if err == nil || !strings.Contains(err.Error(), fixture.want) {
				t.Fatalf("TrustAnchors = %v, want a refusal containing %q", err, fixture.want)
			}
		})
	}
}

// The encoded-apart issuer prints exactly as its subject: only the raw
// names tell them apart, which is why the check compares bytes.
func TestAnIssuerEncodedApartPrintsAlike(t *testing.T) {
	raw, _ := externalRoot(t, externalShape{issuerEncodedApart: true})

	block, _ := pem.Decode(raw)

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if certificate.Subject.String() != certificate.Issuer.String() {
		t.Fatalf("subject %q and issuer %q should print alike", certificate.Subject, certificate.Issuer)
	}

	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatalf("the fixture should verify under its own key: %v", err)
	}
}

// One certificate is trusted under one name: an external file that is an
// authored root, or two external entries for one certificate, are refused
// rather than distributed twice.
func TestExternalAnchorsAreTrustedOnce(t *testing.T) {
	t.Run("an authored root", func(t *testing.T) {
		contract := ceremonyFixture(t)
		createTestRoot(t, contract, newFakeKMS(t))

		authored, err := contract.TrustAnchors()
		if err != nil || len(authored) != 1 {
			t.Fatalf("TrustAnchors = %v, %v", authored, err)
		}

		writeExternal(t, contract.ArtifactPath(externalFile), []byte(authored[0].CertificatePEM))
		contract.Migration.TrustedExternal = []TrustedExternal{{Name: externalName, Certificate: externalFile, SHA256: authored[0].FingerprintSHA256}}

		if _, err := contract.TrustAnchors(); err == nil || !strings.Contains(err.Error(), `already trusted as "example-root-2026-01"`) {
			t.Fatalf("TrustAnchors = %v, want the authored root refused as an external one", err)
		}
	})

	t.Run("two external entries", func(t *testing.T) {
		certificatePEM, sha := externalRoot(t, externalShape{})
		contract := externalFixture(t, certificatePEM, sha)
		writeExternal(t, contract.ArtifactPath("external/copy.pem"), certificatePEM)
		contract.Migration.TrustedExternal = append(contract.Migration.TrustedExternal,
			TrustedExternal{Name: "vendor-b-copy", Certificate: "external/copy.pem", SHA256: strings.ToUpper(sha)})

		if _, err := contract.TrustAnchors(); err == nil || !strings.Contains(err.Error(), "already trusted as \""+externalName+"\"") {
			t.Fatalf("TrustAnchors = %v, want the second entry refused", err)
		}
	})
}

// The path is checked lexically by Validate and by what it is on disk
// here: a symlink as the file, or as a directory on the way to it, is
// refused even when it points at a valid, pinned certificate.
func TestExternalAnchorRefusesSymlinks(t *testing.T) {
	certificatePEM, sha := externalRoot(t, externalShape{})
	outside := filepath.Join(t.TempDir(), "elsewhere")
	writeExternal(t, filepath.Join(outside, "vendor-b.pem"), certificatePEM)

	for name, link := range map[string]func(t *testing.T, contract *Contract){
		"the file": func(t *testing.T, contract *Contract) {
			mustMkdir(t, contract.ArtifactPath("external"))
			mustSymlink(t, filepath.Join(outside, "vendor-b.pem"), contract.ArtifactPath(externalFile))
		},
		"a directory": func(t *testing.T, contract *Contract) {
			mustSymlink(t, outside, contract.ArtifactPath("external"))
		},
	} {
		for reader, read := range map[string]func(*Contract) *Contract{
			"disk":        func(c *Contract) *Contract { return c },
			"file system": func(c *Contract) *Contract { return c.WithFS(os.DirFS(c.dir), c.dir) },
		} {
			t.Run(name+"/"+reader, func(t *testing.T) {
				contract := ceremonyFixture(t)
				createTestRoot(t, contract, newFakeKMS(t))
				link(t, contract)
				contract.Migration.TrustedExternal = []TrustedExternal{{Name: externalName, Certificate: externalFile, SHA256: sha}}

				if err := contract.Validate(); err != nil {
					t.Fatalf("Validate: %v (the path is clean on paper)", err)
				}

				_, err := read(contract).TrustAnchors()
				if err == nil || !strings.Contains(err.Error(), "symlink") {
					t.Fatalf("TrustAnchors = %v, want a symlink refusal", err)
				}
			})
		}
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()

	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
}

// What Validate refuses before any file is read.
func TestValidateExternalAnchors(t *testing.T) {
	sha := strings.Repeat("ab", 32)

	for name, external := range map[string][]TrustedExternal{
		"an authored generation": {{Name: "example-root-2026-01", Certificate: "x.pem", SHA256: sha}},
		"a duplicate": {
			{Name: externalName, Certificate: "x.pem", SHA256: sha},
			{Name: externalName, Certificate: "y.pem", SHA256: strings.Repeat("cd", 32)},
		},
		"one digest twice":   {{Name: externalName, Certificate: "x.pem", SHA256: sha}, {Name: "vendor-c", Certificate: "y.pem", SHA256: strings.ToUpper(sha)}},
		"an upper-case name": {{Name: "Vendor-B", Certificate: "x.pem", SHA256: sha}},
		"a path out":         {{Name: externalName, Certificate: "../x.pem", SHA256: sha}},
		"an absolute path":   {{Name: externalName, Certificate: "/etc/x.pem", SHA256: sha}},
		"an unclean path":    {{Name: externalName, Certificate: "a/../x.pem", SHA256: sha}},
		"no path":            {{Name: externalName, SHA256: sha}},
		"a short digest":     {{Name: externalName, Certificate: "x.pem", SHA256: "abcd"}},
		"a non-hex digest":   {{Name: externalName, Certificate: "x.pem", SHA256: strings.Repeat("zz", 32)}},
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

// External anchors are validated even where nothing else in the migration
// is required: a contract with no trust domain and no trusted generation
// still has its external list checked.
func TestValidateExternalAnchorsWithoutTrustedGenerations(t *testing.T) {
	migration := Migration{TrustedExternal: []TrustedExternal{{Name: "BAD NAME", Certificate: "../../../etc/passwd", SHA256: strings.Repeat("ab", 32)}}}

	if err := migration.validate(map[string]generationInfo{}, false); err == nil || !strings.Contains(err.Error(), "trustedExternal") {
		t.Fatalf("validate = %v, want a trustedExternal refusal", err)
	}

	migration.TrustedExternal[0].Name = externalName
	if err := migration.validate(map[string]generationInfo{}, false); err == nil || !strings.Contains(err.Error(), "clean path") {
		t.Fatalf("validate = %v, want the path refused", err)
	}
}

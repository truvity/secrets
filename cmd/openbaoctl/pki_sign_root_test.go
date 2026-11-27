package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/kmssigner"
)

const (
	vendorGeneration = "vendor-a-private-root-2026-12"
	vendorAccount    = "444455556666"
)

// vendorRepo is a repository that holds its own contract, the way a
// vendor's own repository does: one root generation in its own account,
// its custody outputs beside it, its artifacts under cfg/. It returns the
// contract path, that account's custody outputs, and the KMS double.
func vendorRepo(t *testing.T) (string, string, *fakeKMS) {
	t.Helper()

	repo := t.TempDir()
	cfg := filepath.Join(repo, "cfg")
	require.NoError(t, os.MkdirAll(filepath.Join(cfg, "pki-roots"), 0o755))

	contract := strings.NewReplacer(
		"example-root-2026-01", vendorGeneration,
		"Example Private Root 2026-01", "Vendor A Private Root 2026-12",
		"organization: Example Org}", "organization: Vendor A Ltd}",
		"111122223333", vendorAccount,
	).Replace(contractYAML)
	path := filepath.Join(cfg, "private-pki.yaml")
	require.NoError(t, os.WriteFile(path, []byte(contract), 0o644))

	custody := strings.NewReplacer(
		"example-root-2026-01", vendorGeneration,
		"111122223333", vendorAccount,
	).Replace(custodyOutputsYAML())
	custodyPath := filepath.Join(cfg, "custody-outputs.yaml")
	require.NoError(t, os.WriteFile(custodyPath, []byte(custody), 0o644))

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	return path, custodyPath, &fakeKMS{key: key}
}

// writePublicKey exports the double's key the way `aws kms get-public-key`
// hands it out, in PEM armour, for an offline review.
func writePublicKey(t *testing.T, client *fakeKMS) string {
	t.Helper()

	der, err := x509.MarshalPKIXPublicKey(&client.key.PublicKey)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "root.pub.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644))

	return path
}

// noKMS fails the test if anything asks for a KMS client: an offline review
// must not.
func noKMS(t *testing.T) kmsFactory {
	t.Helper()

	return func(context.Context, string) (kmssigner.API, error) {
		t.Fatal("an offline review asked for a KMS client")

		return nil, errors.New("unreachable")
	}
}

func vendorSource() sourceOptions {
	return sourceOptions{generation: vendorGeneration}
}

// The vendor's own repository reviews its root offline, signs it once on
// the confirmed hash, writes it under its own cfg/, and a rerun signs
// nothing; a second review then says there is nothing to sign.
func TestSignRootInAVendorRepository(t *testing.T) {
	contract, custody, client := vendorRepo(t)
	source := vendorSource()
	source.contract = contract

	var review bytes.Buffer
	require.NoError(t, runSignRoot(context.Background(), &review, signRootOptions{
		source: source, publicKey: writePublicKey(t, client), printTemplate: true,
		signing: signingOptions{custodyOutputs: custody, kms: noKMS(t)},
	}))
	assert.Contains(t, review.String(), "subject:             CN=Vendor A Private Root 2026-12,O=Vendor A Ltd")
	assert.Contains(t, review.String(), "basic constraints:   critical, CA:TRUE, pathlen:3")
	assert.Contains(t, review.String(), "custody check against "+custody+", all verified:")
	assert.Contains(t, review.String(), "nothing was signed")

	hash := confirmPattern.FindStringSubmatch(review.String())
	require.Len(t, hash, 2)

	var signed bytes.Buffer
	require.NoError(t, runSignRoot(context.Background(), &signed, signRootOptions{
		source: source, confirmTemplate: hash[1],
		signing: signingOptions{custodyOutputs: custody, kms: client.factory},
	}))
	assert.Equal(t, 1, client.signCalls)
	assert.Contains(t, signed.String(), "proven:")
	assert.Contains(t, signed.String(), "generationId: "+vendorGeneration)

	artifact := filepath.Join(filepath.Dir(contract), "pki-roots", vendorGeneration+".yaml")
	assert.FileExists(t, artifact, "the root lives in the vendor's own repository, next to its contract")
	assert.FileExists(t, artifact+".attempt")

	var rerun bytes.Buffer
	require.NoError(t, runSignRoot(context.Background(), &rerun, signRootOptions{
		source: source, confirmTemplate: hash[1],
		signing: signingOptions{custodyOutputs: custody, kms: client.factory},
	}))
	assert.Equal(t, 1, client.signCalls, "a rerun signs nothing")

	var again bytes.Buffer
	require.NoError(t, runSignRoot(context.Background(), &again, signRootOptions{
		source: source, publicKey: writePublicKey(t, client), printTemplate: true,
		signing: signingOptions{custodyOutputs: custody, kms: noKMS(t)},
	}))
	assert.Contains(t, again.String(), "nothing to sign")

	// Its intermediates are then signed under its own root, from the same
	// repository's contract and custody outputs.
	csr := writeCSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.internal Intermediate CA", Organization: []string{"Vendor A Ltd"}}})
	intermediate := signIntermediateOptions{
		source: source, trustDomain: "private", csrPath: csr,
		signing: signingOptions{kms: client.factory, custodyOutputs: custody},
	}

	intermediateReview, err := reviewIntermediate(t, intermediate)
	require.NoError(t, err)

	intermediate.confirmTemplate = confirmPattern.FindStringSubmatch(intermediateReview)[1]
	require.NoError(t, runSignIntermediate(context.Background(), &bytes.Buffer{}, intermediate))
	assert.Equal(t, 2, client.signCalls)
	assert.FileExists(t, filepath.Join(filepath.Dir(contract), "pki-roots", vendorGeneration+"-intermediate-private.yaml"))
}

// A confirmation that is not the template's hash is refused before any
// reservation: no .attempt, no signature.
func TestSignRootRefusesAWrongHashBeforeReserving(t *testing.T) {
	contract, custody, client := vendorRepo(t)
	source := vendorSource()
	source.contract = contract

	err := runSignRoot(context.Background(), &bytes.Buffer{}, signRootOptions{
		source: source, confirmTemplate: strings.Repeat("0", 64),
		signing: signingOptions{custodyOutputs: custody, kms: client.factory},
	})
	require.ErrorContains(t, err, "does not match the template to be signed")
	assert.Zero(t, client.signCalls)
	assert.NoFileExists(t, filepath.Join(filepath.Dir(contract), "pki-roots", vendorGeneration+".yaml.attempt"))
}

// Another account's custody outputs are refused before anything: a vendor
// repository can only sign with its own account's key.
func TestSignRootRefusesAnotherAccountsCustody(t *testing.T) {
	contract, _, client := vendorRepo(t)
	source := vendorSource()
	source.contract = contract

	err := runSignRoot(context.Background(), &bytes.Buffer{}, signRootOptions{
		source: source, publicKey: writePublicKey(t, client), printTemplate: true,
		signing: signingOptions{custodyOutputs: writeCustodyOutputs(t), kms: noKMS(t)},
	})
	require.Error(t, err)
	assert.Zero(t, client.signCalls)
}

// A reviewed export of one key cannot confirm a signature by another.
func TestSignRootRefusesAKMSKeyThatIsNotTheReviewedOne(t *testing.T) {
	contract, custody, client := vendorRepo(t)
	source := vendorSource()
	source.contract = contract

	var review bytes.Buffer
	require.NoError(t, runSignRoot(context.Background(), &review, signRootOptions{
		source: source, publicKey: writePublicKey(t, client), printTemplate: true,
		signing: signingOptions{custodyOutputs: custody, kms: noKMS(t)},
	}))

	_, other := setupContract(t)

	err := runSignRoot(context.Background(), &bytes.Buffer{}, signRootOptions{
		source: source, confirmTemplate: confirmPattern.FindStringSubmatch(review.String())[1],
		signing: signingOptions{custodyOutputs: custody, kms: other.factory},
	})
	require.Error(t, err, "the template hash binds the reviewed public key; another KMS key hashes differently")
	assert.Zero(t, other.signCalls)
}

// Exactly one mode; a key must be named.
func TestSignRootRefusesAmbiguousInvocations(t *testing.T) {
	contract, custody, client := vendorRepo(t)
	source := vendorSource()
	source.contract = contract

	for _, options := range []signRootOptions{
		{source: source, signing: signingOptions{custodyOutputs: custody, kms: client.factory}},
		{source: source, printTemplate: true, confirmTemplate: "x", signing: signingOptions{custodyOutputs: custody, kms: client.factory}},
		{source: source, printTemplate: true, importCertificate: "x.pem", signing: signingOptions{custodyOutputs: custody, kms: client.factory}},
	} {
		require.ErrorIs(t, runSignRoot(context.Background(), &bytes.Buffer{}, options), errChooseRootMode)
	}

	err := runSignRoot(context.Background(), &bytes.Buffer{}, signRootOptions{
		source: source, printTemplate: true,
		signing: signingOptions{skipCustody: "a test", kms: client.factory},
	})
	require.ErrorContains(t, err, "--key-arn is required")
	assert.Zero(t, client.signCalls)
}

// A root signed earlier is recorded without signing.
func TestSignRootImportsARootWithoutSigning(t *testing.T) {
	contract, custody, client := vendorRepo(t)
	source := vendorSource()
	source.contract = contract

	var review bytes.Buffer
	require.NoError(t, runSignRoot(context.Background(), &review, signRootOptions{
		source: source, publicKey: writePublicKey(t, client), printTemplate: true,
		signing: signingOptions{custodyOutputs: custody, kms: noKMS(t)},
	}))
	require.NoError(t, runSignRoot(context.Background(), &bytes.Buffer{}, signRootOptions{
		source: source, confirmTemplate: confirmPattern.FindStringSubmatch(review.String())[1],
		signing: signingOptions{custodyOutputs: custody, kms: client.factory},
	}))

	artifact := filepath.Join(filepath.Dir(contract), "pki-roots", vendorGeneration+".yaml")
	certificate := extractCertificatePEM(t, artifact)

	elsewhere, elsewhereCustody, _ := vendorRepo(t)
	other := vendorSource()
	other.contract = elsewhere

	var out bytes.Buffer
	require.NoError(t, runSignRoot(context.Background(), &out, signRootOptions{
		source: other, importCertificate: certificate,
		signing: signingOptions{custodyOutputs: elsewhereCustody, kms: client.factory},
	}))
	assert.Contains(t, out.String(), "recorded without signing")
	assert.Equal(t, 1, client.signCalls, "importing signs nothing")
}

func extractCertificatePEM(t *testing.T, artifactPath string) string {
	t.Helper()

	raw, err := os.ReadFile(artifactPath)
	require.NoError(t, err)

	start := strings.Index(string(raw), "-----BEGIN CERTIFICATE-----")
	end := strings.Index(string(raw), "-----END CERTIFICATE-----")
	require.True(t, start >= 0 && end > start)

	var pemText strings.Builder

	for _, line := range strings.Split(string(raw)[start:end+len("-----END CERTIFICATE-----")], "\n") {
		pemText.WriteString(strings.TrimSpace(line) + "\n")
	}

	path := filepath.Join(t.TempDir(), "root.pem")
	require.NoError(t, os.WriteFile(path, []byte(pemText.String()), 0o644))

	return path
}

func reviewIntermediate(t *testing.T, options signIntermediateOptions) (string, error) {
	t.Helper()

	options.printTemplate = true
	options.confirmTemplate = ""

	var out bytes.Buffer
	err := runSignIntermediate(context.Background(), &out, options)

	return out.String(), err
}

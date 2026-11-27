package ceremony

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rootPlanFixture(t *testing.T) (*RootPlan, *fakeKMS) {
	t.Helper()

	client := fixtureRootKMS(t)
	artifactPath := filepath.Join(t.TempDir(), "roots", fixtureGeneration+".yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(artifactPath), 0o755))

	plan, err := PrepareRoot(fixtureRootSpec(), &client.privateKey.PublicKey, fixtureKeyARN, artifactPath)
	require.NoError(t, err)

	return plan, client
}

// The same spec and key give the same template hash, and the hash is the
// hash of the TBSCertificate KMS then signs: what a reviewer confirmed is
// what was signed, byte for byte.
func TestRootPlanHashIsTheSignedTBSCertificate(t *testing.T) {
	plan, client := rootPlanFixture(t)

	again, err := PrepareRoot(fixtureRootSpec(), &client.privateKey.PublicKey, fixtureKeyARN, plan.ArtifactPath)
	require.NoError(t, err)
	assert.Equal(t, plan.TemplateSHA256, again.TemplateSHA256, "the template hash must be deterministic")

	result, err := SignRoot(context.Background(), client, plan, RootSignOptions{ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.NoError(t, err)
	assert.True(t, result.Signed)
	assert.Equal(t, 1, client.signCalls)

	tbs := sha256.Sum256(result.Certificate.RawTBSCertificate)
	assert.Equal(t, plan.TemplateSHA256, hex.EncodeToString(tbs[:]))

	require.NoError(t, result.Certificate.CheckSignatureFrom(result.Certificate))
	assert.Equal(t, fixtureRootMaxLen, result.Certificate.MaxPathLen)
	assert.FileExists(t, plan.ArtifactPath)
	assert.FileExists(t, plan.ArtifactPath+AttemptSuffix)
	assert.Regexp(t, `template sha256:\s+`+plan.TemplateSHA256, plan.Text())
}

// A wrong confirmation is refused before anything: no reservation, no
// signature, no artifact.
func TestSignRootRefusesAWrongConfirmationBeforeReserving(t *testing.T) {
	plan, client := rootPlanFixture(t)

	_, err := SignRoot(context.Background(), client, plan, RootSignOptions{ConfirmTemplateSHA256: "00" + plan.TemplateSHA256[2:]})
	require.ErrorIs(t, err, ErrRootConfirmation)
	assert.Zero(t, client.signCalls)
	assert.NoFileExists(t, plan.ArtifactPath+AttemptSuffix)
	assert.NoFileExists(t, plan.ArtifactPath)
}

// A rerun after a successful ceremony verifies the committed artifact and
// signs nothing.
func TestSignRootRerunSignsNothing(t *testing.T) {
	plan, client := rootPlanFixture(t)

	_, err := SignRoot(context.Background(), client, plan, RootSignOptions{ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.NoError(t, err)

	again, err := SignRoot(context.Background(), client, plan, RootSignOptions{ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.NoError(t, err)
	assert.False(t, again.Signed)
	assert.Equal(t, 1, client.signCalls, "a rerun must not sign again")
	assert.NotEmpty(t, again.Proof)
}

// A reservation with no artifact is an ambiguous earlier attempt: every
// rerun fails closed and never signs.
func TestSignRootFailsClosedOnAnEarlierAttempt(t *testing.T) {
	plan, client := rootPlanFixture(t)

	require.NoError(t, os.WriteFile(plan.ArtifactPath+AttemptSuffix, []byte("status: reserved\n"), 0o644))

	_, err := SignRoot(context.Background(), client, plan, RootSignOptions{ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.Error(t, err)
	assert.Zero(t, client.signCalls)
	assert.NoFileExists(t, plan.ArtifactPath)
}

// A template reviewed with one key cannot be signed by another: the KMS
// key must be the reviewed public key, checked before the reservation.
func TestSignRootRefusesAnotherKMSKey(t *testing.T) {
	plan, _ := rootPlanFixture(t)
	other := kmsFor(t, fixtureKey(t, 0x42))

	_, err := SignRoot(context.Background(), other, plan, RootSignOptions{ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.ErrorContains(t, err, "is not the public key the template was reviewed with")
	assert.Zero(t, other.signCalls)
	assert.NoFileExists(t, plan.ArtifactPath+AttemptSuffix)
}

// An artifact that is not the plan's root (here: another key's) is refused,
// never overwritten, never re-signed.
func TestSignRootRefusesAForeignArtifact(t *testing.T) {
	plan, client := rootPlanFixture(t)

	otherClient := kmsFor(t, fixtureKey(t, 0x42))
	otherPlan, err := PrepareRoot(fixtureRootSpec(), &otherClient.privateKey.PublicKey, fixtureKeyARN, plan.ArtifactPath)
	require.NoError(t, err)
	_, err = SignRoot(context.Background(), otherClient, otherPlan, RootSignOptions{ConfirmTemplateSHA256: otherPlan.TemplateSHA256})
	require.NoError(t, err)

	_, err = SignRoot(context.Background(), client, plan, RootSignOptions{ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.ErrorContains(t, err, "existing ceremony state is invalid")
	assert.Zero(t, client.signCalls)
}

// The reviewed export of the key, as `aws kms get-public-key` hands it out
// in PEM armour, gives the same plan as the key itself; anything but one
// P-384 PUBLIC KEY block is refused.
func TestParsePublicKeyPEM(t *testing.T) {
	plan, client := rootPlanFixture(t)

	block := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: client.publicDER})

	key, err := ParsePublicKeyPEM(block)
	require.NoError(t, err)

	fromPEM, err := PrepareRoot(fixtureRootSpec(), key, fixtureKeyARN, plan.ArtifactPath)
	require.NoError(t, err)
	assert.Equal(t, plan.TemplateSHA256, fromPEM.TemplateSHA256)

	_, err = ParsePublicKeyPEM(append(block, block...))
	require.ErrorContains(t, err, "exactly one")

	_, err = ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: client.publicDER}))
	require.Error(t, err)

	rsaish, err := x509.MarshalPKIXPublicKey(&fixtureKey(t, 0x11).PublicKey)
	require.NoError(t, err)
	_, err = ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaish[:len(rsaish)-1]}))
	require.Error(t, err)
}

// PrepareRoot refuses what CreateRoot refuses, before building anything.
func TestPrepareRootRefusals(t *testing.T) {
	client := fixtureRootKMS(t)

	_, err := PrepareRoot(fixtureRootSpec(), &client.privateKey.PublicKey, "", "x.yaml")
	require.Error(t, err)

	_, err = PrepareRoot(fixtureRootSpec(), nil, fixtureKeyARN, "x.yaml")
	require.Error(t, err)

	spec := fixtureRootSpec()
	spec.CommonName = ""
	_, err = PrepareRoot(spec, &client.privateKey.PublicKey, fixtureKeyARN, "x.yaml")
	require.Error(t, err)
}

// SignRoot and CreateRoot sign the same certificate for the same spec and
// key: one ceremony, two front doors, and a root made by either verifies
// under the other.
func TestSignRootAndCreateRootAgree(t *testing.T) {
	plan, client := rootPlanFixture(t)

	_, err := SignRoot(context.Background(), client, plan, RootSignOptions{ConfirmTemplateSHA256: plan.TemplateSHA256})
	require.NoError(t, err)

	result, err := CreateRoot(context.Background(), client, plan.Spec, RootOptions{KeyARN: plan.KeyARN, ArtifactPath: plan.ArtifactPath})
	require.NoError(t, err)
	assert.False(t, result.Signed, "CreateRoot re-verifies SignRoot's artifact and signs nothing")
	assert.Equal(t, 1, client.signCalls)
}

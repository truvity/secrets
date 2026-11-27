package ceremony

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/truvity/secrets/pkg/kmssigner"
)

type (
	// RootPlan is the fully checked input to one root self-signature: what
	// a review prints and what a confirmation binds to. It is the root's
	// counterpart of [IntermediatePlan]. The root signs itself, so the
	// public key it certifies is the KMS key's own, and the plan is built
	// from that key alone: a reviewer can build it offline from the key's
	// exported public key (see [ParsePublicKeyPEM]), with no credential.
	RootPlan struct {
		Spec         RootSpec
		KeyARN       string
		ArtifactPath string
		PublicKey    *ecdsa.PublicKey
		Template     *x509.Certificate
		// TemplateSHA256 is the lowercase hex SHA-256 of the exact
		// TBSCertificate the root key will sign.
		TemplateSHA256 string
	}

	// RootSignOptions carries the operator's confirmation of the template
	// they reviewed.
	RootSignOptions struct {
		ConfirmTemplateSHA256 string
	}

	// RootSignResult reports the artifact, whether this invocation signed,
	// and every property proven about the certificate.
	RootSignResult struct {
		Artifact    RootArtifact
		Certificate *x509.Certificate
		Signed      bool
		Proof       []string
	}
)

// ErrRootConfirmation is returned when the confirmed template hash is not
// the hash of the template the plan would sign.
var ErrRootConfirmation = errors.New("template confirmation does not match the template to be signed")

// PrepareRoot builds the exact root certificate the spec and the KMS key's
// public key determine, and the hash of its TBSCertificate. It performs no
// signing and needs no credential when publicKey comes from a reviewed
// export of the key.
func PrepareRoot(spec RootSpec, publicKey *ecdsa.PublicKey, keyARN, artifactPath string) (*RootPlan, error) {
	if keyARN == "" || artifactPath == "" {
		return nil, fmt.Errorf("key ARN and artifact path are required")
	}

	if publicKey == nil || publicKey.Curve != elliptic.P384() {
		return nil, fmt.Errorf("the root key must be ECDSA P-384")
	}

	if err := spec.validate(); err != nil {
		return nil, err
	}

	template, err := RootTemplate(spec, publicKey)
	if err != nil {
		return nil, err
	}

	templateSHA256, err := rootTBSSHA256(template, publicKey)
	if err != nil {
		return nil, err
	}

	return &RootPlan{
		Spec:           spec,
		KeyARN:         keyARN,
		ArtifactPath:   artifactPath,
		PublicKey:      publicKey,
		Template:       template,
		TemplateSHA256: templateSHA256,
	}, nil
}

// ExistingRoot validates the committed artifact of a plan, if there is one:
// (artifact, true, nil) when it exists and is exactly the plan's root,
// (zero, false, nil) when there is none, and an error when it exists but is
// not the plan's root. A review and a signing run both start here, so a
// rerun after a successful ceremony never asks for a signature.
func (p *RootPlan) ExistingRoot() (RootArtifact, bool, error) {
	var existing RootArtifact

	err := readYAMLStrict(p.ArtifactPath, &existing)
	if errors.Is(err, os.ErrNotExist) {
		return RootArtifact{}, false, nil
	}

	if err != nil {
		return RootArtifact{}, false, fmt.Errorf("read ceremony state: %w", err)
	}

	if err := validateRootArtifact(existing, p.Template, p.PublicKey, p.Spec.GenerationID, p.KeyARN); err != nil {
		return RootArtifact{}, false, fmt.Errorf("existing ceremony state is invalid: %w", err)
	}

	return existing, true, nil
}

// SignRoot performs the one KMS self-signature for a prepared plan, or
// re-validates the existing artifact without signing. The order is the
// guarantee:
//
//  1. the confirmation must be the plan's template hash, before anything
//     else, so a typo costs nothing;
//  2. an existing, valid artifact is returned with Signed false: a rerun
//     never signs;
//  3. the KMS key's public key must be the plan's, so a reviewed export of
//     one key cannot confirm a signature by another;
//  4. only then is <artifact>.attempt reserved (exclusively, fsync'd,
//     never removed) and the one Sign call made. An ambiguous outcome
//     leaves the reservation, and every rerun fails closed.
func SignRoot(ctx context.Context, client kmssigner.API, plan *RootPlan, options RootSignOptions) (*RootSignResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ceremony context is required")
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if plan == nil || plan.Template == nil || plan.PublicKey == nil {
		return nil, fmt.Errorf("a prepared root plan is required")
	}

	if !strings.EqualFold(strings.TrimSpace(options.ConfirmTemplateSHA256), plan.TemplateSHA256) {
		return nil, fmt.Errorf("%w: confirmed %q, the template hashes to %s; review --print-template and confirm that exact hash",
			ErrRootConfirmation, options.ConfirmTemplateSHA256, plan.TemplateSHA256)
	}

	existing, found, err := plan.ExistingRoot()
	if err != nil {
		return nil, err
	}

	if found {
		certificate, err := decodeSingleCertificate([]byte(existing.CertificatePEM))
		if err != nil {
			return nil, err
		}

		return &RootSignResult{Artifact: existing, Certificate: certificate, Signed: false, Proof: verifyRoot(certificate, plan)}, nil
	}

	signer, err := kmssigner.New(ctx, client, plan.KeyARN)
	if err != nil {
		return nil, err
	}

	if kmsKey, ok := signer.Public().(*ecdsa.PublicKey); !ok || !kmsKey.Equal(plan.PublicKey) {
		return nil, fmt.Errorf("KMS key %s is not the public key the template was reviewed with; refusing to sign", plan.KeyARN)
	}

	attempt := Attempt{
		GenerationID: plan.Spec.GenerationID,
		KeyARN:       plan.KeyARN,
		StatePath:    plan.ArtifactPath,
		Status:       AttemptStatusReserved,
	}

	certificateDER, err := signOnce(plan.ArtifactPath, attempt, plan.Template, plan.Template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("root certificate: %w", err)
	}

	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse root certificate: %w", err)
	}

	if err := validateRootCertificate(certificate, plan.Template, plan.PublicKey); err != nil {
		return nil, fmt.Errorf("validate root certificate: %w", err)
	}

	tbs := sha256.Sum256(certificate.RawTBSCertificate)
	if hex.EncodeToString(tbs[:]) != plan.TemplateSHA256 {
		return nil, fmt.Errorf("the signed TBSCertificate is not the confirmed template (%s); the artifact is not written", plan.TemplateSHA256)
	}

	artifact := rootArtifactFromCertificate(certificate, plan.Spec.GenerationID, plan.KeyARN)
	if err := writeArtifactExclusive(plan.ArtifactPath, artifact); err != nil {
		return nil, err
	}

	return &RootSignResult{Artifact: artifact, Certificate: certificate, Signed: true, Proof: verifyRoot(certificate, plan)}, nil
}

// Text renders the root template the way an operator reviews it: every
// field that ends up in the certificate, then the hash confirm-template
// takes.
func (p *RootPlan) Text() string {
	template := p.Template

	var b strings.Builder

	line := func(label, value string) {
		fmt.Fprintf(&b, "  %-21s%s\n", label+":", value)
	}

	fmt.Fprintf(&b, "root certificate template\n")
	line("root generation", p.Spec.GenerationID)
	line("artifact", p.ArtifactPath)
	line("key", p.KeyARN)
	line("public key", "ECDSA P-384, SPKI SHA-256 "+strings.ToUpper(hex.EncodeToString(spkiHash(p.PublicKey))))
	line("version", "3")
	line("serial", strings.ToUpper(hex.EncodeToString(template.SerialNumber.Bytes())))
	line("signature algorithm", template.SignatureAlgorithm.String())
	line("issuer", template.Subject.String()+" (self-signed)")
	line("subject", template.Subject.String())
	line("not before", template.NotBefore.UTC().Format(time.RFC3339))
	line("not after", template.NotAfter.UTC().Format(time.RFC3339))
	line("basic constraints", fmt.Sprintf("critical, CA:TRUE, pathlen:%d", template.MaxPathLen))
	line("key usage", "critical, Certificate Sign, CRL Sign")
	line("subject key id", strings.ToUpper(hex.EncodeToString(template.SubjectKeyId)))
	line("authority key id", strings.ToUpper(hex.EncodeToString(template.AuthorityKeyId)))

	if len(template.PermittedDNSDomains) == 0 {
		line("name constraints", "none")
	} else {
		line("name constraints", "critical, permitted DNS: "+strings.Join(template.PermittedDNSDomains, ", "))
	}

	line("template sha256", p.TemplateSHA256)

	return b.String()
}

// ParsePublicKeyPEM reads one PEM "PUBLIC KEY" block (SubjectPublicKeyInfo,
// what `aws kms get-public-key` returns, base64 inside PEM armour) and
// returns its ECDSA P-384 key. A review that builds the root template from
// it needs no credential; the signing run then refuses unless the KMS key
// is this exact key.
func ParsePublicKeyPEM(raw []byte) (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected one PEM PUBLIC KEY block")
	}

	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, fmt.Errorf("expected exactly one PEM PUBLIC KEY block, found trailing data")
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P384() {
		return nil, fmt.Errorf("the root key must be ECDSA P-384")
	}

	return key, nil
}

// rootTBSSHA256 is the hash of the exact TBSCertificate the root key will
// sign. A self-signed TBSCertificate depends on the template and the
// certified public key, never on the signing private key, so a throwaway
// P-384 signer yields byte for byte the bytes KMS will sign: the issuer
// (the template's own subject), the AKI (the template's own, authored) and
// the subject public key (the root key) are all fixed by the template.
func rootTBSSHA256(template *x509.Certificate, publicKey *ecdsa.PublicKey) (string, error) {
	throwaway, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate throwaway key for the template preview: %w", err)
	}

	parent := &x509.Certificate{
		Subject:      template.Subject,
		SubjectKeyId: template.SubjectKeyId,
		PublicKey:    &throwaway.PublicKey,
	}

	previewDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, throwaway)
	if err != nil {
		return "", fmt.Errorf("render template preview: %w", err)
	}

	preview, err := x509.ParseCertificate(previewDER)
	if err != nil {
		return "", fmt.Errorf("parse template preview: %w", err)
	}

	tbs := sha256.Sum256(preview.RawTBSCertificate)

	return hex.EncodeToString(tbs[:]), nil
}

// verifyRoot states, one line each, what the signed (or re-verified) root
// proves. It runs after validateRootCertificate has passed, which checks
// every one of these; the lines are the operator's record.
func verifyRoot(certificate *x509.Certificate, plan *RootPlan) []string {
	tbs := sha256.Sum256(certificate.RawTBSCertificate)

	constraints := "no name constraints"
	if len(certificate.PermittedDNSDomains) != 0 {
		constraints = "critical name constraints permit DNS " + strings.Join(certificate.PermittedDNSDomains, ", ")
	}

	return []string{
		"signed TBSCertificate SHA-256 is " + hex.EncodeToString(tbs[:]) + " (the confirmed template: " +
			fmt.Sprint(hex.EncodeToString(tbs[:]) == plan.TemplateSHA256) + ")",
		"self-signature verifies with the KMS key's P-384 public key (ECDSA-SHA384)",
		"public key is the reviewed one (SPKI SHA-256 " + strings.ToUpper(hex.EncodeToString(spkiHash(plan.PublicKey))) + ")",
		"subject, issuer and deterministic serial match the authored template",
		"validity is " + certificate.NotBefore.UTC().Format(time.RFC3339) + " to " + certificate.NotAfter.UTC().Format(time.RFC3339),
		fmt.Sprintf("CA:TRUE with pathlen %d; key usage is exactly certSign and crlSign", certificate.MaxPathLen),
		"SKI and AKI are SHA-256[:20] of the public key",
		constraints,
	}
}

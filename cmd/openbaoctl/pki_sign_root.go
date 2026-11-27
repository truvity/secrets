package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
	"go.yaml.in/yaml/v3"

	"github.com/truvity/secrets/pkg/ceremony"
	"github.com/truvity/secrets/pkg/kmssigner"
)

const flagPublicKey = "public-key"

var errChooseRootMode = errors.New(
	"choose one: --" + flagPrintTemplate + " to review the exact root template, --" + flagConfirmTemplate +
		" <sha256> to sign it, or --" + flagImportCertificate + " <pem> to record a root signed earlier")

// signRootOptions drives `openbaoctl pki sign-root`: the reviewed,
// confirmed form of create-root, for any repository that holds a contract
// with its own root generation and that account's custody outputs.
type signRootOptions struct {
	source            sourceOptions
	publicKey         string
	printTemplate     bool
	confirmTemplate   string
	importCertificate string
	signing           signingOptions
}

func pkiSignRootCommand(sourceFlags, signingFlags []cli.Flag, source func(*cli.Command) sourceOptions,
	signing func(*cli.Command) signingOptions,
) *cli.Command {
	return &cli.Command{
		Name:  "sign-root",
		Usage: "review, then sign once, the root certificate with the KMS root key (or record one signed earlier)",
		Description: "The root ceremony in two steps, as sign-intermediate:\n\n" +
			"  --print-template   builds the root template from --contract/--generation (or --hierarchy) and the\n" +
			"                     root key's public key and prints it with its template sha256. With --public-key\n" +
			"                     (the key's exported SubjectPublicKeyInfo, PEM) it needs no credential, so a second\n" +
			"                     reviewer can reproduce the hash; without it the key is read from KMS.\n" +
			"  --confirm-template <sha256>  rebuilds the template, refuses a hash that is not its own, refuses a\n" +
			"                     KMS key that is not the reviewed one, reserves <artifact>.attempt, and asks KMS for\n" +
			"                     the one self-signature. A rerun after success signs nothing.\n" +
			"  --import-certificate <pem>   verifies and records a root signed earlier; signs nothing.\n\n" +
			"The artifact is written under the contract's own artifact directory, relative to the contract\n" +
			"file, so a repository that holds its own contract keeps its own root. With --contract the key, the\n" +
			"role and the profile come from --custody-outputs (that account's file) and must match the\n" +
			"generation; --key-arn is needed only without it.",
		Flags: append(append([]cli.Flag{
			&cli.StringFlag{Name: flagKeyARN, Usage: "the root generation's KMS primary key ARN (default: --" + flagCustodyOutputs + "'s)"},
			&cli.StringFlag{Name: flagPublicKey, Usage: "the root key's exported public key (PEM PUBLIC KEY) for an offline --" + flagPrintTemplate},
			&cli.BoolFlag{Name: flagPrintTemplate, Usage: "print the exact root template and its sha256, sign nothing"},
			&cli.StringFlag{Name: flagConfirmTemplate, Usage: "sha256 printed by --" + flagPrintTemplate + "; required to sign"},
			&cli.StringFlag{Name: flagImportCertificate, Usage: "verify and record this existing root certificate (PEM) instead of signing"},
		}, sourceFlags...), signingFlags...),
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return runSignRoot(ctx, os.Stdout, signRootOptions{
				source:            source(cmd),
				publicKey:         cmd.String(flagPublicKey),
				printTemplate:     cmd.Bool(flagPrintTemplate),
				confirmTemplate:   cmd.String(flagConfirmTemplate),
				importCertificate: cmd.String(flagImportCertificate),
				signing:           signing(cmd),
			})
		},
	}
}

func runSignRoot(ctx context.Context, out io.Writer, options signRootOptions) error {
	if countTrue(options.printTemplate, options.confirmTemplate != "", options.importCertificate != "") != 1 {
		return errChooseRootMode
	}

	pkiSource, err := loadSource(options.source)
	if err != nil {
		return err
	}

	spec, err := pkiSource.rootSpec()
	if err != nil {
		return err
	}

	// The custody check is offline, so the review shows it: what an
	// operator confirms with the template hash is the template and this.
	signing, check, err := options.signing.withCustody(pkiSource, "")
	if err != nil {
		return err
	}

	keyARN := signing.keyARN
	if keyARN == "" {
		return fmt.Errorf("--%s is required without --%s: the root's key must be named", flagKeyARN, flagCustodyOutputs)
	}

	artifactPath := pkiSource.rootArtifactPath()

	if options.importCertificate != "" {
		return runImportRoot(ctx, out, signing, check, spec, keyARN, artifactPath, options.importCertificate)
	}

	publicKey, err := rootPublicKey(ctx, signing, keyARN, options.publicKey)
	if err != nil {
		return err
	}

	plan, err := ceremony.PrepareRoot(spec, publicKey, keyARN, artifactPath)
	if err != nil {
		return err
	}

	if options.printTemplate {
		return printRootTemplate(out, plan, check, options.publicKey != "")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	check.log(ctx, logger)

	client, err := signing.client(ctx, keyARN)
	if err != nil {
		return err
	}

	result, err := ceremony.SignRoot(ctx, client, plan, ceremony.RootSignOptions{ConfirmTemplateSHA256: options.confirmTemplate})
	if err != nil {
		return err
	}

	if result.Signed {
		logger.InfoContext(ctx, "signed the root certificate and wrote its public artifact", slog.String("artifact", artifactPath))
	} else {
		logger.InfoContext(ctx, "verified the existing root artifact without signing", slog.String("artifact", artifactPath))
	}

	raw, err := yaml.Marshal(result.Artifact)
	if err != nil {
		return fmt.Errorf("marshal public ceremony output: %w", err)
	}

	_, err = io.WriteString(out, check.text+"\n"+proofText(result.Proof)+"\n"+string(raw))

	return err
}

// rootPublicKey is the reviewed export when one is given (no credential),
// else the KMS key's own public key.
func rootPublicKey(ctx context.Context, signing signingOptions, keyARN, publicKeyPath string) (*ecdsa.PublicKey, error) {
	if publicKeyPath != "" {
		raw, err := os.ReadFile(publicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read --%s: %w", flagPublicKey, err)
		}

		return ceremony.ParsePublicKeyPEM(raw)
	}

	client, err := signing.client(ctx, keyARN)
	if err != nil {
		return nil, err
	}

	signer, err := kmssigner.New(ctx, client, keyARN)
	if err != nil {
		return nil, err
	}

	key, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("KMS key %s is not an ECDSA key", keyARN)
	}

	return key, nil
}

func printRootTemplate(out io.Writer, plan *ceremony.RootPlan, check *custodyCheck, offline bool) error {
	existing, found, err := plan.ExistingRoot()
	if err != nil {
		return err
	}

	var text strings.Builder

	text.WriteString(plan.Text())
	text.WriteString("\n" + check.text)

	if found {
		fmt.Fprintf(&text, "\nthe artifact %s already holds exactly this root (fingerprint SHA256 %s): nothing to sign\n",
			plan.ArtifactPath, existing.FingerprintSHA256)
		_, err = io.WriteString(out, text.String())

		return err
	}

	if !offline {
		fmt.Fprintf(&text, "\nthe public key was read from KMS; pass --%s to review without a credential\n", flagPublicKey)
	}

	fmt.Fprintf(&text, "\nnothing was signed. Signing fires the root key's Sign alarm. To sign exactly this, rerun with\n"+
		"  --%s %s%s\n", flagConfirmTemplate, plan.TemplateSHA256, check.rerun)
	_, err = io.WriteString(out, text.String())

	return err
}

func runImportRoot(ctx context.Context, out io.Writer, signing signingOptions, check *custodyCheck,
	spec ceremony.RootSpec, keyARN, artifactPath, certificatePath string,
) error {
	client, err := signing.client(ctx, keyARN)
	if err != nil {
		return err
	}

	result, err := ceremony.CreateRoot(ctx, client, spec, ceremony.RootOptions{
		KeyARN:                keyARN,
		ArtifactPath:          artifactPath,
		ImportCertificatePath: certificatePath,
	})
	if err != nil {
		return err
	}

	raw, err := yaml.Marshal(result.Artifact)
	if err != nil {
		return fmt.Errorf("marshal public ceremony output: %w", err)
	}

	_, err = io.WriteString(out, check.text+"\nrecorded without signing: "+artifactPath+"\n"+string(raw))

	return err
}

func countTrue(values ...bool) int {
	n := 0

	for _, value := range values {
		if value {
			n++
		}
	}

	return n
}

package esoaws

import (
	"encoding/json"
	"strings"
	"testing"

	awspulumi "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func keyArgs(p pulumi.ProviderResource) SecureStringKeyArgs {
	w := writersArgs(p)
	w.Grants = nil

	return SecureStringKeyArgs{
		Name:        "a-app-client",
		Description: "SSM SecureStrings under /app/client/",
		Alias:       "alias/a-app-client",
		PolicyID:    "app-client-key",
		Writers:     w,
		Writer:      WriteGrant{Name: "a-eso-app-client-writer", Cluster: "a", Prefix: "/app/client/"},
		Readers: []KeyReader{{
			Sid:            "TaskRolesDecryptTheClientCredential",
			RoleARNPattern: "arn:aws:iam::" + clusterAccount + ":role/task-*",
			Parameters:     []string{"/app/client/ca", "/app/client/cert"},
		}},
		ReaderStatements:   []map[string]any{{"Sid": "Prebuilt", "Effect": "Allow"}},
		Recovery:           "arn:aws:iam::" + clusterAccount + ":role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_recovery_*",
		RecoveryParameters: []string{"/app/client/*"},
	}
}

func TestSecureStringKeyPolicy(t *testing.T) {
	doc, err := SecureStringKeyPolicy(keyArgs(nil))
	require.NoError(t, err)
	golden(t, "secure-string-key-policy.json", doc)

	var parsed struct {
		Id        string
		Statement []map[string]any
	}

	require.NoError(t, json.Unmarshal([]byte(doc), &parsed))
	assert.Equal(t, "app-client-key", parsed.Id)

	var sids []string
	for _, st := range parsed.Statement {
		sids = append(sids, st["Sid"].(string))
	}

	assert.Equal(t, []string{"KeyAdministration", "ExternalSecretsWriterAEsoAppClientWriter",
		"TaskRolesDecryptTheClientCredential", "Prebuilt", "BreakglassRecovers"}, sids)

	// The root statement carries no cryptographic action.
	assert.NotContains(t, strings.Join(stringsOf(parsed.Statement[0]["Action"]), " "), "Decrypt")
}

func stringsOf(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}

	return out
}

func TestSecureStringKeyPolicyRefuses(t *testing.T) {
	for name, change := range map[string]func(*SecureStringKeyArgs){
		"grants set":          func(a *SecureStringKeyArgs) { a.Writers.Grants = []WriteGrant{a.Writer} },
		"writer names a key":  func(a *SecureStringKeyArgs) { a.Writer.KMSKeyARN = writerKeyARN },
		"alias without alias": func(a *SecureStringKeyArgs) { a.Alias = "a-app-client" },
		"recovery alone":      func(a *SecureStringKeyArgs) { a.RecoveryParameters = nil },
		"duplicate sid":       func(a *SecureStringKeyArgs) { a.Readers[0].Sid = "BreakglassRecovers" },
		"empty reader":        func(a *SecureStringKeyArgs) { a.Readers[0].Parameters = nil },
		"unknown cluster":     func(a *SecureStringKeyArgs) { a.Writer.Cluster = "z" },
	} {
		t.Run(name, func(t *testing.T) {
			a := keyArgs(nil)
			change(&a)

			_, err := SecureStringKeyPolicy(a)
			assert.Error(t, err)
		})
	}
}

func TestNewSecureStringKey(t *testing.T) {
	rec := &recorder{}

	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := awspulumi.NewProvider(ctx, "cluster", &awspulumi.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		_, err = NewSecureStringKey(ctx, keyArgs(p))

		return err
	}, pulumi.WithMocks("example", "stack", rec)))

	got := map[string]recorded{}
	for _, r := range rec.all {
		got[r.Type+" "+r.Name] = r
	}

	key := got["aws:kms/key:Key a-app-client"]
	require.NotEmpty(t, key.Type)
	assert.InDelta(t, 30, key.Inputs["deletionWindowInDays"].NumberValue(), 0)
	assert.True(t, key.Inputs["enableKeyRotation"].BoolValue())

	policy, err := SecureStringKeyPolicy(keyArgs(nil))
	require.NoError(t, err)
	assert.Equal(t, policy, key.Inputs["policy"].StringValue())

	assert.Contains(t, got, "aws:kms/alias:Alias a-app-client")
	assert.Contains(t, got, KindWriters+" a-parameter-writers")
	assert.Contains(t, got, KindIAMRole+" a-eso-app-client-writer")
	assert.Contains(t, got, KindIAMRolePolicy+" a-eso-app-client-writer-policy")
}

func TestNewSecureStringKeyRegistersNothingWhenInvalid(t *testing.T) {
	rec := &recorder{}

	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := awspulumi.NewProvider(ctx, "cluster", &awspulumi.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		a := keyArgs(p)
		a.Writer.Prefix = "/"

		_, err = NewSecureStringKey(ctx, a)
		assert.Error(t, err)

		return nil
	}, pulumi.WithMocks("example", "stack", rec)))

	for _, r := range rec.all {
		assert.NotContains(t, r.Type, "kms", "nothing is registered")
	}
}

func TestCheckWriterClaims(t *testing.T) {
	ok := []WriterClaim{
		{Label: "a/client", Scope: "a", Role: "a-eso-client-writer", Prefix: "/ci/a/client/"},
		{Label: "a/server", Scope: "a", Role: "a-eso-server-writer", Prefix: "/ci/a/server/"},
		{Label: "b/client", Scope: "b", Role: "a-eso-client-writer", Prefix: "/ci/a/client/"},
	}
	require.NoError(t, CheckWriterClaims(ok))

	for name, tc := range map[string]struct {
		change func([]WriterClaim) []WriterClaim
		want   string
	}{
		"role name":     {func(c []WriterClaim) []WriterClaim { c[0].Role = "no spaces allowed"; return c }, "not an IAM role name"},
		"prefix shape":  {func(c []WriterClaim) []WriterClaim { c[0].Prefix = "/ci/a/client"; return c }, "end with"},
		"wildcard":      {func(c []WriterClaim) []WriterClaim { c[0].Prefix = "/ci/*/"; return c }, "no wildcards"},
		"whole account": {func(c []WriterClaim) []WriterClaim { c[0].Prefix = "/"; return c }, "every parameter"},
		"same prefix":   {func(c []WriterClaim) []WriterClaim { c[1].Prefix = c[0].Prefix; return c }, "one role per prefix"},
		"same role":     {func(c []WriterClaim) []WriterClaim { c[1].Role = c[0].Role; return c }, "role a-eso-client-writer is"},
		"nested":        {func(c []WriterClaim) []WriterClaim { c[1].Prefix = "/ci/a/client/deep/"; return c }, "is inside a/client's"},
	} {
		t.Run(name, func(t *testing.T) {
			err := CheckWriterClaims(tc.change(append([]WriterClaim(nil), ok...)))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

package esoaws

import (
	"sort"
	"strings"
	"sync"
	"testing"

	awspulumi "github.com/pulumi/pulumi-aws/sdk/v7/go/aws"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The writer's key is in the cluster's own account: a writer and the
// parameters it writes share one.
const writerKeyARN = "arn:aws:kms:" + region + ":" + clusterAccount + ":key/abcd1234-12ab-34cd-56ef-1234567890ab"

func writersArgs(p pulumi.ProviderResource) WritersArgs {
	return WritersArgs{
		Name:      "a-parameter-writers",
		Provider:  p,
		AccountID: clusterAccount,
		Region:    region,
		Clusters:  []Cluster{{Name: "a", Mode: PodIdentityMode, PodIdentity: &PodIdentity{RoleARN: esoRole}}},
		Grants: []WriteGrant{{
			Name:      "a-eso-app-client-writer",
			Cluster:   "a",
			Prefix:    "/app/client/",
			KMSKeyARN: writerKeyARN,
		}},
		PermissionsBoundary: "arn:aws:iam::" + clusterAccount + ":policy/example-boundary",
		Tags:                map[string]string{"owner": "platform"},
	}
}

func TestTheWriters(t *testing.T) {
	rec := &recorder{}

	var (
		wg  sync.WaitGroup
		arn string
	)

	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := awspulumi.NewProvider(ctx, "cluster", &awspulumi.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		w, err := NewWriters(ctx, writersArgs(p))
		if err != nil {
			return err
		}

		wg.Add(1)
		w.RoleARNs["a-eso-app-client-writer"].ApplyT(func(s string) string {
			arn = s
			wg.Done()

			return s
		})

		return nil
	}, pulumi.WithMocks("example", "stack", rec)))

	wg.Wait()

	var names []string

	got := map[string]recorded{}

	for _, r := range rec.all {
		if strings.HasPrefix(r.Type, "pulumi:providers:") {
			continue
		}

		names = append(names, r.Type+" "+r.Name)
		got[r.Type+" "+r.Name] = r
	}

	sort.Strings(names)
	assert.Equal(t, []string{
		KindIAMRole + " a-eso-app-client-writer",
		KindIAMRolePolicy + " a-eso-app-client-writer-policy",
		KindWriters + " a-parameter-writers",
	}, names)

	role := got[KindIAMRole+" a-eso-app-client-writer"]
	assert.Contains(t, role.Parent, "Writers::a-parameter-writers")
	assert.Equal(t, "arn:aws:iam::"+clusterAccount+":policy/example-boundary", role.Inputs["permissionsBoundary"].StringValue())
	assert.Equal(t, "platform", role.Inputs["tags"].ObjectValue()["owner"].StringValue())
	golden(t, "writer-trust.json", role.Inputs["assumeRolePolicy"].StringValue())

	policy := got[KindIAMRolePolicy+" a-eso-app-client-writer-policy"].Inputs
	assert.Equal(t, "a-eso-app-client-writer", policy["name"].StringValue())
	golden(t, "writer-policy.json", policy["policy"].StringValue())

	assert.Equal(t, "arn:aws:iam::mock:role/a-eso-app-client-writer", arn)
}

// What the writer may do, said in words rather than read off a golden.
func TestWriterPolicyIsLeastPrivilege(t *testing.T) {
	args := writersArgs(nil)

	doc, err := WriterPolicy(args, args.Grants[0])
	require.NoError(t, err)

	assert.Contains(t, doc, `"Resource":["arn:aws:ssm:`+region+`:`+clusterAccount+`:parameter/app/client/*"]`)

	for _, want := range []string{"ssm:PutParameter", "ssm:GetParameter", "ssm:AddTagsToResource", "ssm:ListTagsForResource",
		"kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", `"kms:ViaService":"ssm.` + region + `.amazonaws.com"`} {
		assert.Contains(t, doc, want)
	}

	for _, forbidden := range []string{"ssm:DeleteParameter", "ssm:DescribeParameters", "ssm:GetParametersByPath", "ssm:GetParameters\"",
		"ssm:RemoveTagsFromResource", "ssm:*", "kms:*", "iam:", "sts:", "parameter/*", `"Resource":"*"`} {
		assert.NotContains(t, doc, forbidden)
	}
}

func TestWriterTrustIsTheClusterIdentityAlone(t *testing.T) {
	args := writersArgs(nil)

	doc, err := WriterTrustPolicy(args, args.Grants[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{"Version":"2012-10-17","Statement":[{"Sid":"ExternalSecretsOperator","Effect":"Allow",
		"Principal":{"AWS":"`+esoRole+`"},"Action":["sts:AssumeRole","sts:TagSession"],
		"Condition":{"ForAllValues:StringEquals":{"aws:TagKeys":["eks-cluster-arn","eks-cluster-name",
		"kubernetes-namespace","kubernetes-service-account","kubernetes-pod-name","kubernetes-pod-uid"]}}}]}`, doc)
}

func TestWriterKeyPolicyStatement(t *testing.T) {
	args := writersArgs(nil)

	st, err := WriterKeyPolicyStatement(args, args.Grants[0])
	require.NoError(t, err)

	raw, err := jsonDoc(st)
	require.NoError(t, err)
	golden(t, "writer-key-statement.json", raw)

	assert.Equal(t, "ExternalSecretsWriterAEsoAppClientWriter", st["Sid"])
}

// The key made by the same program: the policy waits for its ARN and is built,
// and checked, then.
func TestWritersTakeTheKeyAsAnOutput(t *testing.T) {
	rec := &recorder{}

	require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
		p, err := awspulumi.NewProvider(ctx, "cluster", &awspulumi.ProviderArgs{Region: pulumi.String(region)})
		if err != nil {
			return err
		}

		args := writersArgs(p)
		args.Grants[0].KMSKeyARN = ""
		args.Grants[0].KMSKey = pulumi.String(writerKeyARN)

		_, err = NewWriters(ctx, args)

		return err
	}, pulumi.WithMocks("example", "stack", rec)))

	var policy string

	for _, r := range rec.all {
		if r.Type == KindIAMRolePolicy {
			policy = r.Inputs["policy"].StringValue()
		}
	}

	golden(t, "writer-policy.json", policy)
}

func TestWriterPolicyRefusesAnOutputKey(t *testing.T) {
	args := writersArgs(nil)
	args.Grants[0].KMSKeyARN, args.Grants[0].KMSKey = "", pulumi.String(writerKeyARN)

	_, err := WriterPolicy(args, args.Grants[0])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "known at apply")
}

func TestWritersRefuse(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(a *WritersArgs)
		why  string
	}{
		"no key":   {func(a *WritersArgs) { a.Grants[0].KMSKeyARN = "" }, "KMSKeyARN (or KMSKey) is required"},
		"two keys": {func(a *WritersArgs) { a.Grants[0].KMSKey = pulumi.String(writerKeyARN) }, "both set"},
		"an alias": {func(a *WritersArgs) {
			a.Grants[0].KMSKeyARN = "arn:aws:kms:" + region + ":" + clusterAccount + ":alias/x"
		}, "not a KMS key ARN"},
		"key elsewhere": {func(a *WritersArgs) { a.Grants[0].KMSKeyARN = strings.Replace(writerKeyARN, region, "eu-other-1", 1) }, "not in this source's region"},
		"root prefix":   {func(a *WritersArgs) { a.Grants[0].Prefix = "/" }, "every parameter in the account"},
		"no trailing":   {func(a *WritersArgs) { a.Grants[0].Prefix = "/app/client" }, "start and end with"},
		"a wildcard":    {func(a *WritersArgs) { a.Grants[0].Prefix = "/app/*/" }, "no wildcards"},
		"empty segment": {func(a *WritersArgs) { a.Grants[0].Prefix = "/app//client/" }, "not a parameter path"},
		"no cluster":    {func(a *WritersArgs) { a.Grants[0].Cluster = "z" }, "not in args.Clusters"},
		"bad role name": {func(a *WritersArgs) { a.Grants[0].Name = "a b" }, "not an IAM role name"},
		"no grants":     {func(a *WritersArgs) { a.Grants = nil }, "args.Grants is empty"},
		"no provider":   {func(a *WritersArgs) { a.Provider = nil }, "args.Provider is nil"},
		"web identity": {func(a *WritersArgs) {
			a.Clusters = []Cluster{{Name: "a", Mode: WebIdentityMode, WebIdentity: &WebIdentity{IssuerURL: issuerB}}}
		}, "a writer role trusts a PodIdentity cluster"},
		"unused cluster": {func(a *WritersArgs) {
			a.Clusters = append(a.Clusters, Cluster{Name: "b", Mode: PodIdentityMode, PodIdentity: &PodIdentity{RoleARN: esoRole}})
		}, "no grant names cluster"},
		"shared prefix": {func(a *WritersArgs) {
			a.Grants = append(a.Grants, WriteGrant{Name: "other", Cluster: "a", Prefix: "/app/client/", KMSKeyARN: writerKeyARN})
		}, "one role per prefix"},
		"duplicate name": {func(a *WritersArgs) {
			a.Grants = append(a.Grants, WriteGrant{Name: "a-eso-app-client-writer", Cluster: "a", Prefix: "/other/", KMSKeyARN: writerKeyARN})
		}, "duplicate name"},
		"bad boundary": {func(a *WritersArgs) { a.PermissionsBoundary = "nope" }, "PermissionsBoundary"},
		"bad account":  {func(a *WritersArgs) { a.AccountID = "1" }, "12-digit"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := &recorder{}

			require.NoError(t, pulumi.RunErr(func(ctx *pulumi.Context) error {
				p, err := awspulumi.NewProvider(ctx, "cluster", &awspulumi.ProviderArgs{})
				if err != nil {
					return err
				}

				args := writersArgs(p)
				args.Grants = append([]WriteGrant(nil), args.Grants...)
				tc.edit(&args)

				_, err = NewWriters(ctx, args)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.why)

				return nil
			}, pulumi.WithMocks("example", "stack", rec)))

			for _, r := range rec.all {
				assert.True(t, strings.HasPrefix(r.Type, "pulumi:providers:"), "registered %s", r.Type)
			}
		})
	}
}

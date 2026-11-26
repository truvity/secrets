package custody

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The documents a custody WITHOUT StrictRoot renders, byte for byte: the key
// policy with and without a break-glass pattern, the alert event pattern, and
// every input of every resource a deploy declares. The goldens were written by
// the module BEFORE StrictRoot existed, so this test proves that an estate
// upgrading without setting it previews no change on its live roots.
// Regenerate only for an intended change: UPDATE_GOLDEN=1 go test ./pkg/custody/.
func TestDocumentsWithoutStrictRootAreUnchanged(t *testing.T) {
	breakGlass := testArgs()
	breakGlass.BreakGlassPrincipalARNPattern = testBreakGlass

	plain, err := keyPolicy(DefaultPartition, testAccount, testPattern, "admin", "ceremony", policyOptions{})
	require.NoError(t, err)
	withBreakGlass, err := keyPolicy(DefaultPartition, testAccount, testPattern, "admin", "ceremony",
		policyOptions{breakGlassPrincipalARNPattern: testBreakGlass})
	require.NoError(t, err)
	pattern, err := signEventPattern(primaryKeyARN, "mrk-primary", "alias/private-pki/root/"+testGeneration, primaryAliasARN)
	require.NoError(t, err)

	documents := map[string]string{
		"key-policy":                   plain,
		"key-policy-break-glass":       withBreakGlass,
		"sign-event-pattern":           pattern,
		"deploy-resources":             deployedInputs(t, testArgs()),
		"deploy-resources-break-glass": deployedInputs(t, breakGlass),
	}
	for name, got := range documents {
		path := filepath.Join("testdata", "golden", name+".json")
		if os.Getenv("UPDATE_GOLDEN") != "" {
			require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
			require.NoError(t, os.WriteFile(path, []byte(got+"\n"), 0o644))
			continue
		}
		want, err := os.ReadFile(path)
		require.NoError(t, err, name)
		assert.Equal(t, string(want), got+"\n", name)
	}
}

// deployedInputs renders every declared resource's type, name and inputs as
// one sorted JSON document.
func deployedInputs(t *testing.T, args Args) string {
	t.Helper()
	type entry struct {
		Type   string         `json:"type"`
		Name   string         `json:"name"`
		Inputs map[string]any `json:"inputs"`
	}
	var entries []entry
	for kind, resources := range deploy(t, args) {
		for _, item := range resources {
			entries = append(entries, entry{Type: kind, Name: item.Name, Inputs: item.Inputs.Mappable()})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Name < entries[j].Name
	})
	raw, err := json.MarshalIndent(entries, "", "  ")
	require.NoError(t, err)
	return string(raw)
}

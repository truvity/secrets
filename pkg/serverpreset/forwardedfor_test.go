package serverpreset_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/serverpreset"
)

const forwardedForHCL = `ui = true
listener "tcp" {
  address         = "[::]:8200"
  cluster_address = "[::]:8201"
  tls_cert_file   = "/c/tls.crt"
  tls_key_file    = "/c/tls.key"
}
listener "tcp" {
  address       = "[::]:9101"
  tls_cert_file = "/c/tls.crt"
  tls_key_file  = "/c/tls.key"
  telemetry {
    metrics_only                   = true
    unauthenticated_metrics_access = true
  }
}
storage "raft" {
  path = "/d"
}
`

var forwardedForRanges = []string{"10.20.32.0/19", "10.20.64.0/19", "10.20.96.0/19"}

// The settings go into the API listener and ONLY it: the metrics listener is
// open without a token by design and must not be taught to trust a header.
func TestWithForwardedForIsTheAPIListenersAlone(t *testing.T) {
	t.Parallel()

	got, err := serverpreset.WithForwardedFor(forwardedForHCL, forwardedForRanges, 1)
	require.NoError(t, err)

	api, metrics, ok := strings.Cut(got, "listener \"tcp\" {\n  address       = \"[::]:9101\"")
	require.True(t, ok)

	assert.Contains(t, api, `x_forwarded_for_authorized_addrs      = "10.20.32.0/19,10.20.64.0/19,10.20.96.0/19"`)
	assert.Contains(t, api, `x_forwarded_for_hop_skips             = "1"`)
	assert.Contains(t, api, `x_forwarded_for_reject_not_present    = false`)
	assert.Contains(t, api, `x_forwarded_for_reject_not_authorized = false`)
	assert.NotContains(t, metrics, "x_forwarded_for")
	assert.Equal(t, 4, strings.Count(got, "x_forwarded_for_"))

	// Nothing else moved: removing the four lines gives the input back.
	var kept []string

	for _, line := range strings.Split(got, "\n") {
		if !strings.Contains(line, "x_forwarded_for_") {
			kept = append(kept, line)
		}
	}

	assert.Equal(t, forwardedForHCL, strings.Join(kept, "\n"))
}

func TestWithForwardedForWritesTheHopSkipsItIsGiven(t *testing.T) {
	t.Parallel()

	got, err := serverpreset.WithForwardedFor(forwardedForHCL, forwardedForRanges, 2)
	require.NoError(t, err)
	assert.Contains(t, got, `x_forwarded_for_hop_skips             = "2"`)
}

func TestWithForwardedForRefuses(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		hcl  string
		cidr []string
		hops int
		want string
	}{
		"no range":       {forwardedForHCL, nil, 1, "no address range"},
		"no hops":        {forwardedForHCL, forwardedForRanges, 0, "hop_skips"},
		"a host address": {forwardedForHCL, []string{"10.64.32.5/19"}, 1, "not a network address"},
		"not a CIDR":     {forwardedForHCL, []string{"10.20.32.0"}, 1, "not a network address"},
		"no listener":    {"ui = true\n", forwardedForRanges, 1, "no listener"},
		"already set": {
			strings.Replace(forwardedForHCL, `tls_key_file    = "/c/tls.key"`, "x_forwarded_for_hop_skips = 2", 1),
			forwardedForRanges, 1, "not the API listener",
		},
		"the metrics one first": {strings.Replace(forwardedForHCL, "cluster_address", "address2", 1), forwardedForRanges, 1, "not the API listener"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := serverpreset.WithForwardedFor(tc.hcl, tc.cidr, tc.hops)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

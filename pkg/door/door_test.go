package door_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/truvity/secrets/pkg/door"
)

type request struct {
	method, path string
	token        string // empty: no header
	hasToken     bool
}

func tok() (string, bool) { return "t", true }

func get(path string, token bool) request {
	return req("GET", path, token)
}

func req(method, path string, token bool) request {
	r := request{method: method, path: path}
	if token {
		r.token, r.hasToken = tok()
	}

	return r
}

func paths(t *testing.T) *door.Paths {
	t.Helper()

	p, err := door.New([]string{"dev", "prod", "stage"}, door.Mounts{KV: "kv", Issuing: "pki", SSH: "ssh"})
	require.NoError(t, err)

	return p
}

func matches(t *testing.T, ms []door.Match, r request) bool {
	t.Helper()

	for _, m := range ms {
		if m.Method != "" && m.Method != r.method {
			continue
		}

		re, err := regexp.Compile("^(?:" + m.Path + ")$")
		require.NoError(t, err, "the pattern is RE2: %s", m.Path)

		if !re.MatchString(r.path) {
			continue
		}

		if m.RequireToken && !(r.hasToken && regexp.MustCompile("^(?:"+door.TokenPattern+")$").MatchString(r.token)) {
			continue
		}

		return true
	}

	return false
}

// routeOf names the route set that serves a request: the API (login plus
// token-bearing data), the console, or none. It fails when both do.
func routeOf(t *testing.T, p *door.Paths, r request) string {
	t.Helper()

	api := matches(t, p.Login(), r) || matches(t, door.RequireToken(p.Data()), r)
	ui := matches(t, p.Console(), r)

	require.False(t, api && ui, "%s %s is served by both route sets", r.method, r.path)

	switch {
	case api:
		return "api"
	case ui:
		return "ui"
	}

	return ""
}

func TestAllowList(t *testing.T) {
	p := paths(t)

	for name, tc := range map[string]struct {
		req  request
		want string
	}{
		"login":                      {req("POST", "/v1/auth/jwt-roster/login", false), "api"},
		"login in an environment":    {req("POST", "/v1/dev/auth/jwt-roster/login", false), "api"},
		"login in a project":         {req("POST", "/v1/dev/landing/auth/jwt-roster/login", false), "api"},
		"login, wrong method":        {req("GET", "/v1/auth/jwt-roster/login", false), ""},
		"oidc auth url":              {req("POST", "/v1/auth/oidc/oidc/auth_url", false), "api"},
		"oidc callback":              {get("/v1/dev/auth/oidc/oidc/callback", false), "api"},
		"kv read, path namespace":    {get("/v1/dev/kv/data/ci/key", true), "api"},
		"kv read, header namespace":  {get("/v1/kv/data/ci/key", true), "api"},
		"kv list":                    {get("/v1/prod/kv/metadata/", true), "api"},
		"kv write, nested":           {req("POST", "/v1/dev/landing/kv/data/a/b.c_d-e", true), "api"},
		"kv delete":                  {req("DELETE", "/v1/dev/landing/kv/metadata/x", true), "api"},
		"issuing CA sign":            {req("POST", "/v1/stage/pki/sign/role-a", true), "api"},
		"ssh sign":                   {req("POST", "/v1/dev/ssh/sign/role-b", true), "api"},
		"token lookup-self":          {get("/v1/auth/token/lookup-self", true), "api"},
		"token revoke-self":          {req("POST", "/v1/auth/token/revoke-self", true), "api"},
		"capabilities-self":          {req("POST", "/v1/sys/capabilities-self", true), "api"},
		"CLI kv version probe":       {get("/v1/sys/internal/ui/mounts/kv/data/x", true), "api"},
		"CLI kv version probe, root": {get("/v1/sys/internal/ui/mounts", true), "api"},

		"kv read, no token":     {get("/v1/dev/kv/data/x", false), ""},
		"sign, no token":        {req("POST", "/v1/dev/pki/sign/role-a", false), ""},
		"revoke-self, no token": {req("POST", "/v1/auth/token/revoke-self", false), ""},
		"mounts probe, no tok":  {get("/v1/sys/internal/ui/mounts", false), ""},

		"seal status, pre-login": {get("/v1/sys/seal-status", false), "ui"},
		"seal status, head":      {req("HEAD", "/v1/sys/seal-status", false), "ui"},
		"ui feature flags":       {get("/v1/sys/internal/ui/feature-flags", false), "ui"},
		"ui namespaces":          {get("/v1/sys/internal/ui/namespaces", true), "ui"},
		"ui resultant acl":       {get("/v1/dev/sys/internal/ui/resultant-acl", true), "ui"},
		"mounts listing":         {get("/v1/sys/mounts", true), "ui"},
		"policies listing":       {get("/v1/dev/sys/policies/acl", true), "ui"},
		"leader":                 {get("/v1/sys/leader", false), "ui"},
		"health":                 {get("/v1/sys/health", false), "ui"},
		"ui headers":             {get("/v1/sys/config/ui/headers/", true), "ui"},

		"generate-root":           {req("PUT", "/v1/sys/generate-root/attempt", true), ""},
		"rekey":                   {req("PUT", "/v1/sys/rekey/init", true), ""},
		"init":                    {req("PUT", "/v1/sys/init", false), ""},
		"unseal":                  {req("PUT", "/v1/sys/unseal", false), ""},
		"seal":                    {req("PUT", "/v1/sys/seal", true), ""},
		"namespace seal":          {req("PUT", "/v1/dev/sys/seal", true), ""},
		"step-down":               {req("PUT", "/v1/sys/step-down", true), ""},
		"raft snapshot":           {get("/v1/sys/storage/raft/snapshot", true), ""},
		"mount an engine":         {req("POST", "/v1/sys/mounts/evil", true), ""},
		"policy write":            {req("PUT", "/v1/sys/policies/acl/root", true), ""},
		"sys method delete":       {req("DELETE", "/v1/sys/mounts", true), ""},
		"plugins":                 {req("POST", "/v1/sys/plugins/catalog/auth/x", true), ""},
		"token create":            {req("POST", "/v1/auth/token/create", true), ""},
		"accessor lookup":         {req("POST", "/v1/auth/token/lookup-accessor", true), ""},
		"another mount's data":    {get("/v1/dev/secret/data/x", true), ""},
		"other CA mount":          {req("POST", "/v1/dev/pki-origin/sign/origin", true), ""},
		"workload mount login":    {req("POST", "/v1/dev/auth/jwt-dev/login", false), ""},
		"unknown namespace":       {get("/v1/other/kv/data/x", true), ""},
		"sys posing as namespace": {req("PUT", "/v1/sys/kv/data/x", true), ""},
		"encoded slash":           {get("/v1/dev/kv/data/..%2fsys%2fseal", true), ""},
		"encoded dot":             {get("/v1/dev/kv/data/%2e%2e/x", true), ""},
		"dot segment":             {get("/v1/dev/kv/data/../../sys/seal", true), ""},
		"doubled slash":           {get("/v1/dev/kv/data//x", true), ""},
		"hidden name":             {get("/v1/dev/kv/data/.hidden", true), ""},
		"space in a key":          {get("/v1/dev/kv/data/a b", true), ""},
		"newline in the path":     {get("/v1/dev/kv/data/a\nb", true), ""},
		"sign with a subpath":     {req("POST", "/v1/dev/pki/sign/a/b", true), ""},
		"pki issue":               {req("POST", "/v1/dev/pki/issue/private", true), ""},
		"kv config":               {req("POST", "/v1/dev/kv/config", true), ""},
		"kv mount itself":         {req("DELETE", "/v1/dev/kv", true), ""},
		"trailing on self":        {get("/v1/auth/token/lookup-self/x", true), ""},
		"unlisted ui read":        {get("/v1/sys/internal/ui/other", true), ""},
		"metrics":                 {get("/metrics", false), ""},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, routeOf(t, p, tc.req), "%s %s", tc.req.method, tc.req.path)
		})
	}
}

// Every path of the table, with every method and with and without the token
// header, is in at most one route set (routeOf fails on a second).
func TestNoOverlapWhateverTheMethodOrHeader(t *testing.T) {
	p := paths(t)

	for _, path := range []string{
		"/v1/auth/jwt-roster/login", "/v1/auth/oidc/oidc/auth_url", "/v1/dev/auth/oidc/oidc/callback",
		"/v1/dev/kv/data/x", "/v1/sys/capabilities-self", "/v1/sys/internal/ui/mounts",
		"/v1/sys/internal/ui/mounts/kv/data/x", "/v1/sys/internal/ui/namespaces", "/v1/sys/mounts",
		"/v1/sys/seal-status", "/v1/sys/health", "/v1/dev/sys/policies/acl", "/v1/sys/config/ui/headers/",
	} {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
			for _, token := range []bool{false, true} {
				routeOf(t, p, req(method, path, token))
			}
		}
	}
}

func TestRequireTokenSetsTheFlagAndLeavesTheInput(t *testing.T) {
	in := []door.Match{{Path: "^/a$"}}
	out := door.RequireToken(in)

	assert.True(t, out[0].RequireToken)
	assert.False(t, in[0].RequireToken)
}

func TestNewRefuses(t *testing.T) {
	good := door.Mounts{KV: "kv", Issuing: "pki", SSH: "ssh"}

	for name, tc := range map[string]struct {
		namespaces []string
		mounts     door.Mounts
		want       string
	}{
		"no namespaces":     {nil, good, "namespace names"},
		"not a DNS label":   {[]string{"Dev"}, good, "not a DNS label"},
		"a regex namespace": {[]string{"a|b"}, good, "not a DNS label"},
		"empty KV mount":    {[]string{"dev"}, door.Mounts{Issuing: "pki", SSH: "ssh"}, "Mounts.KV"},
		"nested SSH mount":  {[]string{"dev"}, door.Mounts{KV: "kv", Issuing: "pki", SSH: "a/b"}, "Mounts.SSH"},
		"dot-led PKI mount": {[]string{"dev"}, door.Mounts{KV: "kv", Issuing: "..", SSH: "ssh"}, "Mounts.Issuing"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := door.New(tc.namespaces, tc.mounts)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

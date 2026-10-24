// Package door derives the path allow-list of an OpenBAO server's PUBLIC
// door: the requests a gateway that terminates the client's TLS may route to
// the server, and nothing else.
//
// The package is gateway-neutral. It returns [Match] rows (a full-string RE2
// path pattern, an optional method, and whether the request must carry a
// token header); the consuming repository turns them into its own route
// objects (Gateway API HTTPRoute matches, an Envoy config, a proxy rule) and
// decides which hosts and clusters get a door at all.
//
// The doors split into two route sets that share a host and must not overlap:
//
//   - API, what people and CI do: [Paths.Login] (open) and [Paths.Data]
//     (behind [RequireToken]).
//   - Console, the web UI's reads, behind a sign-in the gateway owns:
//     [Paths.Console]. Its shell (`/`, `/ui`) is the consumer's.
//
// What the allow-list decides is the SHAPE of the public path. Who may do
// anything stays OpenBAO's; the matches only narrow what an unauthenticated
// stranger can even ask:
//
//   - a path ALLOW-LIST and nothing else: sys/generate-root*, sys/rekey*,
//     sys/init, sys/unseal, sys/seal, sys/step-down, sys/raft, sys/config,
//     sys/plugins, auth/token/create and every other path not named below
//     match nothing. There is no deny list to forget a path from.
//   - NAMESPACES. A client names a namespace in the path (/v1/<ns>/kv/data/x)
//     or in the X-Vault-Namespace header (/v1/kv/data/x). Every pattern takes
//     an OPTIONAL namespace prefix built from the names given to [New], with
//     one nested level, so both forms match and a prefix that names no
//     namespace of the caller's does not. The header's value is OpenBAO's to
//     validate.
//   - what the patterns refuse on purpose: a percent sign (an encoded slash
//     is how a path walks out of the pattern that admitted it) and a segment
//     that does not start with a letter or a digit (`..`, `.`, hidden names).
//     Patterns are full-string matches; a gateway that normalizes dot segments
//     and merges slashes before matching (Envoy Gateway's defaults) is
//     assumed.
package door

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/truvity/secrets/pkg/model"
)

const (
	// HeaderToken is the header whose presence [RequireToken] demands.
	HeaderToken = "X-Vault-Token"

	// TokenPattern is the header value pattern: at least one character.
	// OpenBAO validates the value itself.
	TokenPattern = ".+"

	// Segment is one path segment of a key, a role or a mount path. It starts
	// with a letter or a digit (never `.`/`..`), and holds none of the
	// characters that change a path's meaning.
	Segment = `[A-Za-z0-9][A-Za-z0-9._-]*`

	// Tail is zero or more further segments, and an optional trailing slash
	// (a KV list is `metadata/` as often as `metadata`).
	Tail = `(?:/` + Segment + `)*/?`
)

var namespaceName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

type (
	// Match is one route match: a request matches when its path matches Path
	// in full, its method equals Method (any method when empty) and, when
	// RequireToken is set, it carries a [HeaderToken] header of at least one
	// character.
	Match struct {
		// Path is a full-string RE2 pattern for the request path.
		Path string
		// Method is the HTTP method, or empty for any.
		Method string
		// RequireToken adds the presence check on [HeaderToken].
		RequireToken bool
	}

	// Mounts are the mount paths of the server, as the consumer lays them out.
	Mounts struct {
		// KV is the KV v2 mount people and CI read and write.
		KV string
		// Issuing is the PKI mount whose `sign/<role>` endpoint is exposed.
		Issuing string
		// SSH is the SSH CA mount whose `sign/<role>` endpoint is exposed.
		SSH string
	}

	// Paths builds the allow-list's matches for one server's namespaces.
	Paths struct {
		prefix string
		mounts Mounts
	}
)

// New refuses an empty namespace list (a prefix that admitted nothing would
// route nothing, and one that admitted anything would not be an allow-list),
// a name that is not a DNS label, and a mount path that is not a plain
// segment sequence.
func New(namespaces []string, mounts Mounts) (*Paths, error) {
	if len(namespaces) == 0 {
		return nil, errors.New("door: the public door needs the server's namespace names; none were given")
	}

	for field, path := range map[string]string{"KV": mounts.KV, "Issuing": mounts.Issuing, "SSH": mounts.SSH} {
		if !regexp.MustCompile(`^` + Segment + `$`).MatchString(path) {
			return nil, fmt.Errorf("door: Mounts.%s %q is not a single mount path segment", field, path)
		}
	}

	quoted := make([]string, 0, len(namespaces))

	for _, name := range slices.Sorted(slices.Values(namespaces)) {
		if !namespaceName.MatchString(name) {
			return nil, fmt.Errorf("door: namespace %q is not a DNS label", name)
		}

		quoted = append(quoted, regexp.QuoteMeta(name))
	}

	return &Paths{
		prefix: "(?:(?:" + strings.Join(quoted, "|") + `)(?:/[a-z][a-z0-9-]*)?/)?`,
		mounts: mounts,
	}, nil
}

// at is the pattern for exactly /v1/<namespace?>/<path>.
func (p *Paths) at(path string) string { return "^/v1/" + p.prefix + path + "$" }

// Login is the open paths: the roster JWT login, and the console's OIDC
// start and callback.
func (p *Paths) Login() []Match {
	return []Match{
		{Path: p.at(`auth/` + model.RosterMount + `/login`), Method: "POST"},
		{Path: p.at(`auth/` + model.RosterUIMount + `/oidc/auth_url`), Method: "POST"},
		{Path: p.at(`auth/` + model.RosterUIMount + `/oidc/callback`), Method: "GET"},
	}
}

// Data is what people and CI do once logged in: read and write KV v2, ask the
// issuing CA and the SSH CA to sign, and the token's own housekeeping. The
// caller's policies decide which of those a login may actually do. Wrap it in
// [RequireToken].
//
// NOT here, by design: any other mount (operator, origin, host-signing and
// workload mounts stay on the private path), every sys/ path but the two
// below, and auth/token/create.
func (p *Paths) Data() []Match {
	return []Match{
		{Path: p.at(p.mounts.KV + `/(?:data|metadata|delete|undelete|destroy)` + Tail)},
		{Path: p.at(p.mounts.Issuing + `/sign/` + Segment)},
		{Path: p.at(p.mounts.SSH + `/sign/` + Segment)},
		{Path: p.at(`auth/token/(?:lookup-self|renew-self|revoke-self)`)},
		{Path: p.at(`sys/capabilities-self`)},
		// `bao kv get` asks which version of KV a path is before it reads it.
		{Path: p.at(`sys/internal/ui/mounts(?:/` + Segment + `)*`)},
	}
}

// Console is what only the web console reads, behind the gateway's sign-in:
// the reads a page makes before login (the seal status, the UI's feature
// flags) and on the way to showing a mount, a policy or a namespace. GET and
// HEAD only: configuration is written elsewhere, never through this door.
// `sys/internal/ui/mounts` is NOT here: it is the CLI's, with a token, and is
// in [Paths.Data], so the other `sys/internal/ui/*` reads are listed by name
// and not by prefix, which keeps the two route sets disjoint.
func (p *Paths) Console() []Match {
	var out []Match

	for _, method := range []string{"GET", "HEAD"} {
		for _, path := range []string{
			`sys/(?:seal-status|health|leader|namespaces)`,
			`sys/(?:mounts|auth|policies/acl|policy)` + Tail,
			`sys/internal/ui/(?:feature-flags|namespaces|resultant-acl|version|authenticated-messages|unauthenticated-messages)`,
			`sys/config/ui/headers` + Tail,
		} {
			out = append(out, Match{Path: p.at(path), Method: method})
		}
	}

	return out
}

// RequireToken returns the matches with the token-presence check set: a
// request without [HeaderToken] matches nothing. The input is not modified.
func RequireToken(matches []Match) []Match {
	out := make([]Match, 0, len(matches))

	for _, m := range matches {
		m.RequireToken = true
		out = append(out, m)
	}

	return out
}

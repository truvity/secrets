package esoaws

import (
	"errors"
	"fmt"
	"strings"
)

// ValidRoleName reports whether name is an IAM role name (1 to 64 of
// A-Z a-z 0-9 +=,.@_-), what every Grant.Name of this package must be.
func ValidRoleName(name string) bool { return roleNameRe.MatchString(name) }

// WriterClaim is one writer role's claim on a parameter prefix, as an estate
// declares it before it builds one NewWriters (or NewSecureStringKey) per
// claim. NewWriters checks the grants it is given together; CheckWriterClaims
// checks the claims of components that are built apart.
type WriterClaim struct {
	// Label names the claim in an error (the estate's own key for it).
	Label string
	// Scope is where the claim holds: the account or cluster whose
	// parameters the prefix is in. Claims in different scopes never collide.
	Scope string
	// Role is the writer role's IAM name.
	Role string
	// Prefix is the parameter path the role writes, as WriteGrant.Prefix.
	Prefix string
}

// CheckWriterClaims refuses what IAM or the parameters' owner would refuse
// later: a role name IAM does not take, a prefix that is not one hierarchical
// path with a closing slash (WriteGrant.Prefix), a role or a prefix claimed
// twice in one scope, and a prefix inside another claim's, which would let
// the outer role write the inner one's parameters. All problems are returned
// together.
func CheckWriterClaims(claims []WriterClaim) error {
	var errs []error

	roles := map[string]string{}
	prefixes := map[string]string{}

	for _, c := range claims {
		where := "writer claim " + c.Label

		if !ValidRoleName(c.Role) {
			errs = append(errs, fmt.Errorf("%s: %q is not an IAM role name (1 to 64 of A-Z a-z 0-9 +=,.@_-)", where, c.Role))
		}

		if _, err := (WritersArgs{}).writePrefix(c.Prefix); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
		}

		if other, ok := roles[c.Scope+"\x00"+c.Role]; ok {
			errs = append(errs, fmt.Errorf("%s: role %s is %s's already", where, c.Role, other))
		}

		roles[c.Scope+"\x00"+c.Role] = c.Label

		if other, ok := prefixes[c.Scope+"\x00"+c.Prefix]; ok {
			errs = append(errs, fmt.Errorf("%s: prefix %s is %s's already: one role per prefix", where, c.Prefix, other))
		}

		prefixes[c.Scope+"\x00"+c.Prefix] = c.Label

		for _, o := range claims {
			if o.Scope == c.Scope && o.Prefix != c.Prefix && strings.HasPrefix(c.Prefix, o.Prefix) {
				errs = append(errs, fmt.Errorf("%s: prefix %s is inside %s's %s", where, c.Prefix, o.Label, o.Prefix))
			}
		}
	}

	return errors.Join(errs...)
}

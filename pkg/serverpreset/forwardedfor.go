package serverpreset

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// WithForwardedFor adds the x_forwarded_for_* settings to the API listener
// (the first `listener "tcp"` stanza, the one with a cluster_address) of the
// server config the preset rendered, and refuses anything it cannot place
// with certainty. The preset's Listener has no such fields, so this is the
// one place they are written, and the metrics-only listener must never carry
// them.
//
// It is for a server behind a proxy chain (a CDN, a tunnel, a gateway) whose
// last hop reaches the server from a pod: without it the audit log, token
// CIDR bindings and any client-address rule see that pod and never the
// caller. What is set, and why each value:
//
//   - x_forwarded_for_authorized_addrs: authorized, the address ranges that
//     may name the real client in X-Forwarded-For. Pods have no stable
//     address, so give the narrowest range the proxy fleet's pods can take
//     (their subnets). Each entry must be a network address in CIDR form; an
//     empty list is refused (it would trust nobody, and guessing a range is
//     not this function's to do).
//   - x_forwarded_for_hop_skips: hopSkips, how many entries to skip from the
//     rear of the chain. OpenBAO counts from the rear; the proxies in front
//     of the server append their peer, so the number is the count of
//     proxy-appended entries behind the client's. A client that sends its own
//     X-Forwarded-For only lengthens the front of the chain. Zero or negative
//     is refused.
//   - x_forwarded_for_reject_not_present = false. The default (true) answers
//     400 to any request WITHOUT the header, from anywhere, and a private
//     door, the secret operator of every cluster and the kubelet's probes
//     send none.
//   - x_forwarded_for_reject_not_authorized = false. The default (true)
//     answers 400 to a request that carries the header from an address
//     outside the range; false ignores the header for that request and
//     records the connection's own address. That is the safe direction on
//     both sides: a caller on a private door cannot spoof an address, and a
//     proxy pod outside the range degrades to the plain audit line instead of
//     an outage of the public door.
func WithForwardedFor(hcl string, authorized []string, hopSkips int) (string, error) {
	if len(authorized) == 0 {
		return "", errors.New("x_forwarded_for_authorized_addrs: no address range was given " +
			"(an empty list would trust nobody, and guessing a range is not this function's to do)")
	}

	if hopSkips < 1 {
		return "", fmt.Errorf("x_forwarded_for_hop_skips: %d is not a positive count of proxy hops", hopSkips)
	}

	for _, cidr := range authorized {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Masked() != prefix {
			return "", fmt.Errorf("x_forwarded_for_authorized_addrs: %q is not a network address in CIDR form", cidr)
		}
	}

	const open = "listener \"tcp\" {\n"

	start := strings.Index(hcl, open)
	if start < 0 {
		return "", errors.New("the server config has no listener \"tcp\" stanza")
	}

	body := start + len(open)

	end := strings.Index(hcl[body:], "\n}\n")
	if end < 0 {
		return "", errors.New("the first listener \"tcp\" stanza is not closed")
	}

	stanza := hcl[body : body+end]
	if !strings.Contains(stanza, "cluster_address") || strings.Contains(stanza, "x_forwarded_for") || strings.Contains(stanza, "telemetry") {
		return "", fmt.Errorf("the first listener stanza is not the API listener the preset renders "+
			"(cluster_address, no telemetry, no x_forwarded_for yet):\n%s", stanza)
	}

	var lines strings.Builder

	for _, kv := range [][2]string{
		{"x_forwarded_for_authorized_addrs", fmt.Sprintf("%q", strings.Join(authorized, ","))},
		{"x_forwarded_for_hop_skips", fmt.Sprintf("%q", fmt.Sprint(hopSkips))},
		{"x_forwarded_for_reject_not_present", "false"},
		{"x_forwarded_for_reject_not_authorized", "false"},
	} {
		fmt.Fprintf(&lines, "\n  %-37s = %s", kv[0], kv[1])
	}

	return hcl[:body+end] + lines.String() + hcl[body+end:], nil
}

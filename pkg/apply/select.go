package apply

import (
	"fmt"

	"github.com/truvity/secrets/pkg/model"
)

// The Pulumi type tokens of what Deploy registers, as a [Resource] names
// them (and as they appear in a URN).
const (
	TypeNamespace                  = "vault:index/namespace:Namespace"
	TypeMount                      = "vault:index/mount:Mount"
	TypePolicy                     = "vault:index/policy:Policy"
	TypePlugin                     = "vault:index/plugin:Plugin"
	TypeAuthBackend                = "vault:index/authBackend:AuthBackend"
	TypeEndpoint                   = "vault:generic/endpoint:Endpoint"
	TypeJWTAuthBackend             = "vault:jwt/authBackend:AuthBackend"
	TypeJWTAuthBackendRole         = "vault:jwt/authBackendRole:AuthBackendRole"
	TypeAWSAuthBackendClient       = "vault:aws/authBackendClient:AuthBackendClient"
	TypeAWSAuthBackendRole         = "vault:aws/authBackendRole:AuthBackendRole"
	TypeGroup                      = "vault:identity/group:Group"
	TypeGroupAlias                 = "vault:identity/groupAlias:GroupAlias"
	TypeKVSecret                   = "vault:kv/secretV2:SecretV2"
	TypePKIRootCert                = "vault:pkiSecret/secretBackendRootCert:SecretBackendRootCert"
	TypePKIIntermediateCertRequest = "vault:pkiSecret/secretBackendIntermediateCertRequest:SecretBackendIntermediateCertRequest"
	TypePKIIntermediateSetSigned   = "vault:pkiSecret/secretBackendIntermediateSetSigned:SecretBackendIntermediateSetSigned"
	TypePKIIssuer                  = "vault:pkiSecret/secretBackendIssuer:SecretBackendIssuer"
	TypePKIRootSignIntermediate    = "vault:pkiSecret/secretBackendRootSignIntermediate:SecretBackendRootSignIntermediate"
	TypePKIConfigIssuers           = "vault:pkiSecret/secretBackendConfigIssuers:SecretBackendConfigIssuers"
	TypePKIConfigURLs              = "vault:pkiSecret/secretBackendConfigUrls:SecretBackendConfigUrls"
	TypePKICRLConfig               = "vault:pkiSecret/secretBackendCrlConfig:SecretBackendCrlConfig"
	TypePKIAutoTidy                = "vault:pkiSecret/backendConfigAutoTidy:BackendConfigAutoTidy"
	TypePKIRole                    = "vault:pkiSecret/secretBackendRole:SecretBackendRole"
	TypeSSHCA                      = "vault:ssh/secretBackendCa:SecretBackendCa"
	TypeSSHRole                    = "vault:ssh/secretBackendRole:SecretBackendRole"
	selectRefusalPrefix            = "apply: select"
	unitMountRule                  = "a mount is applied with its CA, its issuers and its configuration"
	unitAuthRule                   = "an AWS auth mount is applied with its client configuration"
	unitGroupRule                  = "a group is applied with its alias"
	unitKVRule                     = "a KV mount is applied with its canary"
)

type (
	// Resource names one resource Deploy would register: its Pulumi type
	// token (the Type constants) and its logical name, after Rename.
	Resource struct {
		Type string
		Name string
	}
)

// owns reports whether this Deploy registers a resource: every one when
// Options.Select is nil.
func (a *applier) owns(typ, name string) bool {
	if a.opts.Select == nil {
		return true
	}

	return a.opts.Select(Resource{Type: typ, Name: name})
}

// together refuses a selection that splits a unit: the resource must be
// owned exactly when the unit's head (unitOwned) is.
func (a *applier) together(typ, name string, unitOwned bool, head, rule string) error {
	if a.owns(typ, name) == unitOwned {
		return nil
	}

	return fmt.Errorf("%s: %s %s and %s are selected apart; %s", selectRefusalPrefix, typ, name, head, rule)
}

// checkSelection refuses a selection that splits a unit anywhere in the
// model, before Deploy registers anything -- the provider included -- so a
// refused selection never leaves a partial apply behind. It walks the
// namespaces as Deploy does and asks the same unit questions the
// registration asks again; it registers nothing.
func (a *applier) checkSelection() error {
	if a.opts.Select == nil {
		return nil
	}

	for _, namespace := range a.desired.Applied() {
		s := &scope{namespace: namespace, label: namespace.Label()}

		for i := range namespace.PKI {
			if _, _, err := a.pkiUnit(s, &namespace.PKI[i]); err != nil {
				return err
			}
		}

		for i := range namespace.Projects {
			project := &namespace.Projects[i]
			path := namespace.Name + "/" + project.Name
			ps := &scope{namespace: &model.Namespace{Name: path}, label: path}

			for j := range project.PKI {
				if _, _, err := a.pkiUnit(ps, &project.PKI[j]); err != nil {
					return err
				}
			}

			for j := range project.KV {
				if _, _, err := a.kvUnit(ps, &project.KV[j]); err != nil {
					return err
				}
			}
		}

		for i := range namespace.KV {
			if _, _, err := a.kvUnit(s, &namespace.KV[i]); err != nil {
				return err
			}
		}

		for i := range namespace.AWSAuth {
			if _, _, _, err := a.awsUnit(s, &namespace.AWSAuth[i]); err != nil {
				return err
			}
		}

		for i := range namespace.Groups {
			group := &namespace.Groups[i]
			for _, door := range group.Doors {
				if _, _, _, err := a.groupUnit(s, group, door); err != nil {
					return err
				}
			}
		}

		for i := range namespace.SSH {
			if _, _, _, err := a.sshUnit(mountName(s, namespace.SSH[i].Path)); err != nil {
				return err
			}
		}

		for i := range namespace.SSHHost {
			if _, _, _, err := a.sshUnit(mountName(s, namespace.SSHHost[i].Path)); err != nil {
				return err
			}
		}
	}

	return nil
}

// pkiUnit is a PKI mount's logical name and whether this run owns it, after
// checking that its issuers, its pinned default and its maintenance follow
// it.
func (a *applier) pkiUnit(s *scope, desired *model.PKIMount) (string, bool, error) {
	head := mountName(s, desired.Path)
	name := a.name(head)
	owned := a.owns(TypeMount, name)

	var members []Resource

	if desired.DefaultIssuer != "" {
		members = append(members,
			Resource{TypePKIConfigIssuers, a.name(head + "-default")},
			Resource{TypePKIConfigURLs, a.name(head + "-urls")},
			Resource{TypePKICRLConfig, a.name(head + "-crl")},
			Resource{TypePKIAutoTidy, a.name(head + "-auto-tidy")},
		)
	}

	for i := range desired.Issuers {
		issuer := &desired.Issuers[i]

		switch {
		case issuer.SelfSigned:
			members = append(members, Resource{TypePKIRootCert, a.name(issuer.Name + "-certificate")})
		default:
			members = append(members,
				Resource{TypePKIIntermediateCertRequest, a.name(issuer.Name + "-csr")},
				Resource{TypePKIIntermediateSetSigned, a.name(issuer.Name + "-import")},
				Resource{TypePKIIssuer, a.name(issuer.Name + "-issuer")},
			)

			if !issuer.External {
				members = append(members, Resource{TypePKIRootSignIntermediate, a.name(issuer.Name + "-signed")})
			}
		}
	}

	for _, member := range members {
		if err := a.together(member.Type, member.Name, owned, name, unitMountRule); err != nil {
			return "", false, err
		}
	}

	return name, owned, nil
}

// kvUnit is a KV mount's logical name and whether this run owns it, after
// checking that its canary follows it.
func (a *applier) kvUnit(s *scope, desired *model.KVMount) (string, bool, error) {
	name := a.name(mountName(s, desired.Path))
	owned := a.owns(TypeMount, name)

	if desired.Canary != "" {
		if err := a.together(TypeKVSecret, a.name(s.label+"-"+desired.Canary), owned, name, unitKVRule); err != nil {
			return "", false, err
		}
	}

	return name, owned, nil
}

// groupUnit is a group's identity group and alias names on one door and
// whether this run owns them, after checking that the alias follows the
// group. The primary door's keep the bare names.
func (a *applier) groupUnit(s *scope, group *model.Group, door string) (string, string, bool, error) {
	suffix := ""
	if door != a.desired.Identity.PrimaryDoor {
		suffix = "-" + door
	}

	groupName := a.name(s.label + "-group-" + resourceName(group.Name) + suffix)
	aliasName := a.name(s.label + "-alias-" + resourceName(group.Name) + suffix)
	owned := a.owns(TypeGroup, groupName)

	if err := a.together(TypeGroupAlias, aliasName, owned, groupName, unitGroupRule); err != nil {
		return "", "", false, err
	}

	return groupName, aliasName, owned, nil
}

// sshUnit is an SSH mount's and its CA's names, from the mount's logical
// name before Rename, and whether this run owns them, after checking that
// the CA follows the mount.
func (a *applier) sshUnit(name string) (string, string, bool, error) {
	mountName, caName := a.name(name), a.name(name+"-ca")
	owned := a.owns(TypeMount, mountName)

	if err := a.together(TypeSSHCA, caName, owned, mountName, unitMountRule); err != nil {
		return "", "", false, err
	}

	return mountName, caName, owned, nil
}

// awsUnit is an AWS auth mount's and its client's names and whether this
// run owns them, after checking that the client follows the mount (either
// kind: the AuthBackend, or the versioned Endpoint).
func (a *applier) awsUnit(s *scope, desired *model.AWSAuthMount) (string, string, bool, error) {
	mountName := a.name(s.label + "-auth-" + desired.Path)
	clientName := a.name(s.label + "-auth-" + desired.Path + "-client")

	mountType := TypeAuthBackend
	if desired.PluginVersion != "" {
		mountType = TypeEndpoint
	}

	owned := a.owns(mountType, mountName)
	if err := a.together(TypeAWSAuthBackendClient, clientName, owned, mountName, unitAuthRule); err != nil {
		return "", "", false, err
	}

	return mountName, clientName, owned, nil
}

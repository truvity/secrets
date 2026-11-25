package apply

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pulumi/pulumi-vault/sdk/v7/go/vault"
	vaultssh "github.com/pulumi/pulumi-vault/sdk/v7/go/vault/ssh"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"

	"github.com/truvity/secrets/pkg/model"
)

// sshMount registers the SSH engine, its CA and its roles, all protected:
// a role that disappears in a replace is a window in which nobody can
// sign, and a replaced CA is a new key every host has to be told about.
//
// The mount caps every lease at the longest role maximum, so even a role
// written wrong cannot sign past it. Its audit keys make a signing readable
// in the audit log without a hash lookup: the principals asked for and the
// serial handed back.
func (a *applier) sshMount(s *scope, desired *model.SSHMount) error {
	defaultTTL, maxTTL := 0, 0

	for i := range desired.Roles {
		ttl, err := model.DurationSeconds(desired.Roles[i].TTL)
		if err != nil {
			return fmt.Errorf("%s ssh role %s: %w", s.label, desired.Roles[i].Name, err)
		}

		most, err := model.DurationSeconds(desired.Roles[i].MaxTTL)
		if err != nil {
			return fmt.Errorf("%s ssh role %s: %w", s.label, desired.Roles[i].Name, err)
		}

		defaultTTL, maxTTL = max(defaultTTL, ttl), max(maxTTL, most)
	}

	args := &vault.MountArgs{
		Namespace:                s.arg,
		Path:                     pulumi.String(desired.Path),
		Type:                     pulumi.String("ssh"),
		DefaultLeaseTtlSeconds:   pulumi.Int(defaultTTL),
		MaxLeaseTtlSeconds:       pulumi.Int(maxTTL),
		AuditNonHmacRequestKeys:  pulumi.ToStringArray([]string{"valid_principals"}),
		AuditNonHmacResponseKeys: pulumi.ToStringArray([]string{"serial_number"}),
	}

	if desired.Description != "" {
		args.Description = pulumi.String(desired.Description)
	}

	name := mountName(s, desired.Path)

	backend, err := a.sshCA(s, name, desired.Path, desired.KeyType, args, "ssh")
	if err != nil {
		return err
	}

	for i := range desired.Roles {
		role := &desired.Roles[i]

		roleName := a.name(name + "-sshrole-" + role.Name)
		if !a.owns(TypeSSHRole, roleName) {
			continue
		}

		if _, err := vaultssh.NewSecretBackendRole(a.c, roleName, sshRoleArgs(s.arg, backend.path, role),
			authority(s.inside, backend.mount, backend.ca)...); err != nil {
			return fmt.Errorf("%s ssh role %s/%s: %w", s.label, desired.Path, role.Name, err)
		}
	}

	if backend.publicKey != nil {
		a.result.SSHCAPublicKeys[MountRef{Namespace: s.namespace.Name, Path: desired.Path}] = *backend.publicKey
	}

	return nil
}

// sshRoleArgs is a user-certificate role with everything it does not do
// spelled out: no host certificates, no key id of the caller's choosing,
// no empty principals, no templates, no critical options, and no extension
// beyond the ones it names. Each key type is admitted with length 0, which
// is how OpenBAO spells a type of one size such as ed25519.
func sshRoleArgs(namespace pulumi.StringPtrInput, backend pulumi.StringInput, role *model.SSHRole) *vaultssh.SecretBackendRoleArgs {
	// Validate has parsed both already.
	ttl, _ := model.DurationSeconds(role.TTL)
	maxTTL, _ := model.DurationSeconds(role.MaxTTL)

	keys := vaultssh.SecretBackendRoleAllowedUserKeyConfigArray{}
	for _, keyType := range role.KeyTypes {
		keys = append(keys, vaultssh.SecretBackendRoleAllowedUserKeyConfigArgs{
			Type:    pulumi.String(keyType),
			Lengths: pulumi.ToIntArray([]int{0}),
		})
	}

	extensions := pulumi.StringMap{}
	for _, extension := range role.Extensions {
		extensions[extension] = pulumi.String("")
	}

	// ForceCommand is the role's only default critical option, and the
	// allowed list stays empty either way: the caller can never add,
	// replace or remove it (model.SSHRole.ForceCommand, model.go's
	// Validate refuses it beside permit-pty or a forwarding extension).
	criticalOptions := pulumi.StringMap{}
	if role.ForceCommand != "" {
		criticalOptions["force-command"] = pulumi.String(role.ForceCommand)
	}

	return &vaultssh.SecretBackendRoleArgs{
		Namespace:                 namespace,
		Backend:                   backend,
		Name:                      pulumi.String(role.Name),
		KeyType:                   pulumi.String("ca"),
		AllowUserCertificates:     pulumi.Bool(true),
		AllowHostCertificates:     pulumi.Bool(false),
		AllowBareDomains:          pulumi.Bool(false),
		AllowSubdomains:           pulumi.Bool(false),
		AllowEmptyPrincipals:      pulumi.Bool(false),
		AllowUserKeyIds:           pulumi.Bool(false),
		KeyIdFormat:               pulumi.String(role.KeyIDFormat),
		AllowedUsers:              pulumi.String(strings.Join(role.AllowedUsers, ",")),
		AllowedUsersTemplate:      pulumi.Bool(false),
		DefaultUser:               pulumi.String(role.DefaultUser),
		DefaultUserTemplate:       pulumi.Bool(false),
		AllowedUserKeyConfigs:     keys,
		AllowedExtensions:         pulumi.String(strings.Join(role.Extensions, ",")),
		DefaultExtensions:         extensions,
		DefaultExtensionsTemplate: pulumi.Bool(false),
		AllowedCriticalOptions:    pulumi.String(""),
		DefaultCriticalOptions:    criticalOptions,
		Ttl:                       pulumi.String(strconv.Itoa(ttl)),
		MaxTtl:                    pulumi.String(strconv.Itoa(maxTTL)),
	}
}

// sshHostMount registers an SSH host-CA engine, its CA and its roles, on
// the same protections as sshMount: a role that disappears in a replace is
// a window in which no host can be re-signed, and a replaced CA is a new
// key every client has to be told about. The CA is never the same key as
// any user mount's -- it lives on a mount of its own.
func (a *applier) sshHostMount(s *scope, desired *model.SSHHostMount) error {
	defaultTTL, maxTTL := 0, 0

	for i := range desired.Roles {
		ttl, err := model.DurationSeconds(desired.Roles[i].TTL)
		if err != nil {
			return fmt.Errorf("%s ssh host role %s: %w", s.label, desired.Roles[i].Name, err)
		}

		most, err := model.DurationSeconds(desired.Roles[i].MaxTTL)
		if err != nil {
			return fmt.Errorf("%s ssh host role %s: %w", s.label, desired.Roles[i].Name, err)
		}

		defaultTTL, maxTTL = max(defaultTTL, ttl), max(maxTTL, most)
	}

	args := &vault.MountArgs{
		Namespace:                s.arg,
		Path:                     pulumi.String(desired.Path),
		Type:                     pulumi.String("ssh"),
		DefaultLeaseTtlSeconds:   pulumi.Int(defaultTTL),
		MaxLeaseTtlSeconds:       pulumi.Int(maxTTL),
		AuditNonHmacRequestKeys:  pulumi.ToStringArray([]string{"valid_principals"}),
		AuditNonHmacResponseKeys: pulumi.ToStringArray([]string{"serial_number"}),
	}

	if desired.Description != "" {
		args.Description = pulumi.String(desired.Description)
	}

	name := mountName(s, desired.Path)

	backend, err := a.sshCA(s, name, desired.Path, desired.KeyType, args, "ssh host")
	if err != nil {
		return err
	}

	for i := range desired.Roles {
		role := &desired.Roles[i]

		roleName := a.name(name + "-sshrole-" + role.Name)
		if !a.owns(TypeSSHRole, roleName) {
			continue
		}

		if _, err := vaultssh.NewSecretBackendRole(a.c, roleName, sshHostRoleArgs(s.arg, backend.path, role),
			authority(s.inside, backend.mount, backend.ca)...); err != nil {
			return fmt.Errorf("%s ssh host role %s/%s: %w", s.label, desired.Path, role.Name, err)
		}
	}

	if backend.publicKey != nil {
		a.result.SSHHostCAPublicKeys[MountRef{Namespace: s.namespace.Name, Path: desired.Path}] = *backend.publicKey
	}

	return nil
}

// sshHostRoleArgs is a host-certificate role with everything it does not do
// spelled out: no user certificates, no key id of the caller's choosing, no
// templated domains, no critical options and no extension at all. Each key
// type is admitted with length 0, which is how OpenBAO spells a type of one
// size such as ed25519.
func sshHostRoleArgs(namespace pulumi.StringPtrInput, backend pulumi.StringInput, role *model.SSHHostRole) *vaultssh.SecretBackendRoleArgs {
	// Validate has parsed both already.
	ttl, _ := model.DurationSeconds(role.TTL)
	maxTTL, _ := model.DurationSeconds(role.MaxTTL)

	keys := vaultssh.SecretBackendRoleAllowedUserKeyConfigArray{}
	for _, keyType := range role.KeyTypes {
		keys = append(keys, vaultssh.SecretBackendRoleAllowedUserKeyConfigArgs{
			Type:    pulumi.String(keyType),
			Lengths: pulumi.ToIntArray([]int{0}),
		})
	}

	return &vaultssh.SecretBackendRoleArgs{
		Namespace:                 namespace,
		Backend:                   backend,
		Name:                      pulumi.String(role.Name),
		KeyType:                   pulumi.String("ca"),
		AllowUserCertificates:     pulumi.Bool(false),
		AllowHostCertificates:     pulumi.Bool(true),
		AllowBareDomains:          pulumi.Bool(role.AllowBareDomains),
		AllowSubdomains:           pulumi.Bool(role.AllowSubdomains),
		AllowedDomains:            pulumi.String(strings.Join(role.AllowedDomains, ",")),
		AllowedDomainsTemplate:    pulumi.Bool(false),
		AllowEmptyPrincipals:      pulumi.Bool(false),
		AllowUserKeyIds:           pulumi.Bool(false),
		KeyIdFormat:               pulumi.String(role.KeyIDFormat),
		AllowedUserKeyConfigs:     keys,
		AllowedExtensions:         pulumi.String(""),
		DefaultExtensions:         pulumi.StringMap{},
		DefaultExtensionsTemplate: pulumi.Bool(false),
		AllowedCriticalOptions:    pulumi.String(""),
		DefaultCriticalOptions:    pulumi.StringMap{},
		Ttl:                       pulumi.String(strconv.Itoa(ttl)),
		MaxTtl:                    pulumi.String(strconv.Itoa(maxTTL)),
	}
}

// sshBackend is a registered SSH mount and CA, for its roles: the mount's
// path, the two resources (untyped nils when another stack owns the mount,
// Options.Select), and the CA's public key when it is registered here.
type sshBackend struct {
	path      pulumi.StringInput
	mount     pulumi.Resource
	ca        pulumi.Resource
	publicKey *pulumi.StringOutput
}

// sshCA registers an SSH mount and its CA, which are one unit, unless
// another stack owns them.
func (a *applier) sshCA(s *scope, name, path, keyType string, args *vault.MountArgs, label string) (sshBackend, error) {
	mountName, caName, owned, err := a.sshUnit(name)
	if err != nil {
		return sshBackend{}, err
	}

	if !owned {
		return sshBackend{path: pulumi.String(path)}, nil
	}

	mount, err := vault.NewMount(a.c, mountName, args, authority(s.inside)...)
	if err != nil {
		return sshBackend{}, fmt.Errorf("%s %s mount %s: %w", s.label, label, path, err)
	}

	// Generated inside OpenBAO: the signing key is never in Pulumi's
	// state, a file or an output. Only its public half is exported.
	ca, err := vaultssh.NewSecretBackendCa(a.c, caName, &vaultssh.SecretBackendCaArgs{
		Namespace:          s.arg,
		Backend:            mount.Path,
		GenerateSigningKey: pulumi.Bool(true),
		KeyType:            pulumi.String(keyType),
	}, authority(s.inside, mount)...)
	if err != nil {
		return sshBackend{}, fmt.Errorf("%s %s CA %s: %w", s.label, label, path, err)
	}

	return sshBackend{path: mount.Path, mount: mount, ca: ca, publicKey: &ca.PublicKey}, nil
}

package identity

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/itp/pkg/logger"
)

// Mapping represents a certificate field mapping to an identity
type Mapping struct {
	SourceValue string
	Identity    string
}

// RoleMapping represents a mapping from a certificate attribute to additional roles
type RoleMapping struct {
	SourceField string // cn, org, ou, locality, country, state
	SourceValue string
	Roles       []string
}

// GroupMapping represents a mapping from a certificate attribute to additional groups
type GroupMapping struct {
	SourceField string // cn, org, ou, locality, country, state
	SourceValue string
	Groups      []string
}

// Identity represents a translated identity
type Identity struct {
	CommonName       string
	Organization     []string
	OrganizationUnit []string
	Locality         []string
	Country          []string
	State            []string
	Groups           []string
	Roles            []string
}

// Translator handles identity translation between certificate domains
type Translator struct {
	cnMappings      map[string]string
	ouMappings      map[string]string
	orgMappings     map[string]string
	locMappings     map[string]string
	countryMappings map[string]string
	stateMappings   map[string]string
	autoMap         bool
	
	// Conditional role and group mappings
	roleMappings []RoleMapping
	groupMappings []GroupMapping

	logger *logger.Logger
}

// NewTranslator creates a new identity translator
func NewTranslator(logger *logger.Logger, autoMap bool) *Translator {
	return &Translator{
		cnMappings:      make(map[string]string),
		ouMappings:      make(map[string]string),
		orgMappings:     make(map[string]string),
		locMappings:     make(map[string]string),
		countryMappings: make(map[string]string),
		stateMappings:   make(map[string]string),
		autoMap:         autoMap,
		roleMappings:    make([]RoleMapping, 0),
		groupMappings:   make([]GroupMapping, 0),
		logger:          logger,
	}
}

// AddMapping adds a mapping for a specific field
func (t *Translator) AddMapping(field, from string, to string) {
	normalizedField := t.normalizeFieldName(field)
	t.logger.Debug("Adding mapping %s: %s -> %s", normalizedField, from, to)

	switch normalizedField {
	case "CN":
		t.cnMappings[from] = to
	case "O":
		t.orgMappings[from] = to
	case "OU":
		t.ouMappings[from] = to
	case "L":
		t.locMappings[from] = to
	case "C":
		t.countryMappings[from] = to
	case "ST":
		t.stateMappings[from] = to
	default:
		t.logger.Warn("Unknown field type: %s", field)
	}
}

// AddRoleMapping adds a role mapping for a specific certificate attribute
func (t *Translator) AddRoleMapping(sourceField, sourceValue string, roles []string) {
	t.logger.Debug("Adding role mapping %s=%s -> roles=%v", sourceField, sourceValue, roles)
	t.roleMappings = append(t.roleMappings, RoleMapping{
		SourceField: sourceField,
		SourceValue: sourceValue,
		Roles:       roles,
	})
}

// AddGroupMapping adds a group mapping for a specific certificate field
func (t *Translator) AddGroupMapping(fieldName, fieldValue string, groups []string) {
	t.logger.Debug("Adding group mapping %s=%s -> groups=%v", fieldName, fieldValue, groups)
	t.groupMappings = append(t.groupMappings, GroupMapping{
		SourceField: fieldName,
		SourceValue: fieldValue,
		Groups:      groups,
	})
}

// TranslationError represents an error during identity translation
type TranslationError struct {
	Code    string
	Message string
}

func (e *TranslationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Common translation error codes
const (
	ErrNoMappings         = "NO_IDENTITY_MAPPINGS"
	ErrUnrecognizedClient = "UNRECOGNIZED_CLIENT"
)

// TranslateIdentity translates a certificate's identity based on configured mappings
func (t *Translator) TranslateIdentity(cert *x509.Certificate) ([]*Identity, error) {
	t.logger.Debug("Translating identity for certificate CN=%q, O=%v, OU=%v",
		cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.OrganizationalUnit)

	if !t.autoMap && cert.Subject.CommonName == "" {
		return nil, &TranslationError{
			Code:    ErrUnrecognizedClient,
			Message: "certificate has no CN and auto-mapping is disabled",
		}
	}

	var mappedIdentity *Identity
	var mappingSource string
	var details strings.Builder

	// First try to find explicit mappings
	if !t.autoMap {
		mappedIdentity, mappingSource = t.findMappedIdentities(cert)
		if mappedIdentity != nil {
			details.WriteString(fmt.Sprintf("Found mapping from %s\n", mappingSource))
		}
	}

	// If no mappings found and auto-map is enabled, create identity from cert
	if mappedIdentity == nil {
		if !t.autoMap {
			return nil, &TranslationError{
				Code:    ErrNoMappings,
				Message: fmt.Sprintf("no identity mappings found for certificate CN=%s", cert.Subject.CommonName),
			}
		}
		mappedIdentity = t.autoMapIdentity(cert)
		details.WriteString("Using auto-mapped identity\n")
	}

	// Apply any role/group mappings
	t.applyRoleAndGroupMappings(cert, []*Identity{mappedIdentity}, &details)

	t.logger.Debug("Identity translation details:\n%s", details.String())
	return []*Identity{mappedIdentity}, nil
}

// applyRoleAndGroupMappings applies role and group mappings to the identity based on certificate fields
func (t *Translator) applyRoleAndGroupMappings(cert *x509.Certificate, identities []*Identity, details *strings.Builder) {
	for _, identity := range identities {
		// Apply role mappings
		for _, mapping := range t.roleMappings {
			if t.matchesSourceField(cert, mapping.SourceField, mapping.SourceValue) ||
				t.matchesIdentityField(identity, mapping.SourceField, mapping.SourceValue) {
				identity.Roles = append(identity.Roles, mapping.Roles...)
				details.WriteString(fmt.Sprintf("Roles: %s -> %s\n", mapping.SourceValue, formatQuotedArray(mapping.Roles)))
			}
		}

		// Apply group mappings
		for _, mapping := range t.groupMappings {
			if t.matchesSourceField(cert, mapping.SourceField, mapping.SourceValue) ||
				t.matchesIdentityField(identity, mapping.SourceField, mapping.SourceValue) {
				identity.Groups = append(identity.Groups, mapping.Groups...)
				details.WriteString(fmt.Sprintf("Groups: %s -> %s\n", mapping.SourceValue, formatQuotedArray(mapping.Groups)))
			}
		}
	}
}

// applyMappings applies mappings to the identity based on certificate fields
func (t *Translator) applyMappings(identity *Identity, mappings *Identity) {
	if mappings.CommonName != "" {
		identity.CommonName = mappings.CommonName
	}
	if len(mappings.Organization) > 0 {
		identity.Organization = mappings.Organization
	}
	if len(mappings.OrganizationUnit) > 0 {
		identity.OrganizationUnit = mappings.OrganizationUnit
	}
	if len(mappings.Locality) > 0 {
		identity.Locality = mappings.Locality
	}
	if len(mappings.Country) > 0 {
		identity.Country = mappings.Country
	}
	if len(mappings.State) > 0 {
		identity.State = mappings.State
	}
	if len(mappings.Roles) > 0 {
		identity.Roles = append(identity.Roles, mappings.Roles...)
	}
	if len(mappings.Groups) > 0 {
		identity.Groups = append(identity.Groups, mappings.Groups...)
	}
}

// normalizeFieldName converts field names to their canonical form (CN, O, OU, etc.)
func (t *Translator) normalizeFieldName(field string) string {
	switch field {
	case "common-name", "CN", "cn":
		return "CN"
	case "organization", "O", "o":
		return "O"
	case "organization-unit", "OU", "ou":
		return "OU"
	case "locality", "L", "l":
		return "L"
	case "country", "C", "c":
		return "C"
	case "state", "ST", "st":
		return "ST"
	default:
		return field
	}
}

// findMappedIdentities looks for specific mappings for the certificate
func (t *Translator) findMappedIdentities(cert *x509.Certificate) (*Identity, string) {
	t.logger.Debug("Looking for mapped identities for certificate CN=%s", cert.Subject.CommonName)
	
	identity := &Identity{}
	var mappingSource string

	// Check CN mappings
	if mapped, ok := t.cnMappings[cert.Subject.CommonName]; ok {
		t.logger.Debug("Found CN mapping: %s -> %s", cert.Subject.CommonName, mapped)
		identity.CommonName = mapped
		mappingSource = fmt.Sprintf("CN=%s", cert.Subject.CommonName)
		return identity, mappingSource
	}

	// Check Organization mappings
	for _, org := range cert.Subject.Organization {
		if mapped, ok := t.orgMappings[org]; ok {
			t.logger.Debug("Found Organization mapping: %s -> %s", org, mapped)
			identity.Organization = []string{mapped}
			mappingSource = fmt.Sprintf("O=%s", org)
			return identity, mappingSource
		}
	}

	// Check OU mappings
	for _, ou := range cert.Subject.OrganizationalUnit {
		if mapped, ok := t.ouMappings[ou]; ok {
			t.logger.Debug("Found OU mapping: %s -> %s", ou, mapped)
			identity.OrganizationUnit = []string{mapped}
			mappingSource = fmt.Sprintf("OU=%s", ou)
			return identity, mappingSource
		}
	}

	// Check Locality mappings
	for _, locality := range cert.Subject.Locality {
		if mapped, ok := t.locMappings[locality]; ok {
			t.logger.Debug("Found Locality mapping: %s -> %s", locality, mapped)
			identity.Locality = []string{mapped}
			mappingSource = fmt.Sprintf("L=%s", locality)
			return identity, mappingSource
		}
	}

	// Check Country mappings
	for _, country := range cert.Subject.Country {
		if mapped, ok := t.countryMappings[country]; ok {
			t.logger.Debug("Found Country mapping: %s -> %s", country, mapped)
			identity.Country = []string{mapped}
			mappingSource = fmt.Sprintf("C=%s", country)
			return identity, mappingSource
		}
	}

	// Check State mappings
	for _, state := range cert.Subject.Province {
		if mapped, ok := t.stateMappings[state]; ok {
			t.logger.Debug("Found State mapping: %s -> %s", state, mapped)
			identity.State = []string{mapped}
			mappingSource = fmt.Sprintf("ST=%s", state)
			return identity, mappingSource
		}
	}

	t.logger.Debug("No explicit mappings found for certificate")
	return nil, ""
}

// matchesSourceField checks if a certificate field matches the mapping condition
func (t *Translator) matchesSourceField(cert *x509.Certificate, field, value string) bool {
	switch t.normalizeFieldName(field) {
	case "CN":
		return cert.Subject.CommonName == value
	case "O":
		for _, org := range cert.Subject.Organization {
			if org == value {
				return true
			}
		}
	case "OU":
		for _, ou := range cert.Subject.OrganizationalUnit {
			if ou == value {
				return true
			}
		}
	case "L":
		for _, loc := range cert.Subject.Locality {
			if loc == value {
				return true
			}
		}
	case "C":
		for _, country := range cert.Subject.Country {
			if country == value {
				return true
			}
		}
	case "ST":
		for _, state := range cert.Subject.Province {
			if state == value {
				return true
			}
		}
	}
	return false
}

// matchesIdentityField checks if an identity field matches the mapping condition
func (t *Translator) matchesIdentityField(identity *Identity, field, value string) bool {
	switch t.normalizeFieldName(field) {
	case "CN":
		return identity.CommonName == value
	case "O":
		for _, org := range identity.Organization {
			if org == value {
				return true
			}
		}
	case "OU":
		for _, ou := range identity.OrganizationUnit {
			if ou == value {
				return true
			}
		}
	case "L":
		for _, loc := range identity.Locality {
			if loc == value {
				return true
			}
		}
	case "C":
		for _, country := range identity.Country {
			if country == value {
				return true
			}
		}
	case "ST":
		for _, state := range identity.State {
			if state == value {
				return true
			}
		}
	}
	return false
}

// formatQuotedArray formats a string array with quoted values
func formatQuotedArray(values []string) string {
	if len(values) == 0 {
		return "[]"
	}
	quoted := make([]string, len(values))
	for i, v := range values {
		quoted[i] = fmt.Sprintf("%q", v)
	}
	return fmt.Sprintf("[%s]", strings.Join(quoted, ", "))
}

// GetSubjectFromIdentity creates a subject string from an identity
func (t *Translator) GetSubjectFromIdentity(identities []*Identity) string {
	if len(identities) == 0 {
		t.logger.Warn("No identities provided to GetSubjectFromIdentity")
		return ""
	}

	identity := identities[0]
	var parts []string

	if identity.CommonName != "" {
		parts = append(parts, fmt.Sprintf("CN=%s", identity.CommonName))
	}
	if len(identity.Organization) > 0 {
		parts = append(parts, fmt.Sprintf("O=%s", formatQuotedArray(identity.Organization)))
	}
	if len(identity.OrganizationUnit) > 0 {
		parts = append(parts, fmt.Sprintf("OU=%s", formatQuotedArray(identity.OrganizationUnit)))
	}
	if len(identity.Locality) > 0 {
		parts = append(parts, fmt.Sprintf("L=%s", formatQuotedArray(identity.Locality)))
	}
	if len(identity.Country) > 0 {
		parts = append(parts, fmt.Sprintf("C=%s", formatQuotedArray(identity.Country)))
	}
	if len(identity.State) > 0 {
		parts = append(parts, fmt.Sprintf("ST=%s", formatQuotedArray(identity.State)))
	}

	subject := strings.Join(parts, ", ")
	t.logger.Debug("Generated subject string: %s", subject)
	return subject
}

// autoMapIdentity creates an identity based on certificate fields when no explicit mappings are found
func (t *Translator) autoMapIdentity(cert *x509.Certificate) *Identity {
	t.logger.Debug("Auto-mapping identity for certificate CN=%s", cert.Subject.CommonName)
	return &Identity{
		CommonName:       cert.Subject.CommonName,
		Organization:     cert.Subject.Organization,
		OrganizationUnit: cert.Subject.OrganizationalUnit,
		Locality:         cert.Subject.Locality,
		Country:          cert.Subject.Country,
		State:           cert.Subject.Province,
		Groups:           []string{},
		Roles:            []string{},
	}
}

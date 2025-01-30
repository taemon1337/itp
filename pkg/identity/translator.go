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

// AuthMapping represents a mapping from a certificate attribute to auth values
type AuthMapping struct {
	SourceField string // cn, org, ou, locality, country, state
	SourceValue string
	Auths      []string
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
	Auths            []string
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
	
	// Conditional role, group and auth mappings
	roleMappings  []RoleMapping
	groupMappings []GroupMapping
	authMappings  []AuthMapping

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
		authMappings:    make([]AuthMapping, 0),
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

// AddAuthMapping adds an auth mapping for a specific certificate field
func (t *Translator) AddAuthMapping(sourceField, sourceValue string, auths []string) {
	t.logger.Debug("Adding auth mapping %s=%s -> auths=%v", sourceField, sourceValue, auths)
	t.authMappings = append(t.authMappings, AuthMapping{
		SourceField: t.normalizeFieldName(sourceField),
		SourceValue: sourceValue,
		Auths:      auths,
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
	ErrNoIdentityMappings = "NO_IDENTITY_MAPPINGS"
	ErrUnrecognizedClient = "UNRECOGNIZED_CLIENT"
)

// TranslateIdentity translates a certificate's identity based on configured mappings
func (t *Translator) TranslateIdentity(cert *x509.Certificate) (*Identity, error) {
	if !t.autoMap && cert.Subject.CommonName == "" {
		return nil, &TranslationError{
			Code:    ErrNoIdentityMappings,
			Message: fmt.Sprintf("no identity mappings found for certificate and auto-mapping is disabled:\n- Common Name: %q\n- Organization: %q\n", cert.Subject.CommonName, cert.Subject.Organization),
		}
	}

	t.logger.Debug("Translating identity for certificate CN=%q, O=%v, OU=%v", cert.Subject.CommonName, cert.Subject.Organization, cert.Subject.OrganizationalUnit)

	// Try to find explicit mappings first
	identity := &Identity{}
	mappedIdentity, source := t.findMappedIdentities(cert)
	if mappedIdentity != nil {
		identity = mappedIdentity
	} else if !t.autoMap {
		return nil, &TranslationError{
			Code:    ErrNoIdentityMappings,
			Message: fmt.Sprintf("no identity mappings found for certificate and auto-mapping is disabled:\n- Common Name: %q\n- Organization: %q\n", cert.Subject.CommonName, cert.Subject.Organization),
		}
	}

	// Auto-map any unmapped fields if enabled
	if t.autoMap {
		t.logger.Debug("Auto-mapping identity for certificate CN=%s", cert.Subject.CommonName)
		autoMappedIdentity := t.autoMapIdentity(cert)
		if identity.CommonName == "" {
			identity.CommonName = autoMappedIdentity.CommonName
		}
		if len(identity.Organization) == 0 {
			identity.Organization = autoMappedIdentity.Organization
		}
		if len(identity.OrganizationUnit) == 0 {
			identity.OrganizationUnit = autoMappedIdentity.OrganizationUnit
		}
		if len(identity.Locality) == 0 {
			identity.Locality = autoMappedIdentity.Locality
		}
		if len(identity.Country) == 0 {
			identity.Country = []string{"US"} // Default to US if no country specified
		}
		if len(identity.State) == 0 {
			identity.State = autoMappedIdentity.State
		}
	}

	// Add any role mappings
	identity.Roles = t.getRoleMappings(cert)

	// Add any group mappings
	identity.Groups = t.getGroupMappings(cert)

	// Add any auth mappings
	identity.Auths = t.getAuthMappings(cert)

	t.logger.Debug("Identity translation details:")
	if source != "" {
		t.logger.Debug("Found mapping from %s", source)
	} else {
		t.logger.Debug("Using auto-mapped identity")
	}
	return identity, nil
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

		// Apply auth mappings
		for _, mapping := range t.authMappings {
			if t.matchesSourceField(cert, mapping.SourceField, mapping.SourceValue) ||
				t.matchesIdentityField(identity, mapping.SourceField, mapping.SourceValue) {
				identity.Auths = append(identity.Auths, mapping.Auths...)
				details.WriteString(fmt.Sprintf("Auths: %s -> %s\n", mapping.SourceValue, formatQuotedArray(mapping.Auths)))
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
	if len(mappings.Auths) > 0 {
		identity.Auths = append(identity.Auths, mappings.Auths...)
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

// findMappedIdentities looks for explicit mappings for the certificate fields
func (t *Translator) findMappedIdentities(cert *x509.Certificate) (*Identity, string) {
	identity := &Identity{}
	var source string

	// Check CN mapping
	if cert.Subject.CommonName != "" {
		if mapped, ok := t.cnMappings[cert.Subject.CommonName]; ok {
			identity.CommonName = mapped
			source = fmt.Sprintf("CN=%s", cert.Subject.CommonName)
		}
	}

	// Check Organization mappings
	if len(cert.Subject.Organization) > 0 {
		mappedOrgs := make([]string, 0, len(cert.Subject.Organization))
		for _, org := range cert.Subject.Organization {
			if mapped, ok := t.orgMappings[org]; ok {
				mappedOrgs = append(mappedOrgs, mapped)
				if source == "" {
					source = fmt.Sprintf("O=%s", org)
				}
			}
		}
		if len(mappedOrgs) > 0 {
			identity.Organization = mappedOrgs
		}
	}

	// Check OU mappings
	if len(cert.Subject.OrganizationalUnit) > 0 {
		mappedOUs := make([]string, 0, len(cert.Subject.OrganizationalUnit))
		for _, ou := range cert.Subject.OrganizationalUnit {
			if mapped, ok := t.ouMappings[ou]; ok {
				mappedOUs = append(mappedOUs, mapped)
				if source == "" {
					source = fmt.Sprintf("OU=%s", ou)
				}
			}
		}
		if len(mappedOUs) > 0 {
			identity.OrganizationUnit = mappedOUs
		}
	}

	// Check Locality mappings
	if len(cert.Subject.Locality) > 0 {
		mappedLocalities := make([]string, 0, len(cert.Subject.Locality))
		for _, l := range cert.Subject.Locality {
			if mapped, ok := t.locMappings[l]; ok {
				mappedLocalities = append(mappedLocalities, mapped)
				if source == "" {
					source = fmt.Sprintf("L=%s", l)
				}
			}
		}
		if len(mappedLocalities) > 0 {
			identity.Locality = mappedLocalities
		}
	}

	// Check Country mappings
	if len(cert.Subject.Country) > 0 {
		mappedCountries := make([]string, 0, len(cert.Subject.Country))
		for _, c := range cert.Subject.Country {
			if mapped, ok := t.countryMappings[c]; ok {
				mappedCountries = append(mappedCountries, mapped)
				if source == "" {
					source = fmt.Sprintf("C=%s", c)
				}
			}
		}
		if len(mappedCountries) > 0 {
			identity.Country = mappedCountries
		}
	}

	// Check State mappings
	if len(cert.Subject.Province) > 0 {
		mappedStates := make([]string, 0, len(cert.Subject.Province))
		for _, st := range cert.Subject.Province {
			if mapped, ok := t.stateMappings[st]; ok {
				mappedStates = append(mappedStates, mapped)
				if source == "" {
					source = fmt.Sprintf("ST=%s", st)
				}
			}
		}
		if len(mappedStates) > 0 {
			identity.State = mappedStates
		}
	}

	if source == "" {
		return nil, ""
	}

	return identity, source
}

// matchesSourceField checks if a certificate field matches the mapping condition
func (t *Translator) matchesSourceField(cert *x509.Certificate, field, value string) bool {
	if value == "*" {
		return true
	}

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
	if value == "*" {
		return true
	}

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

// GetSubjectFromIdentity returns a formatted string of the identity's subject fields
func (t *Translator) GetSubjectFromIdentity(identities []*Identity) string {
	if len(identities) == 0 {
		t.logger.Warn("No identities provided to GetSubjectFromIdentity")
		return ""
	}

	identity := identities[0]
	var fields []string

	// Maintain consistent field order: CN, O, OU, L, ST, C
	if identity.CommonName != "" {
		fields = append(fields, fmt.Sprintf("CN=%s", identity.CommonName))
	}
	if len(identity.Organization) > 0 {
		fields = append(fields, fmt.Sprintf("O=%s", identity.Organization[0]))
	}
	if len(identity.OrganizationUnit) > 0 {
		fields = append(fields, fmt.Sprintf("OU=%s", identity.OrganizationUnit[0]))
	}
	if len(identity.Locality) > 0 {
		fields = append(fields, fmt.Sprintf("L=%s", identity.Locality[0]))
	}
	if len(identity.State) > 0 {
		fields = append(fields, fmt.Sprintf("ST=%s", identity.State[0]))
	}
	if len(identity.Country) > 0 {
		fields = append(fields, fmt.Sprintf("C=%s", identity.Country[0]))
	}

	subject := strings.Join(fields, ", ")
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
		Auths:            []string{},
	}
}

func (t *Translator) getRoleMappings(cert *x509.Certificate) []string {
	roles := make([]string, 0)
	for _, mapping := range t.roleMappings {
		if t.matchesSourceField(cert, mapping.SourceField, mapping.SourceValue) {
			roles = append(roles, mapping.Roles...)
		}
	}
	return roles
}

func (t *Translator) getGroupMappings(cert *x509.Certificate) []string {
	groups := make([]string, 0)
	for _, mapping := range t.groupMappings {
		if t.matchesSourceField(cert, mapping.SourceField, mapping.SourceValue) {
			groups = append(groups, mapping.Groups...)
		}
	}
	return groups
}

func (t *Translator) getAuthMappings(cert *x509.Certificate) []string {
	auths := make([]string, 0)
	for _, mapping := range t.authMappings {
		if t.matchesSourceField(cert, mapping.SourceField, mapping.SourceValue) {
			auths = append(auths, mapping.Auths...)
		}
	}
	return auths
}

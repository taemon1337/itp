package identity

import (
	"crypto/x509"
	"fmt"
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
}

// NewTranslator creates a new identity translator
func NewTranslator(autoMap bool) *Translator {
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
	}
}

// AddMapping adds a mapping for a specific field
func (t *Translator) AddMapping(field, from string, to string) {
	switch field {
	case "common-name":
		t.cnMappings[from] = to
	case "organization":
		t.orgMappings[from] = to
	case "organization-unit":
		t.ouMappings[from] = to
	case "locality":
		t.locMappings[from] = to
	case "country":
		t.countryMappings[from] = to
	case "state":
		t.stateMappings[from] = to
	}
}

// AddRoleMapping adds a role mapping for a specific certificate attribute
func (t *Translator) AddRoleMapping(sourceField, sourceValue string, roles []string) {
	t.roleMappings = append(t.roleMappings, RoleMapping{
		SourceField: sourceField,
		SourceValue: sourceValue,
		Roles:       roles,
	})
}

// AddGroupMapping adds a group mapping for a specific certificate attribute
func (t *Translator) AddGroupMapping(sourceField, sourceValue string, groups []string) {
	t.groupMappings = append(t.groupMappings, GroupMapping{
		SourceField: sourceField,
		SourceValue: sourceValue,
		Groups:      groups,
	})
}

// TranslateIdentity translates a certificate's identity based on configured mappings
func (t *Translator) TranslateIdentity(cert *x509.Certificate) ([]Identity, error) {
	// Try to find specific mappings first
	identity := t.findMappedIdentities(cert)

	// If no mappings found and auto-map is enabled, use the certificate's CN
	if identity == nil && t.autoMap {
		return []Identity{{CommonName: cert.Subject.CommonName}}, nil
	}

	// If no mappings found and auto-map is disabled, return empty identity
	if identity == nil {
		return []Identity{{}}, nil
	}

	return []Identity{*identity}, nil
}

// findMappedIdentities looks for specific mappings for the certificate
func (t *Translator) findMappedIdentities(cert *x509.Certificate) *Identity {
	identity := &Identity{}
	hasMappings := false

	// Check CN mappings
	if cn, ok := t.cnMappings[cert.Subject.CommonName]; ok {
		identity.CommonName = cn
		hasMappings = true
	} else if t.autoMap {
		identity.CommonName = cert.Subject.CommonName
	}

	// Check Organization mappings
	for _, org := range cert.Subject.Organization {
		if mappedOrg, ok := t.orgMappings[org]; ok {
			identity.Organization = append(identity.Organization, mappedOrg)
			hasMappings = true
		} else if t.autoMap {
			identity.Organization = append(identity.Organization, org)
		}
	}

	// Check OU mappings
	for _, ou := range cert.Subject.OrganizationalUnit {
		if mappedOU, ok := t.ouMappings[ou]; ok {
			identity.OrganizationUnit = append(identity.OrganizationUnit, mappedOU)
			hasMappings = true
		} else if t.autoMap {
			identity.OrganizationUnit = append(identity.OrganizationUnit, ou)
		}
	}

	// Check Locality mappings
	for _, loc := range cert.Subject.Locality {
		if mappedLoc, ok := t.locMappings[loc]; ok {
			identity.Locality = append(identity.Locality, mappedLoc)
			hasMappings = true
		} else if t.autoMap {
			identity.Locality = append(identity.Locality, loc)
		}
	}

	// Check Country mappings
	for _, country := range cert.Subject.Country {
		if mappedCountry, ok := t.countryMappings[country]; ok {
			identity.Country = append(identity.Country, mappedCountry)
			hasMappings = true
		} else if t.autoMap {
			identity.Country = append(identity.Country, country)
		}
	}

	// Check State mappings
	for _, state := range cert.Subject.Province {
		if mappedState, ok := t.stateMappings[state]; ok {
			identity.State = append(identity.State, mappedState)
			hasMappings = true
		} else if t.autoMap {
			identity.State = append(identity.State, state)
		}
	}

	// Apply conditional role mappings
	for _, roleMapping := range t.roleMappings {
		switch roleMapping.SourceField {
		case "common-name":
			if cert.Subject.CommonName == roleMapping.SourceValue {
				identity.OrganizationUnit = append(identity.OrganizationUnit, roleMapping.Roles...)
				hasMappings = true
			}
		case "organization":
			for _, org := range cert.Subject.Organization {
				if org == roleMapping.SourceValue {
					identity.OrganizationUnit = append(identity.OrganizationUnit, roleMapping.Roles...)
					hasMappings = true
				}
			}
		case "organization-unit":
			for _, ou := range cert.Subject.OrganizationalUnit {
				if ou == roleMapping.SourceValue {
					identity.OrganizationUnit = append(identity.OrganizationUnit, roleMapping.Roles...)
					hasMappings = true
				}
			}
		case "locality":
			for _, loc := range cert.Subject.Locality {
				if loc == roleMapping.SourceValue {
					identity.OrganizationUnit = append(identity.OrganizationUnit, roleMapping.Roles...)
					hasMappings = true
				}
			}
		case "country":
			for _, country := range cert.Subject.Country {
				if country == roleMapping.SourceValue {
					identity.OrganizationUnit = append(identity.OrganizationUnit, roleMapping.Roles...)
					hasMappings = true
				}
			}
		case "state":
			for _, state := range cert.Subject.Province {
				if state == roleMapping.SourceValue {
					identity.OrganizationUnit = append(identity.OrganizationUnit, roleMapping.Roles...)
					hasMappings = true
				}
			}
		}
	}

	// Apply conditional group mappings
	for _, groupMapping := range t.groupMappings {
		switch groupMapping.SourceField {
		case "common-name":
			if cert.Subject.CommonName == groupMapping.SourceValue {
				identity.Organization = append(identity.Organization, groupMapping.Groups...)
				hasMappings = true
			}
		case "organization":
			for _, org := range cert.Subject.Organization {
				if org == groupMapping.SourceValue {
					identity.Organization = append(identity.Organization, groupMapping.Groups...)
					hasMappings = true
				}
			}
		case "organization-unit":
			for _, ou := range cert.Subject.OrganizationalUnit {
				if ou == groupMapping.SourceValue {
					identity.Organization = append(identity.Organization, groupMapping.Groups...)
					hasMappings = true
				}
			}
		case "locality":
			for _, loc := range cert.Subject.Locality {
				if loc == groupMapping.SourceValue {
					identity.Organization = append(identity.Organization, groupMapping.Groups...)
					hasMappings = true
				}
			}
		case "country":
			for _, country := range cert.Subject.Country {
				if country == groupMapping.SourceValue {
					identity.Organization = append(identity.Organization, groupMapping.Groups...)
					hasMappings = true
				}
			}
		case "state":
			for _, state := range cert.Subject.Province {
				if state == groupMapping.SourceValue {
					identity.Organization = append(identity.Organization, groupMapping.Groups...)
					hasMappings = true
				}
			}
		}
	}

	if hasMappings || t.autoMap {
		return identity
	}

	return nil
}

// GetSubjectFromIdentity creates a subject string from an identity
func (t *Translator) GetSubjectFromIdentity(identities []Identity) string {
	if len(identities) == 0 {
		return ""
	}

	identity := identities[0]
	var subject string

	if identity.CommonName != "" {
		subject += fmt.Sprintf("CN=%s", identity.CommonName)
	}

	for _, org := range identity.Organization {
		if subject != "" {
			subject += ","
		}
		subject += fmt.Sprintf("O=%s", org)
	}

	for _, ou := range identity.OrganizationUnit {
		if subject != "" {
			subject += ","
		}
		subject += fmt.Sprintf("OU=%s", ou)
	}

	for _, loc := range identity.Locality {
		if subject != "" {
			subject += ","
		}
		subject += fmt.Sprintf("L=%s", loc)
	}

	for _, country := range identity.Country {
		if subject != "" {
			subject += ","
		}
		subject += fmt.Sprintf("C=%s", country)
	}

	for _, state := range identity.State {
		if subject != "" {
			subject += ","
		}
		subject += fmt.Sprintf("ST=%s", state)
	}

	return subject
}

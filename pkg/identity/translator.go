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

// TranslateIdentity translates a certificate's identity based on configured mappings
func (t *Translator) TranslateIdentity(cert *x509.Certificate) ([]Identity, error) {
	// Try to find specific mappings first
	identities := t.findMappedIdentities(cert)
	if len(identities) > 0 {
		return identities, nil
	}

	// If no mappings found and auto-map is enabled, use the certificate's CN
	if t.autoMap {
		return []Identity{{CommonName: cert.Subject.CommonName}}, nil
	}

	return nil, fmt.Errorf("no identity mappings found for certificate")
}

// findMappedIdentities looks for specific mappings for the certificate
func (t *Translator) findMappedIdentities(cert *x509.Certificate) []Identity {
	identity := Identity{}
	hasMappings := false

	// Check CN mappings
	if cn, ok := t.cnMappings[cert.Subject.CommonName]; ok {
		identity.CommonName = cn
		hasMappings = true
	}

	// Check Organization mappings
	for _, org := range cert.Subject.Organization {
		if mappedOrg, ok := t.orgMappings[org]; ok {
			identity.Organization = append(identity.Organization, mappedOrg)
			hasMappings = true
		}
	}

	// Check OU mappings
	for _, ou := range cert.Subject.OrganizationalUnit {
		if mappedOU, ok := t.ouMappings[ou]; ok {
			identity.OrganizationUnit = append(identity.OrganizationUnit, mappedOU)
			hasMappings = true
		}
	}

	// Check Locality mappings
	for _, loc := range cert.Subject.Locality {
		if mappedLoc, ok := t.locMappings[loc]; ok {
			identity.Locality = append(identity.Locality, mappedLoc)
			hasMappings = true
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

	if !hasMappings {
		return nil
	}

	// If we have mappings, also include unmapped fields if autoMap is enabled
	if t.autoMap {
		if identity.CommonName == "" {
			identity.CommonName = cert.Subject.CommonName
		}
		if len(identity.Organization) == 0 {
			identity.Organization = cert.Subject.Organization
		}
		if len(identity.OrganizationUnit) == 0 {
			identity.OrganizationUnit = cert.Subject.OrganizationalUnit
		}
		if len(identity.Locality) == 0 {
			identity.Locality = cert.Subject.Locality
		}
		if len(identity.Country) == 0 {
			identity.Country = cert.Subject.Country
		}
		if len(identity.State) == 0 {
			identity.State = cert.Subject.Province
		}
	}

	return []Identity{identity}
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

package identity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
)

// Mapping represents a certificate field mapping to an identity
type Mapping struct {
	SourceValue string
	Identity    string
}

// Translator handles identity translation between certificate domains
type Translator struct {
	commonNameMappings   map[string]string
	organizationMappings map[string]string
	countryMappings      map[string]string
	stateMappings        map[string]string
	localityMappings     map[string]string
	orgUnitMappings      map[string]string
}

// NewTranslator creates a new identity translator
func NewTranslator() *Translator {
	return &Translator{
		commonNameMappings:   make(map[string]string),
		organizationMappings: make(map[string]string),
		countryMappings:      make(map[string]string),
		stateMappings:        make(map[string]string),
		localityMappings:     make(map[string]string),
		orgUnitMappings:      make(map[string]string),
	}
}

// AddMapping adds a mapping for a specific certificate field
func (t *Translator) AddMapping(field string, sourceValue, identity string) error {
	switch field {
	case "CN":
		t.commonNameMappings[sourceValue] = identity
	case "O":
		t.organizationMappings[sourceValue] = identity
	case "C":
		t.countryMappings[sourceValue] = identity
	case "ST":
		t.stateMappings[sourceValue] = identity
	case "L":
		t.localityMappings[sourceValue] = identity
	case "OU":
		t.orgUnitMappings[sourceValue] = identity
	default:
		return fmt.Errorf("unsupported certificate field: %s", field)
	}
	return nil
}

// TranslateIdentity translates a certificate's identity based on configured mappings
func (t *Translator) TranslateIdentity(cert *x509.Certificate) ([]string, error) {
	var identities []string

	// Check Common Name mapping
	if identity, ok := t.commonNameMappings[cert.Subject.CommonName]; ok {
		identities = append(identities, identity)
	}

	// Check Organization mappings
	for _, org := range cert.Subject.Organization {
		if identity, ok := t.organizationMappings[org]; ok {
			identities = append(identities, identity)
		}
	}

	// Check Country mappings
	for _, country := range cert.Subject.Country {
		if identity, ok := t.countryMappings[country]; ok {
			identities = append(identities, identity)
		}
	}

	// Check State mappings
	for _, state := range cert.Subject.Province {
		if identity, ok := t.stateMappings[state]; ok {
			identities = append(identities, identity)
		}
	}

	// Check Locality mappings
	for _, locality := range cert.Subject.Locality {
		if identity, ok := t.localityMappings[locality]; ok {
			identities = append(identities, identity)
		}
	}

	// Check OrganizationalUnit mappings
	for _, ou := range cert.Subject.OrganizationalUnit {
		if identity, ok := t.orgUnitMappings[ou]; ok {
			identities = append(identities, identity)
		}
	}

	if len(identities) == 0 {
		return nil, fmt.Errorf("no identity mappings found for certificate")
	}

	return identities, nil
}

// GetSubjectFromIdentity returns a pkix.Name for the translated identity
func (t *Translator) GetSubjectFromIdentity(identities []string) pkix.Name {
	// For now, we'll use a simple implementation that sets the CN to the first identity
	// and adds additional identities as OrganizationalUnits
	subject := pkix.Name{
		CommonName:         identities[0],
		OrganizationalUnit: identities[1:],
	}
	return subject
}

package identity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTranslator(t *testing.T) {
	tr := NewTranslator(true)
	assert.NotNil(t, tr)
	assert.True(t, tr.autoMap)
	assert.NotNil(t, tr.cnMappings)
	assert.NotNil(t, tr.ouMappings)
	assert.NotNil(t, tr.orgMappings)
	assert.NotNil(t, tr.locMappings)
	assert.NotNil(t, tr.countryMappings)
	assert.NotNil(t, tr.stateMappings)
}

func TestAddMapping(t *testing.T) {
	tr := NewTranslator(false)
	tests := []struct {
		name  string
		field string
		from  string
		to    string
		check func() bool
	}{
		{
			name:  "common name mapping",
			field: "common-name",
			from:  "test.com",
			to:    "mapped.com",
			check: func() bool { return tr.cnMappings["test.com"] == "mapped.com" },
		},
		{
			name:  "organization unit mapping",
			field: "organization-unit",
			from:  "TestOU",
			to:    "MappedOU",
			check: func() bool { return tr.ouMappings["TestOU"] == "MappedOU" },
		},
		{
			name:  "organization mapping",
			field: "organization",
			from:  "TestOrg",
			to:    "MappedOrg",
			check: func() bool { return tr.orgMappings["TestOrg"] == "MappedOrg" },
		},
		{
			name:  "locality mapping",
			field: "locality",
			from:  "TestCity",
			to:    "MappedCity",
			check: func() bool { return tr.locMappings["TestCity"] == "MappedCity" },
		},
		{
			name:  "country mapping",
			field: "country",
			from:  "US",
			to:    "GB",
			check: func() bool { return tr.countryMappings["US"] == "GB" },
		},
		{
			name:  "state mapping",
			field: "state",
			from:  "CA",
			to:    "NY",
			check: func() bool { return tr.stateMappings["CA"] == "NY" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr.AddMapping(tt.field, tt.from, tt.to)
			assert.True(t, tt.check())
		})
	}
}

func TestTranslateIdentity(t *testing.T) {
	tr := NewTranslator(true)
	tr.AddMapping("common-name", "test.com", "mapped.com")
	tr.AddMapping("organization", "TestOrg", "MappedOrg")

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "test.com",
			Organization: []string{"TestOrg"},
			Country:     []string{"US"},
		},
	}

	identities, err := tr.TranslateIdentity(cert)
	assert.NoError(t, err)
	assert.Len(t, identities, 1)
	assert.Equal(t, "mapped.com", identities[0].CommonName)
	assert.Equal(t, []string{"MappedOrg"}, identities[0].Organization)
	assert.Equal(t, []string{"US"}, identities[0].Country)
}

func TestGetSubjectFromIdentity(t *testing.T) {
	tr := NewTranslator(false)
	identities := []Identity{
		{
			CommonName:       "test.com",
			Organization:     []string{"TestOrg"},
			OrganizationUnit: []string{"TestOU"},
			Locality:         []string{"TestCity"},
			Country:          []string{"US"},
			State:            []string{"CA"},
		},
	}

	subject := tr.GetSubjectFromIdentity(identities)
	assert.Contains(t, subject, "CN=test.com")
	assert.Contains(t, subject, "O=TestOrg")
	assert.Contains(t, subject, "OU=TestOU")
	assert.Contains(t, subject, "L=TestCity")
	assert.Contains(t, subject, "C=US")
	assert.Contains(t, subject, "ST=CA")
}

func TestTranslator_ConditionalRoleMappings(t *testing.T) {
	translator := NewTranslator(true)

	// Add some conditional role mappings
	translator.AddRoleMapping("common-name", "admin@example.com", []string{"cluster-admin", "developer"})
	translator.AddRoleMapping("organization", "platform-team", []string{"operator", "deployer"})
	translator.AddRoleMapping("organization-unit", "engineering", []string{"eng-lead", "builder"})

	tests := []struct {
		name          string
		cert         *x509.Certificate
		expectedRoles []string
	}{
		{
			name: "CN match should add roles",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "admin@example.com",
				},
			},
			expectedRoles: []string{"cluster-admin", "developer"},
		},
		{
			name: "Organization match should add roles",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"platform-team"},
				},
			},
			expectedRoles: []string{"operator", "deployer"},
		},
		{
			name: "OU match should add roles",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{"engineering"},
				},
			},
			expectedRoles: []string{"eng-lead", "builder"},
		},
		{
			name: "Multiple matches should add all roles",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:         "admin@example.com",
					Organization:       []string{"platform-team"},
					OrganizationalUnit: []string{"engineering"},
				},
			},
			expectedRoles: []string{"cluster-admin", "developer", "operator", "deployer", "eng-lead", "builder"},
		},
		{
			name: "No matches should add no roles",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "user@example.com",
					Organization: []string{"other-team"},
				},
			},
			expectedRoles: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identities, err := translator.TranslateIdentity(tt.cert)
			assert.NoError(t, err)
			if tt.expectedRoles == nil {
				assert.Empty(t, identities[0].OrganizationUnit)
			} else {
				assert.ElementsMatch(t, tt.expectedRoles, identities[0].OrganizationUnit)
			}
		})
	}
}

func TestTranslator_ConditionalGroupMappings(t *testing.T) {
	translator := NewTranslator(true)

	// Add some conditional group mappings
	translator.AddGroupMapping("common-name", "admin@example.com", []string{"platform-admins", "sre"})
	translator.AddGroupMapping("organization", "platform-team", []string{"platform", "infra"})
	translator.AddGroupMapping("organization-unit", "engineering", []string{"eng-team", "builders"})

	tests := []struct {
		name            string
		cert           *x509.Certificate
		expectedGroups []string
	}{
		{
			name: "CN match should add groups",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "admin@example.com",
				},
			},
			expectedGroups: []string{"platform-admins", "sre"},
		},
		{
			name: "Organization match should add groups",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"platform-team"},
				},
			},
			expectedGroups: []string{"platform", "infra"},
		},
		{
			name: "OU match should add groups",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{"engineering"},
				},
			},
			expectedGroups: []string{"eng-team", "builders"},
		},
		{
			name: "Multiple matches should add all groups",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:         "admin@example.com",
					Organization:       []string{"platform-team"},
					OrganizationalUnit: []string{"engineering"},
				},
			},
			expectedGroups: []string{"platform-admins", "sre", "platform", "infra", "eng-team", "builders"},
		},
		{
			name: "No matches should add no groups",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "user@example.com",
					Organization: []string{"other-team"},
				},
			},
			expectedGroups: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identities, err := translator.TranslateIdentity(tt.cert)
			assert.NoError(t, err)
			if tt.expectedGroups == nil {
				assert.Empty(t, identities[0].Organization)
			} else {
				assert.ElementsMatch(t, tt.expectedGroups, identities[0].Organization)
			}
		})
	}
}

func TestTranslator_MixedMappings(t *testing.T) {
	translator := NewTranslator(true)

	// Add regular mappings
	translator.AddMapping("common-name", "admin@example.com", "internal-admin")
	translator.AddMapping("organization", "external-team", "internal-team")

	// Add role and group mappings
	translator.AddRoleMapping("common-name", "admin@example.com", []string{"cluster-admin"})
	translator.AddGroupMapping("organization", "external-team", []string{"platform"})

	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "admin@example.com",
			Organization: []string{"external-team"},
		},
	}

	identities, err := translator.TranslateIdentity(cert)
	assert.NoError(t, err)
	assert.Equal(t, "internal-admin", identities[0].CommonName)
	assert.Contains(t, identities[0].Organization, "internal-team")
	assert.Contains(t, identities[0].Organization, "platform")
	assert.Contains(t, identities[0].OrganizationUnit, "cluster-admin")
}

func TestTranslator_TranslationErrors(t *testing.T) {
	translator := NewTranslator(false)

	tests := []struct {
		name        string
		cert       *x509.Certificate
		expectedErr *TranslationError
	}{
		{
			name: "No mappings should return error with details",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "user@example.com",
					Organization: []string{"other-team"},
				},
			},
			expectedErr: &TranslationError{
				Code:    ErrNoMappings,
				Message: "no identity mappings found for certificate (CN=user@example.com, O=[other-team])",
			},
		},
		{
			name: "Empty CN with autoMap disabled should return error",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"other-team"},
				},
			},
			expectedErr: &TranslationError{
				Code:    ErrNoMappings,
				Message: "no identity mappings found for certificate (CN=, O=[other-team])",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := translator.TranslateIdentity(tt.cert)
			assert.Error(t, err)
			if translationErr, ok := err.(*TranslationError); ok {
				assert.Equal(t, tt.expectedErr.Code, translationErr.Code)
				assert.Equal(t, tt.expectedErr.Message, translationErr.Message)
			} else {
				t.Error("Expected TranslationError type")
			}
		})
	}
}

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

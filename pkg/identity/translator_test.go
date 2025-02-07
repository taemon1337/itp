package identity

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/itp/pkg/logger"
	"github.com/stretchr/testify/assert"
)

// setupTestLogger creates a logger for testing
func setupTestLogger() *logger.Logger {
	return logger.New("translator", logger.LevelDebug)
}

func TestNewTranslator(t *testing.T) {
	logger := setupTestLogger()
	tr := NewTranslator(logger, true)
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
	logger := setupTestLogger()
	tr := NewTranslator(logger, false)
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
	logger := setupTestLogger()
	translator := NewTranslator(logger, true) // Enable auto-mapping

	// Add mappings
	translator.AddMapping("CN", "test.com", "mapped.com")
	translator.AddMapping("O", "TestOrg", "MappedOrg")

	// Create test certificate
	cert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "test.com",
			Organization: []string{"TestOrg"},
			Country:      []string{"US"},
		},
	}

	// Translate identity
	identity, err := translator.TranslateIdentity(cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	// Check mappings
	assert.Equal(t, "mapped.com", identity.CommonName)
	assert.Equal(t, []string{"MappedOrg"}, identity.Organization)
	assert.Equal(t, []string{"US"}, identity.Country)
}

func TestGetSubjectFromIdentity(t *testing.T) {
	logger := setupTestLogger()
	translator := NewTranslator(logger, true)

	tests := []struct {
		name     string
		identity *Identity
		want     string
	}{
		{
			name: "all_fields",
			identity: &Identity{
				CommonName:       "test.com",
				Organization:     []string{"TestOrg"},
				OrganizationUnit: []string{"TestOU"},
				Locality:         []string{"TestLocality"},
				Country:          []string{"TestCountry"},
				State:            []string{"TestState"},
			},
			want: "CN=test.com, O=TestOrg, OU=TestOU, L=TestLocality, ST=TestState, C=TestCountry",
		},
		{
			name:     "empty_identities",
			identity: nil,
			want:     "",
		},
		{
			name: "partial_fields",
			identity: &Identity{
				CommonName:   "test.com",
				Organization: []string{"TestOrg"},
			},
			want: "CN=test.com, O=TestOrg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var identities []*Identity
			if tt.identity != nil {
				identities = []*Identity{tt.identity}
			}
			if got := translator.GetSubjectFromIdentity(identities); got != tt.want {
				t.Errorf("GetSubjectFromIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTranslator_ConditionalRoleMappings(t *testing.T) {
	logger := setupTestLogger()
	translator := NewTranslator(logger, true)

	// Add some conditional role mappings
	translator.AddRoleMapping("common-name", "admin@example.com", []string{"cluster-admin", "developer"})
	translator.AddRoleMapping("organization", "platform-team", []string{"operator", "deployer"})
	translator.AddRoleMapping("organization-unit", "engineering", []string{"eng-lead", "builder"})

	tests := []struct {
		name          string
		cert          *x509.Certificate
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
			identity, err := translator.TranslateIdentity(tt.cert)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			if tt.expectedRoles == nil {
				// For the "no matches" case, we should either get no identities
				// or an identity with empty roles
				assert.Empty(t, identity.Roles)
			} else {
				assert.ElementsMatch(t, tt.expectedRoles, identity.Roles)
			}
		})
	}
}

func TestTranslator_ConditionalGroupMappings(t *testing.T) {
	logger := setupTestLogger()
	translator := NewTranslator(logger, true)

	// Add some conditional group mappings
	translator.AddGroupMapping("common-name", "admin@example.com", []string{"platform-admins", "sre"})
	translator.AddGroupMapping("organization", "platform-team", []string{"platform", "infra"})
	translator.AddGroupMapping("organization-unit", "engineering", []string{"eng-team", "builders"})

	tests := []struct {
		name           string
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
			identity, err := translator.TranslateIdentity(tt.cert)
			if err != nil {
				t.Fatalf("Expected no error, got: %v", err)
			}
			if tt.expectedGroups == nil {
				// For the "no matches" case, we should either get no identities
				// or an identity with empty groups
				assert.Empty(t, identity.Groups)
			} else {
				assert.ElementsMatch(t, tt.expectedGroups, identity.Groups)
			}
		})
	}
}

func TestTranslator_MixedMappings(t *testing.T) {
	logger := setupTestLogger()
	translator := NewTranslator(logger, true)

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

	identity, err := translator.TranslateIdentity(cert)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	assert.Equal(t, "internal-admin", identity.CommonName)
	assert.Contains(t, identity.Organization, "internal-team")
	assert.Contains(t, identity.Groups, "platform")
	assert.Contains(t, identity.Roles, "cluster-admin")
}

func TestTranslator_TranslationErrors(t *testing.T) {
	logger := setupTestLogger()
	translator := NewTranslator(logger, false)

	tests := []struct {
		name          string
		cert          *x509.Certificate
		wantErrCode   string
		wantErrDetail string
	}{
		{
			name: "No mappings should return error with details",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "user@example.com",
					Organization: []string{"other-team"},
				},
			},
			wantErrCode:   "NO_IDENTITY_MAPPINGS",
			wantErrDetail: "no identity mappings found for certificate and auto-mapping is disabled:\n- Common Name: \"user@example.com\"\n- Organization: [\"other-team\"]\n",
		},
		{
			name: "Empty CN with autoMap disabled should return error",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"other-team"},
				},
			},
			wantErrCode:   "NO_IDENTITY_MAPPINGS",
			wantErrDetail: "no identity mappings found for certificate and auto-mapping is disabled:\n- Common Name: \"\"\n- Organization: [\"other-team\"]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := translator.TranslateIdentity(tt.cert)
			if identity != nil {
				t.Error("Expected nil identity")
			}

			if err == nil {
				t.Fatal("Expected error")
			}

			tErr, ok := err.(*TranslationError)
			if !ok {
				t.Fatalf("Expected TranslationError, got %T", err)
			}

			if tErr.Code != tt.wantErrCode {
				t.Errorf("Expected error code %q, got %q", tt.wantErrCode, tErr.Code)
			}

			if tErr.Message != tt.wantErrDetail {
				t.Errorf("Expected error detail %q, got %q", tt.wantErrDetail, tErr.Message)
			}
		})
	}
}

func TestTranslator_ConditionalAuthMappings(t *testing.T) {
	logger := setupTestLogger()
	translator := NewTranslator(logger, true)

	// Add some conditional auth mappings
	translator.AddAuthMapping("common-name", "admin@example.com", []string{"read", "write"})
	translator.AddAuthMapping("organization", "platform-team", []string{"deploy", "manage"})
	translator.AddAuthMapping("organization-unit", "engineering", []string{"create", "delete"})

	tests := []struct {
		name          string
		cert          *x509.Certificate
		expectedAuths []string
	}{
		{
			name: "CN match should add auths",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName: "admin@example.com",
				},
			},
			expectedAuths: []string{"read", "write"},
		},
		{
			name: "Organization match should add auths",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					Organization: []string{"platform-team"},
				},
			},
			expectedAuths: []string{"deploy", "manage"},
		},
		{
			name: "OU match should add auths",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					OrganizationalUnit: []string{"engineering"},
				},
			},
			expectedAuths: []string{"create", "delete"},
		},
		{
			name: "Multiple matches should combine auths",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:         "admin@example.com",
					Organization:       []string{"platform-team"},
					OrganizationalUnit: []string{"engineering"},
				},
			},
			expectedAuths: []string{"read", "write", "deploy", "manage", "create", "delete"},
		},
		{
			name: "No matches should result in empty auths",
			cert: &x509.Certificate{
				Subject: pkix.Name{
					CommonName:   "user@example.com",
					Organization: []string{"other-team"},
				},
			},
			expectedAuths: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := translator.TranslateIdentity(tt.cert)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expectedAuths, identity.Auths)
		})
	}
}

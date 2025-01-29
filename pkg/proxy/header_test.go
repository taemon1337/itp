package proxy

import (
	"reflect"
	"testing"

	"github.com/itp/pkg/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeaderInjector(t *testing.T) {
	tests := []struct {
		name      string
		upstream  string
		headers   map[string]string
		id        *identity.Identity
		expected  map[string]string
		wantError bool
	}{
		{
			name:     "basic template",
			upstream: "test-upstream",
			headers: map[string]string{
				"X-User": "{{ .CommonName }}",
			},
			id: &identity.Identity{
				CommonName: "test-user",
			},
			expected: map[string]string{
				"X-User": "test-user",
			},
		},
		{
			name:     "multiple fields",
			upstream: "test-upstream",
			headers: map[string]string{
				"X-User": "{{ .CommonName }}/{{ .Organization }}",
			},
			id: &identity.Identity{
				CommonName:    "test-user",
				Organization: []string{"test-org"},
			},
			expected: map[string]string{
				"X-User": "test-user/[test-org]",
			},
		},
		{
			name:     "multiple headers",
			upstream: "test-upstream",
			headers: map[string]string{
				"X-User": "{{ .CommonName }}",
				"X-Org":  "{{ .Organization }}",
			},
			id: &identity.Identity{
				CommonName:    "test-user",
				Organization: []string{"test-org"},
			},
			expected: map[string]string{
				"X-User": "test-user",
				"X-Org":  "[test-org]",
			},
		},
		{
			name:     "invalid template",
			upstream: "test-upstream",
			headers: map[string]string{
				"X-User": "{{ .Invalid }}",
			},
			id: &identity.Identity{
				CommonName: "test-user",
			},
			expected:  map[string]string{},
			wantError: true,
		},
		{
			name:     "common headers",
			upstream: "test-upstream",
			headers: map[string]string{
				"X-CN":  "{{ .CommonName }}",
				"X-Org": "{{ .Organization }}",
				"X-OU":  "{{ .OrganizationUnit }}",
			},
			id: &identity.Identity{
				CommonName:         "test-user",
				Organization:      []string{"test-org"},
				OrganizationUnit: []string{"test-ou"},
			},
			expected: map[string]string{
				"X-CN":  "test-user",
				"X-Org": "[test-org]",
				"X-OU":  "[test-ou]",
			},
		},
		{
			name:     "multiple identities",
			upstream: "test-upstream",
			headers: map[string]string{
				"X-Users": "{{ .CommonName }}",
				"X-Orgs":  "{{ .Organization }}",
			},
			id: &identity.Identity{
				CommonName:    "user1",
				Organization: []string{"org1"},
			},
			expected: map[string]string{
				"X-Users": "user1",
				"X-Orgs":  "[org1]",
			},
		},
		{
			name:     "empty values",
			upstream: "test-upstream",
			headers: map[string]string{
				"X-Empty": "{{ .CommonName }}",
			},
			id:       &identity.Identity{},
			expected: map[string]string{},
		},
		{
			name:     "wrong upstream",
			upstream: "wrong-upstream",
			headers: map[string]string{
				"X-User": "{{ .CommonName }}",
			},
			id: &identity.Identity{
				CommonName: "test-user",
			},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHeaderInjector()
			for name, tmpl := range tt.headers {
				err := h.AddHeader("test-upstream", name, tmpl)
				if tt.wantError {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			}
			result := h.GetHeaders(tt.upstream, []*identity.Identity{tt.id})
			assert.Equal(t, tt.expected, result, "GetHeaders()")
		})
	}
}

func TestHeaderInjector_AddCommonHeader(t *testing.T) {
	tests := []struct {
		name      string
		headerType string
		upstream  string
		headerName string
		wantErr   bool
	}{
		{
			name:       "valid cn",
			headerType: "cn",
			upstream:   "app.svc",
			headerName: "X-User",
		},
		{
			name:       "valid org",
			headerType: "org",
			upstream:   "app.svc",
			headerName: "X-Team",
		},
		{
			name:       "valid ou",
			headerType: "ou",
			upstream:   "app.svc",
			headerName: "X-Department",
		},
		{
			name:       "invalid type",
			headerType: "invalid",
			upstream:   "app.svc",
			headerName: "X-Header",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHeaderInjector()
			err := h.AddCommonHeader(tt.headerType, tt.upstream, tt.headerName)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddCommonHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name  string
		slice []string
		items []string
		want  []string
	}{
		{
			name:  "unique items",
			slice: []string{"a", "b"},
			items: []string{"c", "d"},
			want:  []string{"a", "b", "c", "d"},
		},
		{
			name:  "duplicate items",
			slice: []string{"a", "b"},
			items: []string{"b", "c"},
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "empty slice",
			slice: nil,
			items: []string{"a", "b"},
			want:  []string{"a", "b"},
		},
		{
			name:  "empty items",
			slice: []string{"a", "b"},
			items: nil,
			want:  []string{"a", "b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(map[string]bool)
			for _, s := range tt.slice {
				seen[s] = true
			}
			got := appendUnique(tt.slice, tt.items, seen)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("appendUnique() = %v, want %v", got, tt.want)
			}
		})
	}
}

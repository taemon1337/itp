package proxy

import (
	"reflect"
	"testing"

	"github.com/itp/pkg/identity"
)

func TestHeaderInjector(t *testing.T) {
	tests := []struct {
		name      string
		upstream  string
		headers   map[string]string // header name -> template
		common    map[string]string // type -> header name
		identities []identity.Identity
		want      map[string]string // expected headers
		wantErr   bool
	}{
		{
			name:     "basic template",
			upstream: "app.svc",
			headers: map[string]string{
				"X-User": "{{.CommonName}}",
			},
			identities: []identity.Identity{
				{CommonName: "test-user"},
			},
			want: map[string]string{
				"X-User": "test-user",
			},
		},
		{
			name:     "multiple fields",
			upstream: "app.svc",
			headers: map[string]string{
				"X-Identity": "{{.CommonName}}/{{.Organization}}",
			},
			identities: []identity.Identity{
				{
					CommonName:   "test-user",
					Organization: []string{"org1", "org2"},
				},
			},
			want: map[string]string{
				"X-Identity": "test-user/[org1 org2]",
			},
		},
		{
			name:     "multiple headers",
			upstream: "app.svc",
			headers: map[string]string{
				"X-User": "{{.CommonName}}",
				"X-Org":  "{{.Organization}}",
			},
			identities: []identity.Identity{
				{
					CommonName:   "test-user",
					Organization: []string{"org1"},
				},
			},
			want: map[string]string{
				"X-User": "test-user",
				"X-Org":  "[org1]",
			},
		},
		{
			name:     "invalid template",
			upstream: "app.svc",
			headers: map[string]string{
				"X-Bad": "{{.Invalid}}",
			},
			wantErr: true,
		},
		{
			name:     "common headers",
			upstream: "app.svc",
			common: map[string]string{
				"cn":  "X-User",
				"org": "X-Team",
			},
			identities: []identity.Identity{
				{
					CommonName:   "test-user",
					Organization: []string{"org1"},
				},
			},
			want: map[string]string{
				"X-User": "test-user",
				"X-Team": "[org1]",
			},
		},
		{
			name:     "multiple identities",
			upstream: "app.svc",
			headers: map[string]string{
				"X-Users": "{{.CommonName}}",
				"X-Orgs":  "{{.Organization}}",
			},
			identities: []identity.Identity{
				{
					CommonName:   "user1",
					Organization: []string{"org1"},
				},
				{
					CommonName:   "user2",
					Organization: []string{"org2"},
				},
			},
			want: map[string]string{
				"X-Users": "user1", // Should use first identity's CN
				"X-Orgs":  "[org1 org2]", // Should combine orgs
			},
		},
		{
			name:     "empty values",
			upstream: "app.svc",
			headers: map[string]string{
				"X-Empty": "{{.CommonName}}",
			},
			identities: []identity.Identity{
				{}, // Empty identity
			},
			want: map[string]string{
				"X-Empty": "", // Empty values should still create header
			},
		},
		{
			name:     "wrong upstream",
			upstream: "other.svc",
			headers: map[string]string{
				"X-User": "{{.CommonName}}",
			},
			identities: []identity.Identity{
				{CommonName: "test-user"},
			},
			want: map[string]string{}, // No headers for wrong upstream
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHeaderInjector()

			// Add custom headers
			for name, tmpl := range tt.headers {
				err := h.AddHeader(tt.upstream, name, tmpl)
				if (err != nil) != tt.wantErr {
					t.Errorf("AddHeader() error = %v, wantErr %v", err, tt.wantErr)
					return
				}
				if tt.wantErr {
					return
				}
			}

			// Add common headers
			for typ, name := range tt.common {
				if err := h.AddCommonHeader(typ, tt.upstream, name); err != nil {
					t.Errorf("AddCommonHeader() error = %v", err)
					return
				}
			}

			got := h.GetHeaders(tt.upstream, tt.identities)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetHeaders() = %v, want %v", got, tt.want)
			}
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

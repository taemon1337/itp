package proxy

import (
	"reflect"
	"testing"

	"github.com/itp/pkg/identity"
)

func TestHeaderInjector(t *testing.T) {
	tests := []struct {
		name     string
		identity *identity.Identity
		template string
		want     string
	}{
		{
			name: "basic_template",
			identity: &identity.Identity{
				CommonName: "test-user",
			},
			template: "{{ .CommonName }}",
			want:     "test-user",
		},
		{
			name: "multiple_fields",
			identity: &identity.Identity{
				CommonName:       "test-user",
				Organization:     []string{"test-org"},
				OrganizationUnit: []string{"test-ou"},
			},
			template: "{{ .CommonName }}/{{ index .Organization 0 }}/{{ index .OrganizationUnit 0 }}",
			want:     "test-user/test-org/test-ou",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			injector := NewHeaderInjector()
			err := injector.AddHeader("test-upstream", "X-User", tt.template)
			if err != nil {
				t.Fatalf("Failed to add header: %v", err)
			}

			headers, err := injector.GetHeaders("test-upstream", tt.identity)
			if err != nil {
				t.Fatalf("Failed to get headers: %v", err)
			}

			if headers["X-User"] != tt.want {
				t.Errorf("Expected header value %q, got %q", tt.want, headers["X-User"])
			}
		})
	}
}

func TestCommonHeaders(t *testing.T) {
	injector := NewHeaderInjector()

	// Add common headers
	err := injector.AddCommonHeader("cn", "test-upstream", "X-Common-CN")
	if err != nil {
		t.Fatalf("Failed to add CN header: %v", err)
	}

	err = injector.AddCommonHeader("groups", "test-upstream", "X-Common-Groups")
	if err != nil {
		t.Fatalf("Failed to add groups header: %v", err)
	}

	identity := &identity.Identity{
		CommonName: "test-user",
		Groups:    []string{"group1", "group2"},
	}

	headers, err := injector.GetHeaders("test-upstream", identity)
	if err != nil {
		t.Fatalf("Failed to get headers: %v", err)
	}

	if headers["X-Common-CN"] != "test-user" {
		t.Errorf("Expected CN header value %q, got %q", "test-user", headers["X-Common-CN"])
	}

	if headers["X-Common-Groups"] != "group1group2" {
		t.Errorf("Expected groups header value %q, got %q", "group1group2", headers["X-Common-Groups"])
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

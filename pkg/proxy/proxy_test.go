package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/itp/pkg/certstore"
	"github.com/itp/pkg/identity"
	"github.com/itp/pkg/router"
	"github.com/stretchr/testify/assert"
)

// mockConn implements net.Conn interface for testing
type mockConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return 0, nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestNew(t *testing.T) {
	r := &router.Router{}
	tr := &identity.Translator{}
	store, err := certstore.NewGeneratedStore(certstore.GeneratedOptions{
		CommonName:    "Test CA",
		Expiry:       24 * time.Hour,
		DefaultTTL:   1 * time.Hour,
		CacheDuration: 5 * time.Minute,
	})
	assert.NoError(t, err)
	allowUnknown := true

	p := New(r, tr, store, allowUnknown)

	assert.NotNil(t, p)
	assert.Equal(t, r, p.router)
	assert.Equal(t, tr, p.translator)
	assert.Equal(t, store, p.certStore)
	assert.Equal(t, allowUnknown, p.allowUnknownCerts)
}

func TestGetDefaultSNI(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		expected string
	}{
		{
			name:     "localhost IPv4",
			addr:     "127.0.0.1:8080",
			expected: "localhost",
		},
		{
			name:     "localhost IPv6",
			addr:     "[::1]:8080",
			expected: "localhost",
		},
		{
			name:     "any IPv4",
			addr:     "0.0.0.0:8080",
			expected: "localhost",
		},
		{
			name:     "any IPv6",
			addr:     "[::]:8080",
			expected: "localhost",
		},
		{
			name:     "specific IP",
			addr:     "192.168.1.1:8080",
			expected: "192.168.1.1",
		},
	}

	p := &Proxy{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := net.ResolveTCPAddr("tcp", tt.addr)
			assert.NoError(t, err)
			
			conn := &mockConn{localAddr: addr}
			result := p.getDefaultSNI(conn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

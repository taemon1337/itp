package tls

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

// Config holds TLS configuration parameters
type Config struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// NewTLSConfig creates a new TLS configuration
func NewTLSConfig(config Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		return nil, err
	}

	caCert, err := ioutil.ReadFile(config.CAFile)
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}, nil
}

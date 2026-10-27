// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func TestMain(m *testing.M) {
	// Set up logger for tests
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	os.Exit(m.Run())
}

// generateTestCertificate generates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Encode certificate to PEM
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// Encode private key to PEM
	privBytes, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM
}

func TestNewTLSConfig_LoadsCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	certPEM, keyPEM := generateTestCertificate(t)
	caPEM, _ := generateTestCertificate(t)

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	config := HTTPSServerConfig{
		TLSCertFilePath: certPath,
		TLSKeyFilePath:  keyPath,
		CAFilePath:      caPath,
	}

	logger := ctrl.Log.WithName("test")
	tlsConfig, certWatcher, err := config.NewTLSConfig(logger)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	require.NotNil(t, certWatcher)

	// Verify TLS config settings
	assert.Equal(t, tls.RequestClientCert, tlsConfig.ClientAuth)
	assert.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	assert.NotNil(t, tlsConfig.GetCertificate)
	assert.NotNil(t, tlsConfig.VerifyConnection)

	// Verify GetCertificate returns the loaded certificate
	cert, err := tlsConfig.GetCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}

func TestNewTLSConfig_InvalidCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	require.NoError(t, os.WriteFile(certPath, []byte("invalid"), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte("invalid"), 0o600))
	require.NoError(t, os.WriteFile(caPath, []byte("invalid"), 0o600))

	config := HTTPSServerConfig{
		TLSCertFilePath: certPath,
		TLSKeyFilePath:  keyPath,
		CAFilePath:      caPath,
	}

	logger := ctrl.Log.WithName("test")
	_, _, err := config.NewTLSConfig(logger)
	require.Error(t, err)
}

// generateCertificateChain generates a certificate chain: root CA -> intermediate CA -> leaf cert.
func generateCertificateChain(t *testing.T) (rootCAPEM []byte, intermediateCert, leafCert *x509.Certificate) {
	t.Helper()

	// Generate root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA"},
			CommonName:   "Test Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	// Generate intermediate CA
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	intermediateTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Intermediate CA"},
			CommonName:   "Test Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	intermediateDER, err := x509.CreateCertificate(rand.Reader, &intermediateTemplate, rootCert, &intermediateKey.PublicKey, rootKey)
	require.NoError(t, err)
	intermediateCert, err = x509.ParseCertificate(intermediateDER)
	require.NoError(t, err)

	// Generate leaf certificate
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			CommonName:   "client.test.local",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, intermediateCert, &leafKey.PublicKey, intermediateKey)
	require.NoError(t, err)
	leafCert, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return rootCAPEM, intermediateCert, leafCert
}

func TestNewTLSConfig_VerifyConnection_WithIntermediateCertificates(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate server certificate and CA chain
	serverCertPEM, serverKeyPEM := generateTestCertificate(t)
	rootCAPEM, intermediateCert, leafCert := generateCertificateChain(t)

	// Write server certificate and key
	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	require.NoError(t, os.WriteFile(certPath, serverCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, serverKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, rootCAPEM, 0o600))

	config := HTTPSServerConfig{
		TLSCertFilePath: certPath,
		TLSKeyFilePath:  keyPath,
		CAFilePath:      caPath,
	}

	logger := ctrl.Log.WithName("test")
	tlsConfig, _, err := config.NewTLSConfig(logger)
	require.NoError(t, err)
	require.NotNil(t, tlsConfig)
	require.NotNil(t, tlsConfig.VerifyConnection)

	tests := []struct {
		name          string
		peerCerts     []*x509.Certificate
		expectError   bool
		errorContains string
	}{
		{
			name:          "no client certificate",
			peerCerts:     []*x509.Certificate{},
			expectError:   true,
			errorContains: "no client certificate provided",
		},
		{
			name:          "valid certificate chain with intermediate",
			peerCerts:     []*x509.Certificate{leafCert, intermediateCert},
			expectError:   false,
			errorContains: "",
		},
		{
			name:          "leaf certificate only (missing intermediate)",
			peerCerts:     []*x509.Certificate{leafCert},
			expectError:   true,
			errorContains: "certificate verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := tls.ConnectionState{
				PeerCertificates: tt.peerCerts,
			}

			err := tlsConfig.VerifyConnection(cs)
			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewTLSConfig_VerifyConnection_OnlyVerifiesLeafCertificate(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate server certificate
	serverCertPEM, serverKeyPEM := generateTestCertificate(t)
	rootCAPEM, intermediateCert, leafCert := generateCertificateChain(t)

	// Write server certificate and key
	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")

	require.NoError(t, os.WriteFile(certPath, serverCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, serverKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, rootCAPEM, 0o600))

	config := HTTPSServerConfig{
		TLSCertFilePath: certPath,
		TLSKeyFilePath:  keyPath,
		CAFilePath:      caPath,
	}

	logger := ctrl.Log.WithName("test")
	tlsConfig, _, err := config.NewTLSConfig(logger)
	require.NoError(t, err)

	// Test that verification succeeds with correct chain order (leaf first, then intermediate)
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, intermediateCert},
	}

	err = tlsConfig.VerifyConnection(cs)
	require.NoError(t, err, "Should verify successfully with leaf cert first and intermediate second")

	// Test with multiple intermediates - verify they are all added to the intermediates pool
	csMultipleIntermediates := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leafCert, intermediateCert, intermediateCert},
	}

	err = tlsConfig.VerifyConnection(csMultipleIntermediates)
	require.NoError(t, err, "Should handle multiple intermediate certificates correctly")
}

func TestNewTLSConfig_MinVersion(t *testing.T) {
	tmpDir := t.TempDir()
	certPEM, keyPEM := generateTestCertificate(t)
	caPEM, _ := generateTestCertificate(t)

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	tests := []struct {
		name       string
		minVersion string
		wantMin    uint16
		wantErr    bool
	}{
		{
			name:       "default when unset",
			minVersion: "",
			wantMin:    tls.VersionTLS12,
		},
		{
			name:       "TLS 1.3",
			minVersion: "VersionTLS13",
			wantMin:    tls.VersionTLS13,
		},
		{
			name:       "invalid version",
			minVersion: "VersionTLS99",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := HTTPSServerConfig{
				TLSCertFilePath: certPath,
				TLSKeyFilePath:  keyPath,
				CAFilePath:      caPath,
				MinVersion:      tt.minVersion,
			}
			logger := ctrl.Log.WithName("test")
			tlsConfig, _, err := config.NewTLSConfig(logger)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantMin, tlsConfig.MinVersion)
		})
	}
}

func TestNewTLSConfig_CipherSuites(t *testing.T) {
	tmpDir := t.TempDir()
	certPEM, keyPEM := generateTestCertificate(t)
	caPEM, _ := generateTestCertificate(t)

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	tests := []struct {
		name         string
		cipherSuites []string
		wantLen      int
		wantErr      bool
	}{
		{
			name:         "nil when unset",
			cipherSuites: nil,
			wantLen:      0,
		},
		{
			name:         "valid cipher suite",
			cipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			wantLen:      1,
		},
		{
			name:         "invalid cipher suite",
			cipherSuites: []string{"INVALID_CIPHER"},
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := HTTPSServerConfig{
				TLSCertFilePath: certPath,
				TLSKeyFilePath:  keyPath,
				CAFilePath:      caPath,
				CipherSuites:    tt.cipherSuites,
			}
			logger := ctrl.Log.WithName("test")
			tlsConfig, _, err := config.NewTLSConfig(logger)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, tlsConfig.CipherSuites, tt.wantLen)
		})
	}
}

func TestNewTLSConfig_CurvePreferences(t *testing.T) {
	tmpDir := t.TempDir()
	certPEM, keyPEM := generateTestCertificate(t)
	caPEM, _ := generateTestCertificate(t)

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	tests := []struct {
		name             string
		curvePreferences []string
		wantCurves       []tls.CurveID
		wantErr          bool
	}{
		{
			name:             "nil when unset",
			curvePreferences: nil,
			wantCurves:       nil,
		},
		{
			name:             "single curve",
			curvePreferences: []string{"X25519"},
			wantCurves:       []tls.CurveID{tls.X25519},
		},
		{
			name:             "multiple curves",
			curvePreferences: []string{"X25519", "CurveP256", "CurveP384"},
			wantCurves:       []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		},
		{
			name:             "post-quantum hybrid",
			curvePreferences: []string{"X25519MLKEM768"},
			wantCurves:       []tls.CurveID{tls.X25519MLKEM768},
		},
		{
			name:             "invalid curve",
			curvePreferences: []string{"InvalidCurve"},
			wantErr:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := HTTPSServerConfig{
				TLSCertFilePath:  certPath,
				TLSKeyFilePath:   keyPath,
				CAFilePath:       caPath,
				CurvePreferences: tt.curvePreferences,
			}
			logger := ctrl.Log.WithName("test")
			tlsConfig, _, err := config.NewTLSConfig(logger)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantCurves, tlsConfig.CurvePreferences)
		})
	}
}

func TestNewTLSConfig_FlagOverridesConfigFile(t *testing.T) {
	tmpDir := t.TempDir()
	certPEM, keyPEM := generateTestCertificate(t)
	caPEM, _ := generateTestCertificate(t)

	certPath := filepath.Join(tmpDir, "tls.crt")
	keyPath := filepath.Join(tmpDir, "tls.key")
	caPath := filepath.Join(tmpDir, "ca.crt")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	// Config file sets TLS 1.2 and one curve.
	config := HTTPSServerConfig{
		TLSCertFilePath:  certPath,
		TLSKeyFilePath:   keyPath,
		CAFilePath:       caPath,
		MinVersion:       "VersionTLS12",
		CurvePreferences: []string{"CurveP256"},
	}

	// Simulate flag override: change min version and curves.
	config.MinVersion = "VersionTLS13"
	config.CurvePreferences = []string{"X25519", "CurveP384"}

	logger := ctrl.Log.WithName("test")
	tlsConfig, _, err := config.NewTLSConfig(logger)
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
	assert.Equal(t, []tls.CurveID{tls.X25519, tls.CurveP384}, tlsConfig.CurvePreferences)
}

func TestParseCurvePreferences(t *testing.T) {
	tests := []struct {
		name    string
		input   []string
		want    []tls.CurveID
		wantErr bool
	}{
		{name: "nil input", input: nil, want: nil},
		{name: "empty input", input: []string{}, want: nil},
		{name: "CurveP256", input: []string{"CurveP256"}, want: []tls.CurveID{tls.CurveP256}},
		{name: "CurveP384", input: []string{"CurveP384"}, want: []tls.CurveID{tls.CurveP384}},
		{name: "CurveP521", input: []string{"CurveP521"}, want: []tls.CurveID{tls.CurveP521}},
		{name: "X25519", input: []string{"X25519"}, want: []tls.CurveID{tls.X25519}},
		{name: "X25519MLKEM768", input: []string{"X25519MLKEM768"}, want: []tls.CurveID{tls.X25519MLKEM768}},
		{name: "SecP256r1MLKEM768", input: []string{"SecP256r1MLKEM768"}, want: []tls.CurveID{tls.SecP256r1MLKEM768}},
		{name: "SecP384r1MLKEM1024", input: []string{"SecP384r1MLKEM1024"}, want: []tls.CurveID{tls.SecP384r1MLKEM1024}},
		{
			name: "all curves", input: []string{"X25519", "CurveP256", "CurveP384", "CurveP521", "X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"},
			want: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521, tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024},
		},
		{name: "unknown curve", input: []string{"BadCurve"}, wantErr: true},
		{name: "one valid one invalid", input: []string{"X25519", "Bogus"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCurvePreferences(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

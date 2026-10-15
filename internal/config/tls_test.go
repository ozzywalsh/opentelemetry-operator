// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApplyTLSConfig(t *testing.T) {
	tests := []struct {
		name           string
		tlsConfig      TLSConfig
		errWanted      string
		curvesExpected []tls.CurveID
	}{
		{
			name: "default",
			tlsConfig: TLSConfig{
				MinVersion: "VersionTLS12",
			},
			errWanted: "",
		},
		{
			name: "badTLSVersion",
			tlsConfig: TLSConfig{
				MinVersion: "foo",
			},
			errWanted: `TLS version invalid: unknown tls version "foo"`,
		},
		{
			name: "badCipherSuites",
			tlsConfig: TLSConfig{
				MinVersion:   "VersionTLS12",
				CipherSuites: []string{"foo"},
			},
			errWanted: "failed to convert TLS cipher suite name to ID: Cipher suite foo not supported or doesn't exist",
		},
		{
			name: "curves",
			tlsConfig: TLSConfig{
				MinVersion: "VersionTLS12",
				Curves:     []string{"X25519", "CurveP256"},
			},
			curvesExpected: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		{
			name: "curves under TLS 1.3",
			tlsConfig: TLSConfig{
				MinVersion: "VersionTLS13",
				Curves:     []string{"X25519MLKEM768"},
			},
			curvesExpected: []tls.CurveID{tls.X25519MLKEM768},
		},
		{
			name: "badCurves",
			tlsConfig: TLSConfig{
				MinVersion: "VersionTLS12",
				Curves:     []string{"P256"},
			},
			errWanted: "failed to convert TLS curve name to ID: curve P256 not supported or doesn't exist, supported curves are CurveP256, CurveP384, CurveP521, SecP256r1MLKEM768, SecP384r1MLKEM1024, X25519, X25519MLKEM768",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &tls.Config{MinVersion: tls.VersionTLS12}
			err := test.tlsConfig.ApplyTLSConfig(cfg)
			if test.errWanted == "" {
				require.NoError(t, err)
				require.Equal(t, test.curvesExpected, cfg.CurvePreferences)
			} else {
				require.EqualError(t, err, test.errWanted)
			}
		})
	}
}

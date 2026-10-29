// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package targetallocator

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	k8sapiflag "k8s.io/component-base/cli/flag"

	"github.com/open-telemetry/opentelemetry-operator/internal/components"
)

func TestApplyTLSProfile(t *testing.T) {
	tests := []struct {
		name       string
		minVersion uint16
		ciphers    []uint16
		curves     []tls.CurveID
		expected   taTLSSettings
	}{
		{
			name:       "TLS 1.2 carries all three settings",
			minVersion: tls.VersionTLS12,
			ciphers:    []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			curves:     []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.X25519},
			expected: taTLSSettings{
				MinVersion:       "VersionTLS12",
				CipherSuites:     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				CurvePreferences: []int32{23, 24, 29},
			},
		},
		{
			name:       "TLS 1.3 drops cipher suites but keeps curves",
			minVersion: tls.VersionTLS13,
			ciphers:    []uint16{tls.TLS_AES_128_GCM_SHA256},
			curves:     []tls.CurveID{tls.X25519},
			expected: taTLSSettings{
				MinVersion:       "VersionTLS13",
				CipherSuites:     nil,
				CurvePreferences: []int32{29},
			},
		},
		{
			name:       "Unmapped version leaves the minimum version empty",
			minVersion: 0x0300, // SSL 3.0 or any non-standard constant
			curves:     []tls.CurveID{tls.CurveP256},
			expected: taTLSSettings{
				MinVersion:       "",
				CipherSuites:     []string{},
				CurvePreferences: []int32{23},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := components.NewStaticTLSProfile(tt.minVersion, tt.ciphers, tt.curves)

			var settings taTLSSettings
			settings.ApplyTLSProfile(profile)
			assert.Equal(t, tt.expected, settings)

			// The Target Allocator must be able to parse what we emit.
			version, err := k8sapiflag.TLSVersion(settings.MinVersion)
			assert.NoError(t, err)
			if settings.MinVersion != "" {
				assert.Equal(t, tt.minVersion, version)
			}
			_, err = k8sapiflag.TLSCipherSuites(settings.CipherSuites)
			assert.NoError(t, err)
			_, err = k8sapiflag.TLSCurvePreferences(settings.CurvePreferences)
			assert.NoError(t, err)
		})
	}
}

func TestApplyTLSProfileNilProfile(t *testing.T) {
	var settings taTLSSettings
	settings.ApplyTLSProfile(nil)
	assert.Equal(t, taTLSSettings{}, settings)
}

func TestTLSSettingsAddTo(t *testing.T) {
	t.Run("adds every setting that has a value", func(t *testing.T) {
		settings := taTLSSettings{
			MinVersion:       "VersionTLS12",
			CipherSuites:     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			CurvePreferences: []int32{23},
		}

		httpsConfig := map[string]any{"enabled": true}
		settings.addTo(httpsConfig)

		assert.Equal(t, map[string]any{
			"enabled":           true,
			"min_version":       "VersionTLS12",
			"cipher_suites":     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
			"curve_preferences": []int32{23},
		}, httpsConfig)
	})

	t.Run("adds nothing when no setting has a value", func(t *testing.T) {
		httpsConfig := map[string]any{"enabled": true}
		taTLSSettings{}.addTo(httpsConfig)

		assert.Equal(t, map[string]any{"enabled": true}, httpsConfig)
	})
}

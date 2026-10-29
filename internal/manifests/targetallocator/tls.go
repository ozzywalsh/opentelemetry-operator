// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package targetallocator

import (
	"crypto/tls"

	"github.com/open-telemetry/opentelemetry-operator/internal/components"
)

// taTLSSettings holds the TLS settings of the Target Allocator's https block.
// The Target Allocator is not a collector, so the settings use the Go
// vocabulary component-base parses rather than the collector's.
type taTLSSettings struct {
	MinVersion       string
	CipherSuites     []string
	CurvePreferences []int32
}

// golangTLSVersionNames maps a TLS version constant to the name the Target
// Allocator accepts for https.min_version. It parses that field with
// k8sapiflag.TLSVersion, which takes these names rather than the display
// strings tls.VersionName returns, such as "TLS 1.2".
var golangTLSVersionNames = map[uint16]string{
	tls.VersionTLS10: "VersionTLS10",
	tls.VersionTLS11: "VersionTLS11",
	tls.VersionTLS12: "VersionTLS12",
	tls.VersionTLS13: "VersionTLS13",
}

// ApplyTLSProfile sets MinVersion, CipherSuites and CurvePreferences from the
// given TLS profile. The groups are carried as numeric IANA IDs, because
// component-base offers only TLSCurvePreferences([]int32) and has no name
// parser for them; CurveID.String() is a display helper. A version missing
// from golangTLSVersionNames leaves MinVersion empty, which
// k8sapiflag.TLSVersion resolves to its own default.
func (t *taTLSSettings) ApplyTLSProfile(profile components.TLSProfile) {
	if t == nil || profile == nil {
		return
	}
	t.MinVersion = golangTLSVersionNames[profile.MinTLSVersion()]
	t.CipherSuites = profile.CipherSuiteNames()
	if curves := profile.CurveIDs(); len(curves) > 0 {
		ids := make([]int32, 0, len(curves))
		for _, c := range curves {
			ids = append(ids, int32(c))
		}
		t.CurvePreferences = ids
	}
}

// addTo sets the settings that have a value on the https configuration.
func (t taTLSSettings) addTo(httpsConfig map[string]any) {
	if t.MinVersion != "" {
		httpsConfig["min_version"] = t.MinVersion
	}
	if len(t.CipherSuites) > 0 {
		httpsConfig["cipher_suites"] = t.CipherSuites
	}
	if len(t.CurvePreferences) > 0 {
		httpsConfig["curve_preferences"] = t.CurvePreferences
	}
}

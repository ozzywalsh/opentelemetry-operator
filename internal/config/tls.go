// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/tls"
	"fmt"
	"maps"
	"slices"
	"strings"

	k8sapiflag "k8s.io/component-base/cli/flag"
)

type TLSConfig struct {
	// Instructs the operator to get the TLS profile from the cluster.
	UseClusterProfile bool
	// Configures TLS in operands created by the operator.
	ConfigureOperands bool
	MinVersion        string
	CipherSuites      []string
	Curves            []string
}

// curveIDs maps Go crypto/tls curve constant names to their tls.CurveID, so
// that --tls-curve-preferences uses the same vocabulary as --tls-min-version
// and --tls-cipher-suites.
var curveIDs = map[string]tls.CurveID{
	"X25519":             tls.X25519,
	"CurveP256":          tls.CurveP256,
	"CurveP384":          tls.CurveP384,
	"CurveP521":          tls.CurveP521,
	"X25519MLKEM768":     tls.X25519MLKEM768,
	"SecP256r1MLKEM768":  tls.SecP256r1MLKEM768,
	"SecP384r1MLKEM1024": tls.SecP384r1MLKEM1024,
}

// TLSCurvePreferences returns the curve IDs for the given Go crypto/tls curve
// constant names.
func TLSCurvePreferences(names []string) ([]tls.CurveID, error) {
	if len(names) == 0 {
		return nil, nil
	}
	curves := make([]tls.CurveID, 0, len(names))
	for _, name := range names {
		id, ok := curveIDs[name]
		if !ok {
			return nil, fmt.Errorf("curve %s not supported or doesn't exist, supported curves are %s", name, strings.Join(slices.Sorted(maps.Keys(curveIDs)), ", "))
		}
		curves = append(curves, id)
	}
	return curves, nil
}

// ApplyTLSConfig get the option from command argument (tlsConfig), check the validity through k8s apiflag
// and set the config for webhook server.
// refer to https://pkg.go.dev/k8s.io/component-base/cli/flag
func (tlsOpt TLSConfig) ApplyTLSConfig(cfg *tls.Config) error {
	// TLSVersion helper function returns the TLS Version ID for the version name passed.
	tlsVersion, err := k8sapiflag.TLSVersion(tlsOpt.MinVersion)
	if err != nil {
		return fmt.Errorf("TLS version invalid: %w", err)
	}

	// TLSCipherSuites helper function returns a list of cipher suite IDs from the cipher suite names passed.
	cipherSuiteIDs, err := k8sapiflag.TLSCipherSuites(tlsOpt.CipherSuites)
	if err != nil {
		return fmt.Errorf("failed to convert TLS cipher suite name to ID: %w", err)
	}
	curvePreferences, err := TLSCurvePreferences(tlsOpt.Curves)
	if err != nil {
		return fmt.Errorf("failed to convert TLS curve name to ID: %w", err)
	}

	cfg.MinVersion = tlsVersion
	cfg.CipherSuites = cipherSuiteIDs
	cfg.CurvePreferences = curvePreferences
	return nil
}

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"crypto/tls"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/open-telemetry/opentelemetry-operator/internal/config"
)

func TestTLSOptionFuncsClusterProfileWins(t *testing.T) {
	manual := config.TLSConfig{
		MinVersion:   "VersionTLS12",
		CipherSuites: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		Curves:       []string{"CurveP521"},
	}
	clusterProfile := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS13,
		Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
		Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
	}

	tests := []struct {
		name              string
		useClusterProfile bool
		expectedVersion   uint16
		expectedCurves    []tls.CurveID
	}{
		{
			name:              "manual settings only",
			useClusterProfile: false,
			expectedVersion:   tls.VersionTLS12,
			expectedCurves:    []tls.CurveID{tls.CurveP521},
		},
		{
			name:              "cluster profile overrides manual settings",
			useClusterProfile: true,
			expectedVersion:   tls.VersionTLS13,
			expectedCurves:    []tls.CurveID{tls.X25519, tls.CurveP256},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsCfg := manual
			tlsCfg.UseClusterProfile = tt.useClusterProfile

			cfg := &tls.Config{}
			for _, f := range tlsOptionFuncs(tlsCfg, clusterProfile) {
				f(cfg)
			}

			assert.Equal(t, tt.expectedVersion, cfg.MinVersion)
			assert.Equal(t, tt.expectedCurves, cfg.CurvePreferences)
		})
	}
}

// TestSecurityProfileWatcherGroupsOnlyChange confirms that a change limited to
// the profile's groups triggers the graceful restart, like any other field.
func TestSecurityProfileWatcherGroupsOnlyChange(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	require.NoError(t, configv1.AddToScheme(scheme))

	initial := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
		Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519},
	}
	changed := initial
	changed.Groups = []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1}

	apiServer := &configv1.APIServer{}
	apiServer.Name = openshifttls.APIServerName
	apiServer.Spec.TLSSecurityProfile = &configv1.TLSSecurityProfile{
		Type:   configv1.TLSProfileCustomType,
		Custom: &configv1.CustomTLSProfile{TLSProfileSpec: changed},
	}

	var observed *configv1.TLSProfileSpec
	watcher := &openshifttls.SecurityProfileWatcher{
		Client:                fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiServer).Build(),
		InitialTLSProfileSpec: initial,
		OnProfileChange: func(_ context.Context, _, newSpec configv1.TLSProfileSpec) {
			observed = &newSpec
		},
	}

	_, err := watcher.Reconcile(t.Context(), reconcile.Request{
		NamespacedName: types.NamespacedName{Name: openshifttls.APIServerName},
	})
	require.NoError(t, err)
	require.NotNil(t, observed, "a groups-only change must trigger the restart callback")
	assert.Equal(t, changed.Groups, observed.Groups)
}

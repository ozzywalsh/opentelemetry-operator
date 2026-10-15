// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	openshifttls "github.com/openshift/controller-runtime-common/pkg/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	reconcile "sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// A profile change that only touches groups must still trigger the graceful
// restart, so that injected curve_preferences follow the cluster profile.
// The watcher's change detection is upstream; this test pins the behavior
// the operator depends on. See TRACING-6893.
func TestTLSProfileWatcherGroupsOnlyChangeTriggersRestart(t *testing.T) {
	scheme := k8sruntime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, configv1.AddToScheme(scheme))

	initial := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
	}
	changed := configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers:       []string{"ECDHE-RSA-AES128-GCM-SHA256"},
		Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
	}

	apiserver := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type:   configv1.TLSProfileCustomType,
				Custom: &configv1.CustomTLSProfile{TLSProfileSpec: changed},
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiserver).Build()

	var changes int
	watcher := &openshifttls.SecurityProfileWatcher{
		Client:                cl,
		InitialTLSProfileSpec: initial,
		OnProfileChange:       func(context.Context, configv1.TLSProfileSpec, configv1.TLSProfileSpec) { changes++ },
	}

	req := reconcile.Request{NamespacedName: client.ObjectKey{Name: "cluster"}}
	_, err := watcher.Reconcile(t.Context(), req)
	require.NoError(t, err)
	assert.Equal(t, 1, changes, "groups-only profile change should trigger the graceful restart")
}

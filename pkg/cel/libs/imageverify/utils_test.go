/*
Copyright The Kyverno Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package imageverify

import (
	"context"
	"testing"

	"github.com/kyverno/api/api/policies.kyverno.io/v1alpha1"
	"github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetRemoteOptsFromPolicy_NilCredentials(t *testing.T) {
	lister := newFakeSecretLister()
	opts, err := GetRemoteOptsFromPolicy(context.Background(), lister, nil)
	assert.NoError(t, err)
	assert.NotNil(t, opts)
	assert.Empty(t, opts)
}

func TestGetRemoteOptsFromPolicy_PullSecretsOnly(t *testing.T) {
	lister := newFakeSecretLister()
	creds := &v1beta1.Credentials{
		Secrets: []string{"my-pull-secret"},
	}
	opts, err := GetRemoteOptsFromPolicy(context.Background(), lister, creds)
	assert.NoError(t, err)
	// Should have one option (pull secret) and no error.
	assert.NotNil(t, opts)
}

func TestGetRemoteOptsFromPolicy_InsecureRegistry(t *testing.T) {
	lister := newFakeSecretLister()
	creds := &v1beta1.Credentials{
		AllowInsecureRegistry: true,
	}
	opts, err := GetRemoteOptsFromPolicy(context.Background(), lister, creds)
	assert.NoError(t, err)
	assert.NotEmpty(t, opts)
}

func TestGetRemoteOptsFromPolicy_WithValidMTLS(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "mtls-certs"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}
	lister := newFakeSecretLister(secret)

	creds := &v1beta1.Credentials{
		TLSClientCert: &v1alpha1.TLSClientConfig{
			Secret: "mtls-certs",
		},
	}
	opts, err := GetRemoteOptsFromPolicy(context.Background(), lister, creds)
	require.NoError(t, err)
	// opts should include base BuildRemoteOpts result (empty here)
	// plus the WithMTLSTransport option.
	assert.NotNil(t, opts)
	// We expect at least one option: the mTLS transport wrapper.
	assert.NotEmpty(t, opts)
}

func TestGetRemoteOptsFromPolicy_WithMTLSSecretNotFound(t *testing.T) {
	lister := newFakeSecretLister() // empty — no secrets
	creds := &v1beta1.Credentials{
		TLSClientCert: &v1alpha1.TLSClientConfig{
			Secret: "missing-secret",
		},
	}
	opts, err := GetRemoteOptsFromPolicy(context.Background(), lister, creds)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mTLS setup failed")
	assert.Nil(t, opts)
}

func TestGetRemoteOptsFromPolicy_WithMTLSWrongSecretType(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "opaque-secret"},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls.crt": []byte("cert"),
			"tls.key": []byte("key"),
		},
	}
	lister := newFakeSecretLister(secret)
	creds := &v1beta1.Credentials{
		TLSClientCert: &v1alpha1.TLSClientConfig{
			Secret: "opaque-secret",
		},
	}
	opts, err := GetRemoteOptsFromPolicy(context.Background(), lister, creds)
	assert.Error(t, err)
	assert.Nil(t, opts)
}

func TestGetRemoteOptsFromPolicy_WithAllCredentials(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "full-mtls"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}
	lister := newFakeSecretLister(secret)

	creds := &v1beta1.Credentials{
		AllowInsecureRegistry: false,
		Providers:             []v1beta1.CredentialsProvidersType{"google"},
		Secrets:               []string{"pull-secret"},
		TLSClientCert: &v1alpha1.TLSClientConfig{
			Secret: "full-mtls",
		},
	}
	opts, err := GetRemoteOptsFromPolicy(context.Background(), lister, creds)
	require.NoError(t, err)
	assert.NotEmpty(t, opts)
}

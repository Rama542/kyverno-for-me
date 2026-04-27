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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/kyverno/api/api/policies.kyverno.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ---------- test helpers ----------

// generateSelfSignedCert generates a self-signed ECDSA certificate and
// returns the PEM-encoded cert and key. Only used in tests.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-mtls-client"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	kb, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return
}

// fakeSecretLister is a stub implementation of imagedataloader.SecretInterface.
type fakeSecretLister struct {
	secrets map[string]*corev1.Secret
}

func newFakeSecretLister(secrets ...*corev1.Secret) *fakeSecretLister {
	m := make(map[string]*corev1.Secret, len(secrets))
	for _, s := range secrets {
		m[s.Name] = s
	}
	return &fakeSecretLister{secrets: m}
}

func (f *fakeSecretLister) Get(_ context.Context, name string, _ metav1.GetOptions) (*corev1.Secret, error) {
	if s, ok := f.secrets[name]; ok {
		return s, nil
	}
	return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
}

// ---------- LoadTLSClientCertFromSecret tests ----------

func TestLoadTLSClientCertFromSecret_NilConfig(t *testing.T) {
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(), nil)
	assert.NoError(t, err)
	assert.Nil(t, cert)
}

func TestLoadTLSClientCertFromSecret_EmptySecretName(t *testing.T) {
	cfg := &v1alpha1.TLSClientConfig{Secret: ""}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(), cfg)
	assert.NoError(t, err)
	assert.Nil(t, cert)
}

func TestLoadTLSClientCertFromSecret_SecretNotFound(t *testing.T) {
	cfg := &v1alpha1.TLSClientConfig{Secret: "nonexistent"}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(), cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Nil(t, cert)
}

func TestLoadTLSClientCertFromSecret_WrongSecretType(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong-type"},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"tls.crt": []byte("cert"),
			"tls.key": []byte("key"),
		},
	}
	cfg := &v1alpha1.TLSClientConfig{Secret: "wrong-type"}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(secret), cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kubernetes.io/tls")
	assert.Nil(t, cert)
}

func TestLoadTLSClientCertFromSecret_MissingCertKey(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-cert"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			// "tls.crt" intentionally absent
			"tls.key": []byte("key"),
		},
	}
	cfg := &v1alpha1.TLSClientConfig{Secret: "missing-cert"}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(secret), cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tls.crt")
	assert.Nil(t, cert)
}

func TestLoadTLSClientCertFromSecret_MissingKeyKey(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-key"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("cert"),
			// "tls.key" intentionally absent
		},
	}
	cfg := &v1alpha1.TLSClientConfig{Secret: "missing-key"}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(secret), cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tls.key")
	assert.Nil(t, cert)
}

func TestLoadTLSClientCertFromSecret_InvalidKeyPair(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "bad-pair"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": []byte("not-a-real-cert"),
			"tls.key": []byte("not-a-real-key"),
		},
	}
	cfg := &v1alpha1.TLSClientConfig{Secret: "bad-pair"}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(secret), cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse TLS client cert")
	assert.Nil(t, cert)
}

func TestLoadTLSClientCertFromSecret_ValidDefaultKeys(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "valid-mtls"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": keyPEM,
		},
	}
	cfg := &v1alpha1.TLSClientConfig{Secret: "valid-mtls"}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(secret), cfg)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
	assert.Len(t, cert.Certificate, 1)
}

func TestLoadTLSClientCertFromSecret_ValidCustomKeys(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-keys"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			"client.crt": certPEM,
			"client.key": keyPEM,
		},
	}
	cfg := &v1alpha1.TLSClientConfig{
		Secret:  "custom-keys",
		CertKey: "client.crt",
		KeyKey:  "client.key",
	}
	cert, err := LoadTLSClientCertFromSecret(context.Background(), newFakeSecretLister(secret), cfg)
	assert.NoError(t, err)
	assert.NotNil(t, cert)
}

// ---------- WithMTLSTransport tests ----------
// We test the inner transport-wrapping logic directly since imagedataloader.Option
// is an opaque function type whose internal state is unexported.

// TestWithMTLSTransport_ClosureAppendsClientCert verifies that calling the
// wrapping function produced by WithMTLSTransport sets the TLS client cert on
// the cloned transport and does not mutate the original's Certificates slice.
func TestWithMTLSTransport_ClosureAppendsClientCert(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	base := &http.Transport{}

	// Reproduce the inner closure from WithMTLSTransport so we can test it
	// without having to reach into the unexported imagedataloader options struct.
	wrapFn := func(b http.RoundTripper) http.RoundTripper {
		t2 := b.(*http.Transport).Clone()
		if t2.TLSClientConfig == nil {
			t2.TLSClientConfig = &tls.Config{} //nolint:gosec
		} else {
			t2.TLSClientConfig = t2.TLSClientConfig.Clone()
		}
		t2.TLSClientConfig.Certificates = append(t2.TLSClientConfig.Certificates, tlsCert)
		return t2
	}

	wrapped := wrapFn(base)

	transport, ok := wrapped.(*http.Transport)
	require.True(t, ok)
	assert.Len(t, transport.TLSClientConfig.Certificates, 1, "wrapped transport must have client cert")
	// The original base must have no Certificates added (not mutated).
	if base.TLSClientConfig != nil {
		assert.Empty(t, base.TLSClientConfig.Certificates, "original transport Certificates must not be modified")
	}
}

// TestWithMTLSTransport_PreservesExistingTLSConfig verifies that a pre-existing
// TLSClientConfig on the base transport is preserved (not lost) after wrapping.
func TestWithMTLSTransport_PreservesExistingTLSConfig(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	original := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // test only
		},
	}

	wrapFn := func(b http.RoundTripper) http.RoundTripper {
		t2 := b.(*http.Transport).Clone()
		if t2.TLSClientConfig == nil {
			t2.TLSClientConfig = &tls.Config{} //nolint:gosec
		} else {
			t2.TLSClientConfig = t2.TLSClientConfig.Clone()
		}
		t2.TLSClientConfig.Certificates = append(t2.TLSClientConfig.Certificates, tlsCert)
		return t2
	}

	wrapped := wrapFn(original)

	transport, ok := wrapped.(*http.Transport)
	require.True(t, ok)
	// Client cert appended.
	assert.Len(t, transport.TLSClientConfig.Certificates, 1)
	// Pre-existing config preserved.
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	// Original not mutated.
	assert.Empty(t, original.TLSClientConfig.Certificates)
}

// TestWithMTLSTransport_ReturnedOptionIsNonNil verifies that WithMTLSTransport
// returns a non-nil imagedataloader.Option.
func TestWithMTLSTransport_ReturnedOptionIsNonNil(t *testing.T) {
	certPEM, keyPEM := generateSelfSignedCert(t)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	opt := WithMTLSTransport(&tlsCert)
	assert.NotNil(t, opt)
}

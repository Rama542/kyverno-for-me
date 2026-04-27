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
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/kyverno/api/api/policies.kyverno.io/v1alpha1"
	"github.com/kyverno/sdk/extensions/imagedataloader"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// defaultCertKey is the default key within a kubernetes.io/tls Secret
	// that holds the PEM-encoded client certificate.
	defaultCertKey = "tls.crt"
	// defaultKeyKey is the default key within a kubernetes.io/tls Secret
	// that holds the PEM-encoded client private key.
	defaultKeyKey = "tls.key"
)

// LoadTLSClientCertFromSecret loads an mTLS client certificate and its private key
// from a kubernetes.io/tls Secret in the Kyverno namespace. It returns nil (no error)
// when cfg is nil so callers can use it unconditionally.
//
// The Secret MUST be of type kubernetes.io/tls. The certificate and key PEM data
// are read from the keys specified in cfg (defaulting to "tls.crt" and "tls.key").
func LoadTLSClientCertFromSecret(
	ctx context.Context,
	lister imagedataloader.SecretInterface,
	cfg *v1alpha1.TLSClientConfig,
) (*tls.Certificate, error) {
	if cfg == nil || cfg.Secret == "" {
		return nil, nil
	}

	secret, err := lister.Get(ctx, cfg.Secret, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get mTLS secret %q: %w", cfg.Secret, err)
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, fmt.Errorf(
			"mTLS secret %q must be of type %q, got %q",
			cfg.Secret, corev1.SecretTypeTLS, secret.Type,
		)
	}

	certKey := cfg.CertKey
	if certKey == "" {
		certKey = defaultCertKey
	}
	keyKey := cfg.KeyKey
	if keyKey == "" {
		keyKey = defaultKeyKey
	}

	certPEM, ok := secret.Data[certKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found in mTLS secret %q", certKey, cfg.Secret)
	}
	keyPEM, ok := secret.Data[keyKey]
	if !ok {
		return nil, fmt.Errorf("key %q not found in mTLS secret %q", keyKey, cfg.Secret)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TLS client cert from secret %q: %w", cfg.Secret, err)
	}
	return &cert, nil
}

// WithMTLSTransport returns an imagedataloader.Option that wraps the base HTTP
// transport to present the supplied TLS client certificate during registry
// connections. This enables mTLS (mutual TLS) authentication with registries
// that mandate client certificates.
//
// The base transport is cloned so the original DefaultTransport is never mutated.
func WithMTLSTransport(cert *tls.Certificate) imagedataloader.Option {
	return imagedataloader.WithTransport(func(base http.RoundTripper) http.RoundTripper {
		// Clone the base transport so we don't mutate the shared DefaultTransport.
		var t *http.Transport
		if baseT, ok := base.(*http.Transport); ok {
			t = baseT.Clone()
		} else {
			// Fallback: clone the SDK default transport.
			t = imagedataloader.DefaultTransport.Clone()
		}

		if t.TLSClientConfig == nil {
			t.TLSClientConfig = &tls.Config{} //nolint:gosec // no minimum TLS version needed for registry compat
		} else {
			// Clone the TLS config to avoid mutating a shared pointer.
			tlsCfg := t.TLSClientConfig.Clone()
			t.TLSClientConfig = tlsCfg
		}

		t.TLSClientConfig.Certificates = append(t.TLSClientConfig.Certificates, *cert)
		return t
	})
}

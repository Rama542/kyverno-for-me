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
	"fmt"

	"github.com/kyverno/api/api/policies.kyverno.io/v1beta1"
	"github.com/kyverno/sdk/extensions/imagedataloader"
)

func attestationMap(ivpol v1beta1.ImageValidatingPolicyLike) map[string]v1beta1.Attestation {
	if ivpol == nil {
		return nil
	}
	spec := ivpol.GetSpec()
	return arrToMap(spec.Attestations)
}

type ARR_TYPE interface {
	GetKey() string
}

func arrToMap[T ARR_TYPE](arr []T) map[string]T {
	m := make(map[string]T)
	for _, v := range arr {
		m[v.GetKey()] = v
	}

	return m
}

// GetRemoteOptsFromPolicy builds the list of imagedataloader.Option values
// derived from a policy's Credentials field.
//
// It handles:
//   - Cloud provider credential helpers (Google, Amazon, Azure, GitHub)
//   - Kubernetes pull-secret references (dockerconfigjson)
//   - Insecure registry access
//   - mTLS client certificates via a kubernetes.io/tls Secret (NEW)
//
// If credentials are nil the function returns an empty, non-nil slice.
// If loading the mTLS secret fails the error is propagated to the caller.
func GetRemoteOptsFromPolicy(
	ctx context.Context,
	lister imagedataloader.SecretInterface,
	creds *v1beta1.Credentials,
) ([]imagedataloader.Option, error) {
	if creds == nil {
		return []imagedataloader.Option{}, nil
	}

	providers := make([]string, 0, len(creds.Providers))
	if len(creds.Providers) != 0 {
		for _, v := range creds.Providers {
			providers = append(providers, string(v))
		}
	}

	opts := imagedataloader.BuildRemoteOpts(creds.Secrets, providers, creds.AllowInsecureRegistry)

	// mTLS: load client certificate from a kubernetes.io/tls Secret when specified.
	if creds.TLSClientCert != nil {
		cert, err := LoadTLSClientCertFromSecret(ctx, lister, creds.TLSClientCert)
		if err != nil {
			return nil, fmt.Errorf("registry mTLS setup failed: %w", err)
		}
		if cert != nil {
			opts = append(opts, WithMTLSTransport(cert))
		}
	}

	return opts, nil
}

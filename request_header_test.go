// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package twoway

import (
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/require"
)

func TestHeader(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		want := RequestHeader{
			KeyID:  255,
			KemID:  hpke.KEM_P384_HKDF_SHA384,
			KDFID:  hpke.KDF_HKDF_SHA384,
			AEADID: hpke.AEAD_AES256GCM,
		}

		wantEnc := []byte{
			255,
			0, 17,
			0, 2,
			0, 2,
		}

		got, err := ParseRequestHeaderFrom(wantEnc)
		require.NoError(t, err)
		require.Equal(t, want, got)

		gotEnc, err := got.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, wantEnc, gotEnc)
	})

	failTests := map[string][]byte{
		"fail, nil":   nil,
		"fail, empty": {},
		"fail, too short": {
			255,
			0, 17,
			0, 2,
			0,
		},
		"fail, invalid KEM": {
			255,
			0, 0,
			0, 2,
			0, 2,
		},
		"fail, invalid KDF": {
			255,
			0, 17,
			0, 0,
			0, 2,
		},
		"fail, invalid AEAD": {
			255,
			0, 17,
			0, 2,
			0, 0,
		},
	}
	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			_, err := ParseRequestHeaderFrom(tc)
			require.Error(t, err)
		})
	}
}

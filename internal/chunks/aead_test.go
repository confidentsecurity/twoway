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

package chunks

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/openpcc/twoway/internal/test"
	"github.com/stretchr/testify/require"
)

func TestAEADContext(t *testing.T) {
	const key = "00000000000000000000000000000000"
	const nonce = "000000000000"

	t.Run("ok, seal and open chunks", func(t *testing.T) {
		block, err := aes.NewCipher([]byte(key))
		require.NoError(t, err)
		gcm, err := cipher.NewGCM(block)
		require.NoError(t, err)

		sealer, err := NewAEADContext(gcm, []byte(nonce))
		require.NoError(t, err)
		opener, err := NewAEADContext(gcm, []byte(nonce))
		require.NoError(t, err)

		for i := range 100 {
			pt := strconv.Itoa(i)

			ct, err := sealer.Seal(nil, []byte(pt), []byte("test"))
			require.NoError(t, err)

			gotPT, err := opener.Open(nil, ct, []byte("test"))
			require.NoError(t, err)

			require.Equal(t, []byte(pt), gotPT)
		}
	})

	t.Run("ok, seal and open chunks in place", func(t *testing.T) {
		block, err := aes.NewCipher([]byte(key))
		require.NoError(t, err)
		gcm, err := cipher.NewGCM(block)
		require.NoError(t, err)

		sealer, err := NewAEADContext(gcm, []byte(nonce))
		require.NoError(t, err)
		opener, err := NewAEADContext(gcm, []byte(nonce))
		require.NoError(t, err)
		for range 100 {
			var err error
			pt := make([]byte, 16+1)
			pt[0] = 'a'

			pt, err = sealer.Seal(pt[:0], pt, []byte("test"))
			require.NoError(t, err)

			require.False(t, pt[0] == 'a')

			pt, err = opener.Open(pt[:0], pt, []byte("test"))
			require.NoError(t, err)

			require.True(t, pt[0] == 'a')
		}
	})

	t.Run("fail, sealer overflows", func(t *testing.T) {
		block, err := aes.NewCipher([]byte(key))
		require.NoError(t, err)
		gcm, err := cipher.NewGCM(block)
		require.NoError(t, err)

		sealer, err := NewAEADContext(gcm, []byte(nonce))
		require.NoError(t, err)

		// fast forward to end of chunk stream.
		for i := range sealer.nonce {
			sealer.counter[i] = math.MaxUint8
		}

		_, err = sealer.Seal(nil, []byte("a"), nil)
		require.ErrorIs(t, err, ErrNonceReuse)
	})

	t.Run("fail, opener overflow cannot happen", func(t *testing.T) {
		// An overflow of the opener counter could only happen if a sealer
		// uses a longer nonce.
		// However this would also mean the sealer uses a different nonce.
		// So opening would fail using the normal way instead. This test verifies
		// that the opening happens before this potential nonce check.

		block, err := aes.NewCipher([]byte(key))
		require.NoError(t, err)

		sealerGcm, err := cipher.NewGCMWithNonceSize(block, 13)
		require.NoError(t, err)

		openerGcm, err := cipher.NewGCM(block) // nonce length of 12
		require.NoError(t, err)

		sealerNonce := append([]byte(nonce), 0)
		sealer, err := NewAEADContext(sealerGcm, sealerNonce)
		require.NoError(t, err)

		opener, err := NewAEADContext(openerGcm, []byte(nonce))
		require.NoError(t, err)

		// seal the chunk that will cause an overflow in opener.
		for i := range sealer.nonce {
			sealer.counter[i] = math.MaxUint8
		}
		sealer.counter[0] = 0
		ct, err := sealer.Seal(nil, []byte("a"), nil)
		require.NoError(t, err)

		// open this chunk and verify it causes an overflow.
		_, err = opener.Open(nil, ct, nil)
		require.Error(t, err)
		// verify this is not a nonce reuse error.
		require.False(t, errors.Is(err, ErrNonceReuse))
	})
}

func TestHPKEContext(t *testing.T) {
	t.Run("ok, seal and open chunks", func(t *testing.T) {
		hpkeSender, hpkeReceiver := test.SetupHPKESenderReceiver(t)
		_, _, aeadID := hpkeSender.Params()

		encapKey, hpkeSealer, err := hpkeSender.Setup(rand.Reader)
		require.NoError(t, err)

		hpkeOpener, err := hpkeReceiver.Setup(encapKey)
		require.NoError(t, err)

		sealer := NewHPKESealerContext(hpkeSealer, aeadID)
		opener := NewHPKEOpenerContext(hpkeOpener, aeadID)

		for i := range 100 {
			pt := strconv.Itoa(i)

			ct, err := sealer.Seal(nil, []byte(pt), []byte("test"))
			require.NoError(t, err)

			gotPT, err := opener.Open(nil, ct, []byte("test"))
			require.NoError(t, err)

			require.Equal(t, []byte(pt), gotPT)
		}
	})

	t.Run("ok, seal and open chunks in place", func(t *testing.T) {
		hpkeSender, hpkeReceiver := test.SetupHPKESenderReceiver(t)
		_, _, aeadID := hpkeSender.Params()

		encapKey, hpkeSealer, err := hpkeSender.Setup(rand.Reader)
		require.NoError(t, err)

		hpkeOpener, err := hpkeReceiver.Setup(encapKey)
		require.NoError(t, err)

		sealer := NewHPKESealerContext(hpkeSealer, aeadID)
		opener := NewHPKEOpenerContext(hpkeOpener, aeadID)

		for range 100 {
			var err error
			pt := make([]byte, 16+1)
			pt[0] = 'a'
			pt, err = sealer.Seal(pt[:0], pt, []byte("test"))
			require.NoError(t, err)

			pt, err = opener.Open(pt[:0], pt, []byte("test"))
			require.NoError(t, err)
			require.True(t, pt[0] == 'a')
		}
	})
}

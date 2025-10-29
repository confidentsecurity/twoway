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

package twoway_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"testing/iotest"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/twoway"
	"github.com/confidentsecurity/twoway/internal/test"
	"github.com/stretchr/testify/require"
)

func TestMultiSenderReceiver(t *testing.T) {
	const requestNonceLen = 12
	const responseNonceLen = 16
	const keyID = 0
	const reqMediaType = "request"
	const resMediaType = "response"

	for name, tc := range test.SendReceiveTests() {
		t.Run(name+", unchunked", func(t *testing.T) {
			suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
			kdfID, _, _ := suite.Params()

			sender := twoway.NewMultiRequestSender(suite, rand.Reader)

			// encrypt request
			reqCTBuf := &bytes.Buffer{}
			reqSealer, err := sender.NewRequestSealer(bytes.NewReader(tc.Plaintext), []byte(reqMediaType))
			require.NoError(t, err)

			// verify only fixed length is returned.
			_, ok := reqSealer.Len()
			require.True(t, ok)
			_, ok = reqSealer.MaxCiphertextChunkLen()
			require.False(t, ok)

			_, err = io.Copy(reqCTBuf, reqSealer)
			require.NoError(t, err)

			// this sealer includes a header in its output.
			require.Equal(t, tc.UnchunkedLen+requestNonceLen, reqCTBuf.Len())

			// encapsulate a key, decrypt the request and do a response cycle for each receiver.
			for range 3 {
				pubKey, privKey, err := kdfID.Scheme().GenerateKeyPair()
				require.NoError(t, err)

				reqCT := bytes.NewReader(reqCTBuf.Bytes())

				encapKey, newRespOpener, err := reqSealer.EncapsulateKey(keyID, pubKey)
				require.NoError(t, err)

				// now pretend we're on the receiving end.
				receiver, err := twoway.NewMultiRequestReceiver(suite, keyID, privKey, rand.Reader)
				require.NoError(t, err)

				// decrypt request
				reqOpener, err := receiver.NewRequestOpener(encapKey, reqCT, []byte(reqMediaType))
				require.NoError(t, err)

				// verify plaintext can be read from the reader.
				err = iotest.TestReader(reqOpener, tc.Plaintext)
				require.NoError(t, err)

				// encrypt the same plaintext as a response.
				respCTBuf := &bytes.Buffer{}
				respSealer, err := reqOpener.NewResponseSealer(bytes.NewReader(tc.Plaintext), []byte(resMediaType))
				require.NoError(t, err)

				// verify only fixed length is returned.
				_, ok := respSealer.Len()
				require.True(t, ok)
				_, ok = respSealer.MaxCiphertextChunkLen()
				require.False(t, ok)

				_, err = io.Copy(respCTBuf, respSealer)
				require.NoError(t, err)

				// this sealer includes a header in its output.
				require.Equal(t, tc.UnchunkedLen+responseNonceLen, respCTBuf.Len())

				// okay, back to the sender end, decrypt the response from this receiver.
				respOpener, err := newRespOpener(respCTBuf, []byte(resMediaType))
				require.NoError(t, err)

				// verify plaintext can be read from the reader.
				err = iotest.TestReader(respOpener, tc.Plaintext)
				require.NoError(t, err)
			}
		})

		t.Run(name+", chunked", func(t *testing.T) {
			suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
			kdfID, _, _ := suite.Params()

			sender := twoway.NewMultiRequestSender(suite, rand.Reader)

			// encrypt request
			reqCTBuf := &bytes.Buffer{}
			reqSealer, err := sender.NewRequestSealer(
				bytes.NewReader(tc.Plaintext),
				[]byte(reqMediaType),
				twoway.EnableChunking(),
				twoway.WithInitialChunkBufferLen(tc.MaxPlaintextChunkLen),
				twoway.WithMaxChunkPlaintextLen(tc.MaxPlaintextChunkLen),
			)
			require.NoError(t, err)

			// verify only chunk length is returned.
			_, ok := reqSealer.Len()
			require.False(t, ok)
			_, ok = reqSealer.MaxCiphertextChunkLen()
			require.True(t, ok)

			_, err = io.Copy(reqCTBuf, reqSealer)
			require.NoError(t, err)

			// this sealer includes a header in its output.
			require.Equal(t, tc.ChunkedLen+requestNonceLen, reqCTBuf.Len())

			// encapsulate a key, decrypt the request and do a response cycle for each receiver.
			for range 3 {
				pubKey, privKey, err := kdfID.Scheme().GenerateKeyPair()
				require.NoError(t, err)

				reqCT := bytes.NewReader(reqCTBuf.Bytes())

				encapKey, newRespOpener, err := reqSealer.EncapsulateKey(keyID, pubKey)
				require.NoError(t, err)

				// now pretend we're on the receiving end.
				receiver, err := twoway.NewMultiRequestReceiver(suite, keyID, privKey, rand.Reader)
				require.NoError(t, err)

				// decrypt request
				reqOpener, err := receiver.NewRequestOpener(
					encapKey,
					reqCT,
					[]byte(reqMediaType),
					twoway.EnableChunking(),
					twoway.WithInitialChunkBufferLen(tc.MaxPlaintextChunkLen),
					twoway.WithMaxChunkPlaintextLen(tc.MaxPlaintextChunkLen),
				)
				require.NoError(t, err)

				// verify plaintext can be read from the reader.
				err = iotest.TestReader(reqOpener, tc.Plaintext)
				require.NoError(t, err)

				// encrypt the same plaintext as a response.
				respCTBuf := &bytes.Buffer{}
				respSealer, err := reqOpener.NewResponseSealer(
					bytes.NewReader(tc.Plaintext),
					[]byte(resMediaType),
					twoway.EnableChunking(),
					twoway.WithInitialChunkBufferLen(tc.MaxPlaintextChunkLen),
					twoway.WithMaxChunkPlaintextLen(tc.MaxPlaintextChunkLen),
				)
				require.NoError(t, err)

				// verify only chunk length is returned.
				_, ok = respSealer.Len()
				require.False(t, ok)
				_, ok = respSealer.MaxCiphertextChunkLen()
				require.True(t, ok)

				_, err = io.Copy(respCTBuf, respSealer)
				require.NoError(t, err)

				// this sealer includes a header in its output.
				require.Equal(t, tc.ChunkedLen+responseNonceLen, respCTBuf.Len())

				// okay, back to the sender end, decrypt the response from this receiver.
				respOpener, err := newRespOpener(
					respCTBuf,
					[]byte(resMediaType),
					twoway.EnableChunking(),
					twoway.WithInitialChunkBufferLen(tc.MaxPlaintextChunkLen),
					twoway.WithMaxChunkPlaintextLen(tc.MaxPlaintextChunkLen),
				)
				require.NoError(t, err)

				// verify plaintext can be read from the reader.
				err = iotest.TestReader(respOpener, tc.Plaintext)
				require.NoError(t, err)
			}
		})
	}

	// TODO: Negative tests.
	// fail, request opener with invalid header.
	// fail, request opener with non-matching header.
	// fail, response opener with missing nonce.
	// fail, request ciphertext tampered with.
	// fail, response ciphertext tampered with.
	// fail, media type mismatch on request.
	// fail, media type mismatch on response.
	// fail, suite mismatch on request.
	// fail, suite mismatch on response.
}

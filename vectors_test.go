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
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/confidentsecurity/twoway"
	"github.com/confidentsecurity/twoway/internal/test/unsafehpke"
	"github.com/stretchr/testify/require"
)

func TestVectors(t *testing.T) {
	// IMPORTANT! On the use of unsafehpke:
	//
	// The Chunked OHTTP RFC examples provide us with a constant sender secret (senderPrivKeyB in these tests). This is incompatible with
	// the circl/hpke package.
	//
	// circl/hpke generates this sender secret from a seed and we can only inject a seed. Since we don't
	// have the seed for OHTTP RFC Example, this causes a bit of an issue.
	//
	// I have made a local copy of `circl/hpke` in `internal/test/unsafehpke` that allows for the injection
	// of this sender secret. This package should only be used in tests.

	t.Run("ok, ohttp rfc example", func(t *testing.T) {
		// This test walks through the example from the OHTTP RFC, it skips the key setup.
		// see:
		// https://www.rfc-editor.org/rfc/rfc9458.html#name-complete-example-of-a-reque
		var (
			receiverPrivKeyB = hexDecode(t, `3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a`)
			keyConfig        = hexDecode(t, `01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003`)
			senderPrivKeyB   = hexDecode(t, `bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73`)
			requestB         = hexDecode(t, `00034745540568747470730b6578616d706c652e636f6d012f`)
			encapRequestB    = hexDecode(t, `010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525`)
			responseB        = hexDecode(t, `0140c8`)
			encapResponseB   = hexDecode(t, `c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd`)
			salt             = hexDecode(t, `4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472c789e7151fcba46158ca84b04464910d`)
		)

		keyID := keyConfig[0]
		kemID := unsafehpke.KEM_X25519_HKDF_SHA256
		kdfID := unsafehpke.KDF_HKDF_SHA256
		aeadID := unsafehpke.AEAD_AES128GCM
		suite := unsafehpke.NewSuite(kemID, kdfID, aeadID)

		receiverPrivKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(receiverPrivKeyB)
		require.NoError(t, err)

		// only need the public key from the keyConfig.
		pubKeyB := keyConfig[3 : len(keyConfig)-2-4]

		senderPubKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(pubKeyB)
		require.NoError(t, err)

		// check integrity.
		require.True(t, receiverPrivKey.Public().Equal(senderPubKey))

		// this is where we inject the constant secret key mentioned above.
		senderPrivKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(senderPrivKeyB)
		require.NoError(t, err)
		unsafehpke.InjectedXKEMPrivateKey.Setup((senderPrivKey))

		// create the HPKE sending context.
		unsafeSuite := unsafeHPKESuite{
			suite: suite,
		}

		reqSender, err := twoway.NewRequestSenderWithCustomSuite(unsafeSuite, keyID, senderPubKey, nil)
		require.NoError(t, err)

		reqSealer, err := reqSender.NewRequestSealer(bytes.NewBuffer(requestB), []byte("message/bhttp request"))
		require.NoError(t, err)

		// seal the request
		reqCTBuf := &bytes.Buffer{}
		_, err = io.Copy(reqCTBuf, reqSealer)
		require.NoError(t, err)

		// verify the sealed request matches the expected encapsulated request.
		require.Equal(t, encapRequestB, reqCTBuf.Bytes())

		// create the HPKE receiving context.
		// we need to inject a fixed random reader here as we need a fixed nonce, the nonce
		// in this case the nonce is the last 16 bytes of the salt.
		nonceReader := bytes.NewReader(salt[len(salt)-16:])
		receiver, err := twoway.NewRequestReceiverWithCustomSuite(unsafeSuite, keyID, receiverPrivKey, nonceReader)
		require.NoError(t, err)

		reqOpener, err := receiver.NewRequestOpener(reqCTBuf, []byte("message/bhttp request"))
		require.NoError(t, err)

		// open the request
		reqPTBuf := &bytes.Buffer{}
		_, err = io.Copy(reqPTBuf, reqOpener)
		require.NoError(t, err)

		// verify the opened request matches the original request.
		require.Equal(t, requestB, reqPTBuf.Bytes())

		// seal the response
		respSealer, err := reqOpener.NewResponseSealer(bytes.NewReader(responseB), []byte("message/bhttp response"))
		require.NoError(t, err)

		respCTBuf := &bytes.Buffer{}
		_, err = io.Copy(respCTBuf, respSealer)
		require.NoError(t, err)

		// verify the sealed response matches the encapsulated response.
		require.Equal(t, encapResponseB, respCTBuf.Bytes())

		// open the response
		respOpener, err := reqSealer.NewResponseOpener(respCTBuf, []byte("message/bhttp response"))
		require.NoError(t, err)

		respPTBuf := &bytes.Buffer{}
		_, err = io.Copy(respPTBuf, respOpener)
		require.NoError(t, err)

		// verify the opened response matches the original response.
		require.Equal(t, responseB, respPTBuf.Bytes())
	})

	t.Run("ok, chunked ohttp rfc example", func(t *testing.T) {
		// This test walks through the example from the Chunked OHTTP Draft RFC, it skips the key setup.
		// see:
		// https://github.com/ietf-wg-ohai/draft-ohai-chunked-ohttp/blob/main/draft-ietf-ohai-chunked-ohttp.md#example
		var (
			receiverPrivKeyB = hexDecode(t, `1c190d72acdbe4dbc69e680503bb781a932c70a12c8f3754434c67d8640d8698`)
			keyConfig        = hexDecode(t, `010020668eb21aace159803974a4c67f08b4152d29bed10735fd08f98ccdd6fe09570800080001000100010003`)
			senderPrivKeyB   = hexDecode(t, `b26d565f3f875ed480d1abced3d665159650c99174fd0b124ac4bda0c64ae324`)
			requestB         = hexDecode(t, `00034745540568747470730b6578616d706c652e636f6d012f`)
			encapRequestB    = hexDecode(t, `010020000100018811eb457e100811c40a0aa71340a1b81d804bb986f736f2f566a7199761a0321c2ad24942d4d692563012f2980c8fef437a336b9b2fc938ef77a5834f1d2e33d8fd25577afe31bd1c79d094f76b6250ae6549b473ecd950501311001c6c1395d0ef7c1022297966307b8a7f`)
			responseB        = hexDecode(t, `0140c8`)
			encapResponseB   = hexDecode(t, `bcce7f4cb921309ba5d62edf1769ef091179bf1cc87fa0e2c02de4546945aa3d1e4812b348b5bd4c594c16b6170b07b475845d1f3200ed9d8a796617a5b27265f4d73247f639`)
			salt             = hexDecode(t, `8811eb457e100811c40a0aa71340a1b81d804bb986f736f2f566a7199761a032bcce7f4cb921309ba5d62edf1769ef09`)
		)

		keyID := keyConfig[0]
		kemID := unsafehpke.KEM_X25519_HKDF_SHA256
		kdfID := unsafehpke.KDF_HKDF_SHA256
		aeadID := unsafehpke.AEAD_AES128GCM
		suite := unsafehpke.NewSuite(kemID, kdfID, aeadID)

		receiverPrivKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(receiverPrivKeyB)
		require.NoError(t, err)

		// only need the public key from the keyConfig.
		pubKeyB := keyConfig[3 : len(keyConfig)-2-4]

		senderPubKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(pubKeyB)
		require.NoError(t, err)

		// check integrity.
		require.True(t, receiverPrivKey.Public().Equal(senderPubKey))

		// this is where we inject the constant secret key mentioned above.
		senderPrivKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(senderPrivKeyB)
		require.NoError(t, err)
		unsafehpke.InjectedXKEMPrivateKey.Setup((senderPrivKey))

		// create the HPKE sending context.
		unsafeSuite := unsafeHPKESuite{
			suite: suite,
		}

		reqSender, err := twoway.NewRequestSenderWithCustomSuite(unsafeSuite, keyID, senderPubKey, nil)
		require.NoError(t, err)

		requestReads := newHardcodedReads(requestB[:12], requestB[12:])
		reqSealer, err := reqSender.NewRequestSealer(
			requestReads, []byte("message/bhttp chunked request"), twoway.EnableChunking(),
		)
		require.NoError(t, err)

		// seal the request
		reqCTBuf := &bytes.Buffer{}
		_, err = io.Copy(reqCTBuf, reqSealer)
		require.NoError(t, err)

		// verify the sealed request matches the expected encapsulated request.
		require.Equal(t, encapRequestB, reqCTBuf.Bytes())

		// create the HPKE receiving context.
		// we need to inject a fixed random reader here as we need a fixed nonce, the nonce
		// in this case the nonce is the last 16 bytes of the salt.
		nonceReader := bytes.NewReader(salt[len(salt)-16:])
		receiver, err := twoway.NewRequestReceiverWithCustomSuite(unsafeSuite, keyID, receiverPrivKey, nonceReader)
		require.NoError(t, err)

		reqOpener, err := receiver.NewRequestOpener(
			reqCTBuf, []byte("message/bhttp chunked request"), twoway.EnableChunking(),
		)
		require.NoError(t, err)

		// open the request
		reqPTBuf := &bytes.Buffer{}
		_, err = io.Copy(reqPTBuf, reqOpener)
		require.NoError(t, err)

		// verify the opened request matches the original request.
		require.Equal(t, requestB, reqPTBuf.Bytes())

		// seal the response
		responseReads := newHardcodedReads(responseB[:1], responseB[1:])
		respSealer, err := reqOpener.NewResponseSealer(
			responseReads, []byte("message/bhttp chunked response"), twoway.EnableChunking(),
		)
		require.NoError(t, err)

		respCTBuf := &bytes.Buffer{}
		_, err = io.Copy(respCTBuf, respSealer)
		require.NoError(t, err)

		// verify the sealed response matches the encapsulated response.
		require.Equal(t, encapResponseB, respCTBuf.Bytes())

		// open the response
		respOpener, err := reqSealer.NewResponseOpener(
			respCTBuf, []byte("message/bhttp chunked response"), twoway.EnableChunking(),
		)
		require.NoError(t, err)

		respPTBuf := &bytes.Buffer{}
		_, err = io.Copy(respPTBuf, respOpener)
		require.NoError(t, err)

		// verify the opened response matches the original response.
		require.Equal(t, responseB, respPTBuf.Bytes())
	})
}

func hexDecode(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

type unsafeHPKESuite struct {
	suite unsafehpke.Suite
}

func (s unsafeHPKESuite) NewSender(pubKey kem.PublicKey, info []byte) (twoway.HPKESender, error) {
	sender, err := s.suite.NewSender(pubKey, info)
	return unsafeHPKESender{sender}, err
}
func (s unsafeHPKESuite) NewReceiver(privKey kem.PrivateKey, info []byte) (twoway.HPKEReceiver, error) {
	receiver, err := s.suite.NewReceiver(privKey, info)
	return unsafeHPKEReceiver{receiver}, err
}

func (s unsafeHPKESuite) Params() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	kemID, kdfID, aeadID := s.suite.Params()
	return hpke.KEM(kemID), hpke.KDF(kdfID), hpke.AEAD(aeadID)
}

type unsafeHPKESender struct {
	sender *unsafehpke.Sender
}

func (s unsafeHPKESender) Setup(rnd io.Reader) ([]byte, twoway.HPKESealer, error) {
	enc, sealer, err := s.sender.Setup(rnd)
	return enc, sealer, err
}

type unsafeHPKEReceiver struct {
	receiver *unsafehpke.Receiver
}

func (r unsafeHPKEReceiver) Setup(encapKey []byte) (twoway.HPKEOpener, error) {
	opener, err := r.receiver.Setup(encapKey)
	return opener, err
}

type hardcodedReads struct {
	reads [][]byte
	i     int
}

func newHardcodedReads(reads ...[]byte) *hardcodedReads {
	return &hardcodedReads{
		reads: reads,
		i:     0,
	}
}

func (r *hardcodedReads) Read(p []byte) (int, error) {
	if r.i >= len(r.reads) {
		return 0, io.EOF
	}

	if len(p) < len(r.reads[r.i]) {
		return 0, fmt.Errorf("not enough space for read p len %d and read len %d", len(p), len(r.reads[r.i]))
	}

	n := copy(p, r.reads[r.i])
	r.i++
	return n, nil
}

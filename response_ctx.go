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
	"crypto/cipher"
	"fmt"
	"io"
)

type responseCtx struct {
	nonceReader  io.Reader
	suite        HPKESuite
	hpkeExporter HPKEExporter
	hpkeEncapKey []byte
}

type responseParams struct {
	responseNonce []byte
	aeadNonce     []byte
	cipher        cipher.AEAD
}

func (c *responseCtx) newResponseParams(mediaType []byte) (responseParams, error) {
	_, kdfID, aeadID := c.suite.Params()

	// entropyLen = max(Nn, Nk)
	entropyLen := max(aeadID.KeySize(), aeadID.NonceSize())

	// response_nonce = random(entropy_len)
	respNonce := make([]byte, entropyLen)
	_, err := c.nonceReader.Read(respNonce)
	if err != nil {
		return responseParams{}, fmt.Errorf("failed to read nonce: %w", err)
	}

	// secret = context.Export("message/bhttp response", entropy_len)
	secret := c.hpkeExporter.Export(mediaType, entropyLen)

	// salt = concat(enc, response_nonce)
	// create a new slice to avoid modifying the original slice
	salt := append([]byte{}, c.hpkeEncapKey...)
	salt = append(salt, respNonce...)

	// prk = Extract(salt, secret)
	// note: circl/hpke wants these in the opposite order as the RFC pseudocode above.
	prk := kdfID.Extract(secret, salt)
	// aeadKey = Expand(prk, "aeadkey", Nk)
	aeadkey := kdfID.Expand(prk, []byte("key"), aeadID.KeySize())
	// aeadNonce = Expand(prk, "aeadNonce", Nn)
	aeadNonce := kdfID.Expand(prk, []byte("nonce"), aeadID.NonceSize())

	cphr, err := aeadID.New(aeadkey)
	if err != nil {
		return responseParams{}, fmt.Errorf("failed to create aead cipher: %w", err)
	}

	return responseParams{
		responseNonce: respNonce,
		aeadNonce:     aeadNonce,
		cipher:        cphr,
	}, nil
}

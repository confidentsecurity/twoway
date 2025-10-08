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

// Package chunks encrypts/decrypts sequences of chunks using Authenticated
// Encryption with Associated Data.
//
// This package implements the chunk format specified in the [Chunked OHTTP Draft RFC], but is useful in others contexts as well.
//
// [Chunked OHTTP Draft RFC]: https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-response-encapsulation
package chunks

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"math"

	"github.com/cloudflare/circl/hpke"
)

// Sealer seals chunks.
type Sealer interface {
	// Seal works the same as cipher.AEAD except that the nonce is managed by the Sealer.
	Seal(dst, pt, aad []byte) ([]byte, error)
	Overhead() int
}

// Opener opens chunks.
type Opener interface {
	// Open works the same as cipher.AEAD except that the nonce is managed by the Opener.
	Open(dst, pt, aad []byte) ([]byte, error)
	Overhead() int
}

// AEADContext is a [Sealer] and [Opener] that seals/opens chunks in order using a given AEAD cipher.
//
// It manages a counter and nonce as specified in the section on Chunked Responses in section 6.2 of the Chunked OHTTP RFC:
// https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-response-encapsulation
type AEADContext struct {
	cipher cipher.AEAD

	counter   []byte
	baseNonce []byte
	nonce     []byte
}

// NewAEADContext creates a new AEAD Context.
func NewAEADContext(c cipher.AEAD, baseNonce []byte) (*AEADContext, error) {
	if len(baseNonce) < 1 {
		return nil, fmt.Errorf("invalid base nonce, want at least len %d, got %d", 1, len(baseNonce))
	}

	ctx := &AEADContext{
		cipher:    c,
		counter:   make([]byte, len(baseNonce)),
		baseNonce: bytes.Clone(baseNonce),
		nonce:     make([]byte, len(baseNonce)),
	}

	// make ctx ready for the 0th chunk.
	ctx.xorNonce()

	return ctx, nil
}

// Overhead returns the overhead of this AEAD cipher.
func (c *AEADContext) Overhead() int {
	return c.cipher.Overhead()
}

func (c *AEADContext) next() error {
	ok := incrementBigEndianNoOverflow(c.counter)
	if !ok {
		return ErrNonceReuse
	}

	c.xorNonce()
	return nil
}

func (c *AEADContext) xorNonce() {
	for i := range c.baseNonce {
		c.nonce[i] = c.baseNonce[i] ^ c.counter[i]
	}
}

// Seal seals the plaintext.
func (c *AEADContext) Seal(dst, pt, aad []byte) ([]byte, error) {
	ct := c.cipher.Seal(dst, c.nonce, pt, aad)
	err := c.next()
	if err != nil {
		return nil, err
	}

	return ct, nil
}

// Open opens the ciphertext.
func (c *AEADContext) Open(dst, ct, aad []byte) ([]byte, error) {
	pt, err := c.cipher.Open(dst, c.nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %w", err)
	}

	err = c.next()
	if err != nil {
		return nil, err
	}

	return pt, nil
}

func incrementBigEndianNoOverflow(nr []byte) bool {
	// if nr is all ones we will overflow on the next increase, return an error.
	overflow := true
	for i := 0; i < len(nr); i++ {
		if nr[i] != math.MaxUint8 {
			overflow = false
		}
	}

	if overflow {
		return false
	}

	// there will be no overflow, increment the number.
	// Start from the least significant byte (on the right in big endian).
	for i := len(nr) - 1; i >= 0; i-- {
		nr[i]++
		if nr[i] != 0 {
			// done, if this byte didn't overflow we don't need to touch the other ones.
			return true
		}
	}

	return true
}

// HPKEOpener is redefined here to prevent circular imports.
type HPKEOpener interface {
	Open(ct, aad []byte) ([]byte, error)
}

// HPKESealer is redefined here to prevent circular imports.
type HPKESealer interface {
	Seal(pt, aad []byte) ([]byte, error)
}

// HPKESealerCtx is a [Sealer] that uses HPKE to manage the encryption context.
// HPKE will take care of the counter and nonce handling for us.
type HPKESealerCtx struct {
	sealer   HPKESealer
	overhead int
}

// NewHPKESealerContext creates a new HPKE sealing context.
func NewHPKESealerContext(sealer HPKESealer, aeadID hpke.AEAD) *HPKESealerCtx {
	return &HPKESealerCtx{
		sealer: sealer,
		//nolint:gosec
		overhead: int(aeadID.CipherLen(0)),
	}
}

// Seal seals the plaintext.
func (s *HPKESealerCtx) Seal(dst, pt, aad []byte) ([]byte, error) {
	ct, err := s.sealer.Seal(pt, aad)
	if err != nil {
		return nil, err
	}

	// fake having encryption in place, as the contract of our Sealer
	// depends on it.
	if cap(dst) >= len(ct) {
		dst = dst[:len(ct)]
		copy(dst, ct)
		return dst, nil
	}

	return ct, nil
}

// Overhead returns the overhead of this AEAD cipher.
func (s *HPKESealerCtx) Overhead() int {
	return s.overhead
}

// HPKEOpenerCtx is an [Opener] that uses HPKE to manage the encryption context.
// HPKE will take care of the counter and nonce handling for us.
type HPKEOpenerCtx struct {
	opener   HPKEOpener
	overhead int
}

// NewHPKEOpenerContext creates a new HPKE opening context.
func NewHPKEOpenerContext(opener HPKEOpener, aeadID hpke.AEAD) *HPKEOpenerCtx {
	return &HPKEOpenerCtx{
		opener: opener,
		//nolint:gosec
		overhead: int(aeadID.CipherLen(0)),
	}
}

// Open opens the ciphertext.
func (c *HPKEOpenerCtx) Open(dst, ct, aad []byte) ([]byte, error) {
	pt, err := c.opener.Open(ct, aad)
	if err != nil {
		return nil, err
	}

	// fake having decryption in place, as the contract of our Opener depends on it.
	if cap(dst) >= len(pt) {
		dst = dst[:len(pt)]
		copy(dst, pt)
		return dst, nil
	}

	return pt, nil
}

// Overhead returns the overhead of this AEAD cipher.
func (c *HPKEOpenerCtx) Overhead() int {
	return c.overhead
}

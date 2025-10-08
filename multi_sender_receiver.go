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
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

const multiEncapKeyAAD = "multi-encap-key"

// MultiRequestSender sends request messages to multiple receivers. Messages can be
// received by [MultiRequestReceiver].
//
// Create a new sealer using [MultiRequestSender.NewRequestSealer] to begin sealing
// a plaintext.
//
// After creating a sealer, the sealer's internal secret key can be encapsulated for one
// or more receivers. It up to the caller to provide this encapsulated key to the
// appropriate receiver.
//
// This type and its sealer are not compatible with OHTTP.
type MultiRequestSender struct {
	suite      HPKESuite
	randReader io.Reader
}

// NewMultiRequestSender creates a new sender for the given HPKE suite.
func NewMultiRequestSender(suite hpke.Suite, randReader io.Reader) *MultiRequestSender {
	return NewMultiRequestSenderWithCustomSuite(AdaptCirclHPKESuite(suite), randReader)
}

// NewMultiRequestSenderWithCustomSuite allows for the use of a non-circl HPKE suite.
func NewMultiRequestSenderWithCustomSuite(suite HPKESuite, randReader io.Reader) *MultiRequestSender {
	return &MultiRequestSender{
		randReader: randReader,
		suite:      suite,
	}
}

// NewRequestSealer generates a new random key and begins sealing the plaintext message. The mediaType is used
// as additional context and must be matched when opening the ciphertext returned by this sealer.
//
// Enable chunking by passing the [EnableChunking] option.
func (s *MultiRequestSender) NewRequestSealer(pt io.Reader, mediaType []byte, opts ...Option) (*MultiRequestSealer, error) {
	cfg := defaultSealerConfig()
	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	key := make([]byte, keyLen)
	_, err := io.ReadFull(s.randReader, key)
	if err != nil {
		return nil, fmt.Errorf("failed to read key: %w", err)
	}

	_, _, aeadID := s.suite.Params()
	cphr, nonce, err := newCipher(key, aeadID, s.randReader)
	if err != nil {
		return nil, err
	}

	encReader, encLen, err := newSealingAEADReader(pt, cfg, cphr, nonce)
	if err != nil {
		return nil, err
	}

	return &MultiRequestSealer{
		sender:    s,
		key:       key,
		mediaType: bytes.Clone(mediaType),
		// prefix ciphertext with nonce.
		reader: newSealerReader(encReader, nonce, cfg.chunked, encLen),
	}, nil
}

// MultiRequestSealer seals a request message for multiple receivers.
//
// MultiRequestSealer implements [io.Reader], Read returns the ciphertext.
//
// If chunking is enabled, the ciphertext will consist of one or more chunks.
// These chunks can be processed incrementally.
type MultiRequestSealer struct {
	sender    *MultiRequestSender
	key       []byte
	mediaType []byte
	reader    *sealerReader
}

// Len returns the remaining number of bytes that can be read.
//
// Only applies sealers sealing unchunked messages. If this sealer is sealing
// a chunked message the second return value will be false.
//
// Len includes the header length.
func (s *MultiRequestSealer) Len() (int, bool) {
	return s.reader.Len()
}

// HeaderLen returns the length of the header of this message. Each sealer prefixes
// a message or a stream of chunks with a single header.
func (s *MultiRequestSealer) HeaderLen() int {
	return s.reader.HeaderLen()
}

// MaxCiphertextChunkLen returns the maximum length of a ciphertext chunk. If this
// sealerReader is not sealing a chunked message the second return value will be false.
//
// The actual length of a ciphertext chunk depends on the length returned by
// original plaintext reader.
//
// The returned length does not include the header length.
func (s *MultiRequestSealer) MaxCiphertextChunkLen() (int, bool) {
	return s.reader.MaxCiphertextChunkLen()
}

// Read the ciphertext.
func (s *MultiRequestSealer) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

// ResponseOpenerFunc is a function that creates a response opener.
type ResponseOpenerFunc func(ct io.Reader, mediaType []byte, opts ...Option) (io.Reader, error)

// EncapsulateKey encapsulates the internal secret key for a given public key of a receiver.
// The returned [ResponseOpenerFunc] should be used to create a response opener for this receiver.
func (s *MultiRequestSealer) EncapsulateKey(keyID byte, pubKey kem.PublicKey) ([]byte, ResponseOpenerFunc, error) {
	// output = concat(hdr, hpkeEncapKey, encapKey)
	h := NewRequestHeaderForSuite(s.sender.suite, keyID)
	hdr, err := h.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get info: %w", err)
	}

	hpkeSender, err := s.sender.suite.NewSender(pubKey, info(hdr, s.mediaType))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create hpke sender: %w", err)
	}

	hpkeEncapKey, hpkeSealer, err := hpkeSender.Setup(s.sender.randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create hpke sealer: %w", err)
	}

	encapKey, err := hpkeSealer.Seal(s.key, []byte(multiEncapKeyAAD))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to seal key: %w", err)
	}

	out := make([]byte, 0, len(hdr)+len(hpkeEncapKey)+len(encapKey))
	out = append(out, hdr...)
	out = append(out, hpkeEncapKey...)
	out = append(out, encapKey...)

	return out, s.newResponseOpenerFunc(hpkeEncapKey, hpkeSealer), nil
}

func (s *MultiRequestSealer) newResponseOpenerFunc(hpkeEncapkey []byte, hpkeExporter HPKEExporter) ResponseOpenerFunc {
	return func(ct io.Reader, mediaType []byte, opts ...Option) (io.Reader, error) {
		cfg := defaultOpenerConfig()
		for _, opt := range opts {
			err := opt(cfg)
			if err != nil {
				return nil, err
			}
		}

		respCtx := &responseCtx{
			nonceReader:  ct, // first few bytes will be the nonce.
			suite:        s.sender.suite,
			hpkeExporter: hpkeExporter,
			hpkeEncapKey: hpkeEncapkey,
		}

		params, err := respCtx.newResponseParams(mediaType)
		if err != nil {
			return nil, nil
		}

		return newOpeningAEADReader(ct, cfg, params.cipher, params.aeadNonce)
	}
}

// MultiRequestReceiver receives request messages from [MultiRequestSender].
//
// When a ciphertext is received, it should be passed to [MultiRequestReceiver.NewRequestOpener]
// to create an opener.
//
// This type and its opener are not compatible with OHTTP.
type MultiRequestReceiver struct {
	randReader io.Reader
	suite      HPKESuite
	privKey    kem.PrivateKey
	header     RequestHeader
}

// NewMultiRequestReceiver creates a receiver for the given HPKE suite and private key.
func NewMultiRequestReceiver(suite hpke.Suite, keyID byte, privKey kem.PrivateKey, randReader io.Reader) (*MultiRequestReceiver, error) {
	return NewMultiRequestReceiverWithCustomSuite(AdaptCirclHPKESuite(suite), keyID, privKey, randReader)
}

// NewMultiRequestReceiverWithCustomSuite allows for the use of a non-circl HPKE suite.
func NewMultiRequestReceiverWithCustomSuite(suite HPKESuite, keyID byte, privKey kem.PrivateKey, randReader io.Reader) (*MultiRequestReceiver, error) {
	return &MultiRequestReceiver{
		randReader: randReader,
		suite:      suite,
		privKey:    privKey,
		header:     NewRequestHeaderForSuite(suite, keyID),
	}, nil
}

// NewRequestOpener creates a new opener and begins opening the plaintext message.
//
// The mediaType is used as additional context and must match the mediaType that was used to seal the ciphertext.
//
// Enable chunking by passing the [EnableChunking] option.
func (r *MultiRequestReceiver) NewRequestOpener(encapKey []byte, ct io.Reader, mediaType []byte, opts ...Option) (*RequestOpener, error) {
	cfg := defaultOpenerConfig()
	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	k, hpkeOpener, err := r.decapsulateMultiKeys(encapKey, mediaType)
	if err != nil {
		return nil, err
	}

	_, _, aeadID := r.suite.Params()
	cphr, nonce, err := newCipher(k.key, aeadID, ct) // reads nonce from ct.
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	openingReader, err := newOpeningAEADReader(ct, cfg, cphr, nonce)
	if err != nil {
		return nil, err
	}

	return &RequestOpener{
		reader: openingReader,
		respCtx: &responseCtx{
			nonceReader:  r.randReader, // random nonces.
			suite:        r.suite,
			hpkeExporter: hpkeOpener,
			hpkeEncapKey: k.hpkeEncapKey,
		},
	}, nil
}

type multiKeys struct {
	hpkeEncapKey []byte
	key          []byte
}

func (r *MultiRequestReceiver) decapsulateMultiKeys(encapKey, mediaType []byte) (multiKeys, HPKEOpener, error) {
	header, err := ParseRequestHeaderFrom(encapKey)
	if err != nil {
		return multiKeys{}, nil, fmt.Errorf("failed to parse header from encapsulated key: %w", err)
	}

	// this will fail during opening as well, but we can return a friendlier message.
	if header != r.header {
		return multiKeys{}, nil, fmt.Errorf("mismatched suite or key, got header %v want %v", header, r.header)
	}

	hdr := encapKey[:BinaryRequestHeaderLen]
	encapKey = encapKey[BinaryRequestHeaderLen:]

	// next is the hpkeEncapKey
	hpkeEncapKeyLen := header.KemID.Scheme().CiphertextSize()
	if len(encapKey) < hpkeEncapKeyLen {
		return multiKeys{}, nil, fmt.Errorf("invalid hpke encapsulated key, want len %d, got %d", hpkeEncapKeyLen, len(encapKey))
	}
	hpkeEncapKey := encapKey[:hpkeEncapKeyLen]

	// remaining should be the regular encap key
	encapKey = encapKey[hpkeEncapKeyLen:]

	// create receiver and opener for encapsulated key
	hpkeReceiver, err := r.suite.NewReceiver(r.privKey, info(hdr, mediaType))
	if err != nil {
		return multiKeys{}, nil, fmt.Errorf("failed to create hpke receiver: %w", err)
	}

	hpkeOpener, err := hpkeReceiver.Setup(hpkeEncapKey)
	if err != nil {
		return multiKeys{}, nil, fmt.Errorf("failed to create hpke opener: %w", err)
	}

	key, err := hpkeOpener.Open(encapKey, []byte(multiEncapKeyAAD))
	if err != nil {
		return multiKeys{}, nil, fmt.Errorf("failed to open encapsulated key: %w", err)
	}

	return multiKeys{
		hpkeEncapKey: hpkeEncapKey,
		key:          key,
	}, hpkeOpener, nil
}

const keyLen = 32

func newCipher(key []byte, aeadID hpke.AEAD, nonceReader io.Reader) (cipher.AEAD, []byte, error) {
	if !aeadID.IsValid() {
		return nil, nil, fmt.Errorf("invalid aead %v", aeadID)
	}

	if nonceReader == nil {
		return nil, nil, errors.New("missing nonce reader")
	}

	c, err := aeadID.New(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	nonce := make([]byte, c.NonceSize())
	_, err = io.ReadFull(nonceReader, nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	return c, nonce, nil
}

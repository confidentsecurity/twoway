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
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// RequestSender sends request messages to a single receiver. Messages can be
// received by [RequestReceiver].
//
// Create a new sealer using [RequestSender.NewRequestSealer] to begin sealing
// a plaintext.
//
// The output of this sender and its sealers fully conforms to request formats
// defined in OHTTP RFC and Chunked OHTTP Draft RFC.
//
// As Chunked OHTTP is still a draft, this functionality might be subject to
// change.
type RequestSender struct {
	randReader io.Reader
	suite      HPKESuite
	pubKey     kem.PublicKey
	header     RequestHeader
	headerB    []byte
}

// NewRequestSender creates a new sender for the given HPKE suite and public key.
func NewRequestSender(suite hpke.Suite, keyID byte, pubKey kem.PublicKey, randReader io.Reader) (*RequestSender, error) {
	return NewRequestSenderWithCustomSuite(AdaptCirclHPKESuite(suite), keyID, pubKey, randReader)
}

// NewRequestSenderWithCustomSuite allows for the use of a non-circl HPKE suite.
func NewRequestSenderWithCustomSuite(suite HPKESuite, keyID byte, pubKey kem.PublicKey, randReader io.Reader) (*RequestSender, error) {
	if randReader == nil {
		randReader = rand.Reader
	}

	h := NewRequestHeaderForSuite(suite, keyID)
	headerB, err := h.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request heade to binary: %w", err)
	}

	return &RequestSender{
		randReader: randReader,
		suite:      suite,
		pubKey:     pubKey,
		header:     h,
		headerB:    headerB,
	}, nil
}

// NewRequestSealer creates a new sealer and begins sealing the plaintext message.
//
// The mediaType is used as additional context and must be matched when opening the ciphertext returned by this sealer.
//
// Enable chunking by passing the [EnableChunking] option.
func (s *RequestSender) NewRequestSealer(pt io.Reader, mediaType []byte, opts ...Option) (*RequestSealer, error) {
	cfg := defaultSealerConfig()
	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	// enc, sctxt = SetupBaseS(pkR, info)
	hpkeSender, err := s.suite.NewSender(s.pubKey, info(s.headerB, mediaType))
	if err != nil {
		return nil, fmt.Errorf("failed to create hpke sender: %w", err)
	}

	enc, hpkeSealer, err := hpkeSender.Setup(s.randReader)
	if err != nil {
		return nil, fmt.Errorf("failed to setup hpke sealer: %w", err)
	}

	// ct = sctxt.Seal("", request))
	encReader, encLen, err := newSealingHPKEReader(pt, cfg, hpkeSealer, s.header.AEADID)
	if err != nil {
		return nil, err
	}

	// enc_request = concat(hdr, enc, ct)
	return &RequestSealer{
		suite: s.suite,
		// prefix ciphertext with header and encapsulated key.
		reader:       newSealerReader(encReader, append(s.headerB, enc...), cfg.chunked, encLen),
		hpkeSealer:   hpkeSealer,
		hpkeEncapKey: enc,
	}, nil
}

// RequestSealer seals a request message for a single receiver.
//
// RequestSealer implements [io.Reader], Read returns the ciphertext.
//
// If chunking is enabled, the ciphertext will consist of one or more chunks.
// These chunks can be processed incrementally.
type RequestSealer struct {
	suite        HPKESuite
	reader       *sealerReader
	hpkeSealer   HPKESealer
	hpkeEncapKey []byte
}

// Len returns the remaining number of bytes that can be read.
//
// Only applies sealers sealing unchunked messages. If this sealer is sealing
// a chunked message the second return value will be false.
//
// Len includes the header length.
func (s *RequestSealer) Len() (int, bool) {
	return s.reader.Len()
}

// HeaderLen returns the length of the header of this message. Each sealer prefixes
// a message or a stream of chunks with a single header.
func (s *RequestSealer) HeaderLen() int {
	return s.reader.HeaderLen()
}

// MaxCiphertextChunkLen returns the maximum length of a ciphertext chunk. If this
// sealerReader is not sealing a chunked message the second return value will be false.
//
// The actual length of a ciphertext chunk depends on the length returned by
// original plaintext reader.
//
// The returned length does not include the header length.
func (s *RequestSealer) MaxCiphertextChunkLen() (int, bool) {
	return s.reader.MaxCiphertextChunkLen()
}

// Read the ciphertext.
func (s *RequestSealer) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

// NewResponseOpener creates a new opener and begins opening the plaintext message.
//
// The mediaType is used as additional context and must match the mediaType that was used to seal the ciphertext.
//
// Enable chunking by passing the [EnableChunking] option.
func (s *RequestSealer) NewResponseOpener(ct io.Reader, mediaType []byte, opts ...Option) (io.Reader, error) {
	cfg := defaultOpenerConfig()
	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	respCtx := &responseCtx{
		nonceReader:  ct, // first few bytes will be the nonce.
		suite:        s.suite,
		hpkeExporter: s.hpkeSealer,
		hpkeEncapKey: s.hpkeEncapKey,
	}

	params, err := respCtx.newResponseParams(mediaType)
	if err != nil {
		return nil, err
	}

	return newOpeningAEADReader(ct, cfg, params.cipher, params.aeadNonce)
}

// RequestReceiver receives request messages from [RequestSender].
//
// When a ciphertext is received, it should be passed to [RequestReceiver.NewRequestOpener]
// to create an opener.
//
// This receiver accepts request formats as defined in the OHTTP RFC and Chunked OHTTP Draft RFC.
//
// As Chunked OHTTP is still a draft, this functionality might be subject to change.
type RequestReceiver struct {
	randReader io.Reader
	suite      HPKESuite
	privKey    kem.PrivateKey
	header     RequestHeader
	headerB    []byte
}

// NewRequestReceiver creates a new receiver for the given HPKE suite and private key.
func NewRequestReceiver(suite hpke.Suite, keyID byte, privKey kem.PrivateKey, randReader io.Reader) (*RequestReceiver, error) {
	return NewRequestReceiverWithCustomSuite(AdaptCirclHPKESuite(suite), keyID, privKey, randReader)
}

// NewRequestReceiverWithCustomSuite allows for the use of a non-circl HPKE suite.
func NewRequestReceiverWithCustomSuite(suite HPKESuite, keyID byte, privKey kem.PrivateKey, randReader io.Reader) (*RequestReceiver, error) {
	if randReader == nil {
		randReader = rand.Reader
	}

	h := NewRequestHeaderForSuite(suite, keyID)
	headerB, err := h.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request heade to binary: %w", err)
	}

	return &RequestReceiver{
		randReader: randReader,
		suite:      suite,
		privKey:    privKey,
		header:     h,
		headerB:    headerB,
	}, nil
}

// NewRequestOpener creates a new opener and begins opening the plaintext message.
//
// The mediaType is used as additional context and must match the mediaType that was used to seal the ciphertext.
//
// Enable chunking by passing the [EnableChunking] option.
func (r *RequestReceiver) NewRequestOpener(ct io.Reader, mediaType []byte, opts ...Option) (*RequestOpener, error) {
	cfg := defaultOpenerConfig()
	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	// read the header from ct.
	hdr := make([]byte, BinaryRequestHeaderLen)
	_, err := io.ReadFull(ct, hdr)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	header, err := ParseRequestHeaderFrom(hdr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// this will fail during opening as well, but we can return a friendlier message.
	if header != r.header {
		return nil, fmt.Errorf("mismatched suite or key, got header %v want %v", header, r.header)
	}

	// rctxt = SetupBaseR(enc, skR, info)
	hpkeReceiver, err := r.suite.NewReceiver(r.privKey, info(r.headerB, mediaType))
	if err != nil {
		return nil, fmt.Errorf("failed to setup hpke receiver: %w", err)
	}

	// read encap key.
	enc := make([]byte, r.header.KemID.Scheme().CiphertextSize())
	_, err = io.ReadFull(ct, enc)
	if err != nil {
		return nil, fmt.Errorf("failed to read encapsulated key: %w", err)
	}

	hpkeOpener, err := hpkeReceiver.Setup(enc)
	if err != nil {
		return nil, fmt.Errorf("failed to setup hpke opener: %w", err)
	}

	openingReader, err := newOpeningHPKEReader(ct, cfg, hpkeOpener, r.header.AEADID)
	if err != nil {
		return nil, err
	}

	return &RequestOpener{
		reader: openingReader,
		respCtx: &responseCtx{
			nonceReader:  r.randReader,
			suite:        r.suite,
			hpkeExporter: hpkeOpener,
			hpkeEncapKey: enc,
		},
	}, nil
}

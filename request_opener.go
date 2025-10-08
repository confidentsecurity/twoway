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
	"io"
)

// RequestOpener opens a request message.
//
// RequestOpener implements [io.Reader], Read returns the plaintext.
type RequestOpener struct {
	reader  io.Reader
	respCtx *responseCtx
}

func (o *RequestOpener) Read(p []byte) (int, error) {
	return o.reader.Read(p)
}

// NewResponseSealer begins sealing the given plaintext. The mediaType is used
// as additional context and must be matched when opening the ciphertext returned by this sealer.
//
// Enable chunking by passing the [EnableChunking] option.
func (o *RequestOpener) NewResponseSealer(pt io.Reader, mediaType []byte, opts ...Option) (*ResponseSealer, error) {
	cfg := defaultSealerConfig()
	for _, opt := range opts {
		err := opt(cfg)
		if err != nil {
			return nil, err
		}
	}

	params, err := o.respCtx.newResponseParams(mediaType)
	if err != nil {
		return nil, err
	}

	sealingReader, encLen, err := newSealingAEADReader(pt, cfg, params.cipher, params.aeadNonce)
	if err != nil {
		return nil, err
	}

	return &ResponseSealer{
		// IMPORTANT! Because aeadNonce and aeadKey are derived from the same shared secret
		// we should be careful not to pass aeadNonce here.
		reader: newSealerReader(sealingReader, params.responseNonce, cfg.chunked, encLen),
	}, nil
}

// ResponseSealer seals a response message.
//
// ResponseSealer implements [io.Reader], Read returns the ciphertext.
type ResponseSealer struct {
	reader *sealerReader
}

// Len returns the remaining number of bytes that can be read.
//
// Only applies sealers sealing unchunked messages. If this sealer is sealing
// a chunked message the second return value will be false.
//
// Len includes the header length.
func (s *ResponseSealer) Len() (int, bool) {
	return s.reader.Len()
}

// HeaderLen returns the length of the header of this message. Each sealer prefixes
// a message or a stream of chunks with a single header.
func (s *ResponseSealer) HeaderLen() int {
	return s.reader.HeaderLen()
}

// MaxCiphertextChunkLen returns the maximum length of a ciphertext chunk. If this
// sealerReader is not sealing a chunked message the second return value will be false.
//
// The actual length of a ciphertext chunk depends on the length returned by
// original plaintext reader.
//
// The returned length does not include the header length.
func (s *ResponseSealer) MaxCiphertextChunkLen() (int, bool) {
	return s.reader.MaxCiphertextChunkLen()
}

func (s *ResponseSealer) Read(p []byte) (int, error) {
	return s.reader.Read(p)
}

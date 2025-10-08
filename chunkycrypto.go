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
	"fmt"
	"io"

	"github.com/cloudflare/circl/hpke"
	"github.com/confidentsecurity/twoway/internal/chunks"
)

type sealerReader struct {
	chunked bool
	// maxCiphertextChunkLen is only valid for chunked messages.
	maxCiphertextChunkLen int
	// remaining is only valid for unchunked messages.
	remaining int
	orig      io.Reader
	prefix    []byte
	index     int
}

func newSealerReader(reader io.Reader, prefix []byte, chunked bool, length int) *sealerReader {
	remaining := 0                  // does not apply to chunked messages, we don't know the number of chunks in advance.
	maxCiphertextChunkLen := length // for chunked messages, the length is the max chunk length.
	if !chunked {
		remaining = len(prefix) + length
		maxCiphertextChunkLen = 0 // does not apply to unchunked messages.
	}

	return &sealerReader{
		chunked:               chunked,
		maxCiphertextChunkLen: maxCiphertextChunkLen,
		remaining:             remaining,
		orig:                  reader,
		prefix:                prefix,
		index:                 0,
	}
}

// Len returns the remaining number of bytes that can be read.
//
// Only applies sealers sealing unchunked messages. If this sealer is sealing
// a chunked message the second return value will be false.
//
// Len includes the header length.
//
// This method is exposed by the actual sealers.
func (r *sealerReader) Len() (int, bool) {
	return r.remaining, !r.chunked
}

// HeaderLen returns the length of the header of this message. Each sealer prefixes
// a message or a stream of chunks with a single header.
//
// This method is exposed by the actual sealers.
func (r *sealerReader) HeaderLen() int {
	return len(r.prefix)
}

// MaxCiphertextChunkLen returns the maximum length of a ciphertext chunk. If this
// sealerReader is not sealing a chunked message the second return value will be false.
//
// The actual length of a ciphertext chunk depends on the length returned by
// original plaintext reader.
//
// The returned length does not include the header length.
//
// This method is exposed by the actual sealers.
func (r *sealerReader) MaxCiphertextChunkLen() (int, bool) {
	return r.maxCiphertextChunkLen, r.chunked
}

func (r *sealerReader) Read(p []byte) (int, error) {
	if r.index < len(r.prefix) {
		n := copy(p, r.prefix[r.index:])
		r.index += n
		return n, nil
	}

	return r.orig.Read(p)
}

// newSealingAEADReader returns the a sealing reader and the ciphertext len. If the reader is chunked
// it will return the maximum ciphertext length.
func newSealingAEADReader(pt io.Reader, cfg *opConfig, cphr cipher.AEAD, nonce []byte) (io.Reader, int, error) {
	if cfg.chunked {
		ctx, err := chunks.NewAEADContext(cphr, nonce)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create aead context: %w", err)
		}

		sealingReader, err := chunks.NewEncryptingReader(pt, ctx, cfg.maxChunkPlaintextLen)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create sealing reader: %w", err)
		}

		return sealingReader, sealingReader.MaxCiphertextLen(), nil
	}

	ptB, err := io.ReadAll(pt)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	ctB := cphr.Seal(nil, nonce, ptB, nil)

	return bytes.NewReader(ctB), len(ctB), nil
}

func newOpeningAEADReader(ct io.Reader, cfg *opConfig, cphr cipher.AEAD, nonce []byte) (io.Reader, error) {
	if cfg.chunked {
		ctx, err := chunks.NewAEADContext(cphr, nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to create aead context: %w", err)
		}

		sealingReader, err := chunks.NewDecryptingReader(ct, ctx, cfg.initialChunkBufferLen, cfg.maxChunkPlaintextLen)
		if err != nil {
			return nil, fmt.Errorf("failed to create sealing reader: %w", err)
		}

		return sealingReader, nil
	}

	ctB, err := io.ReadAll(ct)
	if err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	ptB, err := cphr.Open(nil, nonce, ctB, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open ciphertext: %w", err)
	}

	return bytes.NewReader(ptB), nil
}

// newSealingHPKEReader returns the a sealing reader and the ciphertext len. If the reader is chunked
// it will return the maximum ciphertext length.
func newSealingHPKEReader(pt io.Reader, cfg *opConfig, hpkeSealer HPKESealer, aeadID hpke.AEAD) (io.Reader, int, error) {
	if cfg.chunked {
		ctx := chunks.NewHPKESealerContext(hpkeSealer, aeadID)
		reader, err := chunks.NewEncryptingReader(pt, ctx, cfg.maxChunkPlaintextLen)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create sealing reader: %w", err)
		}
		return reader, reader.MaxCiphertextLen(), nil
	}

	// unchunked, read the plaintext and encrypt it.
	ptB, err := io.ReadAll(pt)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read plaintext: %w", err)
	}
	ctB, err := hpkeSealer.Seal(ptB, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed seal plaintext: %w", err)
	}
	return bytes.NewReader(ctB), len(ctB), nil
}

func newOpeningHPKEReader(ct io.Reader, cfg *opConfig, hpkeOpener HPKEOpener, aeadID hpke.AEAD) (io.Reader, error) {
	if cfg.chunked {
		ctx := chunks.NewHPKEOpenerContext(hpkeOpener, aeadID)
		openingReader, err := chunks.NewDecryptingReader(ct, ctx, cfg.initialChunkBufferLen, cfg.maxChunkPlaintextLen)
		if err != nil {
			return nil, fmt.Errorf("failed to create opening reader: %w", err)
		}

		return openingReader, nil
	}

	ctB, err := io.ReadAll(ct)
	if err != nil {
		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	ptB, err := hpkeOpener.Open(ctB, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open ciphertext: %w", err)
	}

	return bytes.NewReader(ptB), nil
}

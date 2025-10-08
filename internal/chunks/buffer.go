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
	"bytes"
	"errors"
	"io"
	"math"

	"github.com/quic-go/quic-go/quicvarint"
)

// finalChunkHeader is a quic encoding of 0
var finalChunkHeader = quicvarint.Append(nil, 0)

type encryptionBuffer struct {
	sealer Sealer

	// We use separate buffers for plaintext and ciphertext on the
	// off-chance there is a bug in the sealer implementation or an
	// attacker can somehow trick the sealer to silently fail.
	//
	// If we were to use in-place encryption, a silent failure of
	// the sealer might lead to us accidentally exposing the plaintext
	// if we were to use in-place encryption.
	plaintext []byte // input as read from the reader.

	maxHeaderLen int
	buffer       []byte // output

	// slices below are windows into buffer
	chunk      []byte // header+data
	header     []byte // up to maxHeaderLen, right aligned.
	ciphertext []byte // starts at maxHeaderLen
}

func newEncryptionBuffer(maxPlaintextLen int, sealer Sealer) (*encryptionBuffer, error) {
	maxCiphertextLen := maxPlaintextLen + sealer.Overhead()

	// quicvarint.Len will panic if you call it with a number greater than it's max representation
	if maxCiphertextLen > quicvarint.Max {
		return &encryptionBuffer{}, errors.New("maximum plaintext length is too long, leads to chunk with size bigger than quic can encode")
	}
	maxHeaderLen := quicvarint.Len(uint64(maxCiphertextLen))
	maxCTChunkLen := maxCiphertextLen + maxHeaderLen

	// slices have a max size of math.MaxInt, can't index anything bigger
	if maxCTChunkLen > math.MaxInt {
		return &encryptionBuffer{}, errors.New("maximum plaintext length is too long, leads to chunk that doesn't fit into a slice")
	}

	return &encryptionBuffer{
		sealer:       sealer,
		plaintext:    make([]byte, maxPlaintextLen),
		maxHeaderLen: maxHeaderLen,
		buffer:       make([]byte, maxCTChunkLen),
		chunk:        nil,
		header:       nil,
		ciphertext:   nil,
	}, nil
}

// encryptChunkFrom encrypts the plaintext read from r into b.chunk as a chunk.
// returns false if no data was read from the underlying reader.
func (b *encryptionBuffer) encryptChunkFrom(r io.Reader) (bool, error) {
	// attempt to read as much plaintext
	b.plaintext = b.plaintext[:cap(b.plaintext)]
	n, err := r.Read(b.plaintext)
	if n == 0 {
		if !errors.Is(err, io.EOF) {
			return false, err
		}
		if err == nil {
			return false, nil
		}

		// err is io.EOF, encrypt the final chunk.
		// The OHTTP RFC allows for content, but we don't add any.
		b.plaintext = b.plaintext[:0]
		err = b.encryptChunk(true, []byte("final"))
		if err != nil {
			return false, err
		}
		return true, nil
	}

	b.plaintext = b.plaintext[:n]
	err = b.encryptChunk(false, nil)
	if err != nil {
		return false, err
	}

	return true, err
}

// encryptChunk resizes all required slices and encrypts a chunk.
func (b *encryptionBuffer) encryptChunk(isFinal bool, aad []byte) error {
	defer func() {
		// zero the plaintext once this function is done, so we don't keep it around longer than necessary.
		zero(b.plaintext[:cap(b.plaintext)])
		b.plaintext = b.plaintext[:0]
	}()

	// encodeChunkLen can be different from the actual chunk length, in the final
	// chunk we will have at least {overhead} bytes of content but encode a 0 to indicate
	// the final chunk.
	encodeChunkLen := uint64(0)
	if !isFinal {
		encodeChunkLen = uint64(len(b.plaintext) + b.sealer.Overhead())
	}

	// reslice the chunk and its windows
	// Buffer is the size of the maximum possible message
	// b.buffer ends up being: [ unusedHeaderBytes | b.header | b.ciphertext | unusedCiphertextbytes ]
	headerLen := quicvarint.Len(encodeChunkLen)
	start := b.maxHeaderLen - headerLen
	b.chunk = b.buffer[start : b.maxHeaderLen+b.sealer.Overhead()+len(b.plaintext)]
	b.header = b.chunk[:headerLen]
	b.ciphertext = b.chunk[headerLen:]

	// encode the chunk length as the header.
	// Appending after b.header[:0] writes into the values of b.header, saving us a copy()
	quicvarint.Append(b.header[:0], encodeChunkLen)

	// seal ciphertext
	var err error
	b.ciphertext, err = b.sealer.Seal(b.ciphertext[:0], b.plaintext, aad)
	if err != nil {
		return err
	}

	return nil
}

func (b *encryptionBuffer) containsFinalChunk() bool {
	if b.header == nil {
		return false
	}

	return bytes.Equal(finalChunkHeader, b.header)
}

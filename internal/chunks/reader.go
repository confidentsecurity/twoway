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
	"errors"
	"fmt"
	"io"
	"math"
	"slices"

	"github.com/quic-go/quic-go/quicvarint"
)

// EncryptingReader encrypts data from the underlying reader.
//
// Data is encrypted in chunks of up to maxChunkLen.
//
// Chunks are encoded in the format specified for [Chunked OHTTP Responses] in
// the [Chunked OHTTP Draft RFC].
//
// The reader accepts a base nonce, this nonce is combined with a counter
// to create chunk nonces.
//
// The base nonce needs to be provided to a decrypting party for them to be able to decrypt
// the encrypted chunks. The base nonce is not included in the data output by this reader.
//
// As specified in the Draft RFC, the amount of bits used for a nonce limits how many chunks
// can be counted. This reader returns [ErrNonceReuse] if this limit is reached.
//
// EncryptingReader is not safe for concurrent use.
//
// For maximum versatily, this reader does not enforce the maximum chunk length specified in
// the draft RFC.
//
// [Chunked OHTTP Responses]: https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-response-encapsulation
// [Chunked OHTTP Draft RFC]: https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html
type EncryptingReader struct {
	reader    io.Reader
	buffer    *encryptionBuffer
	remaining []byte
}

var _ io.Reader = &EncryptingReader{}

// NewEncryptingReader creates a new encrypting reader for the given cipher, nonce and reader.
func NewEncryptingReader(r io.Reader, sealer Sealer, maxPlaintextLen int) (*EncryptingReader, error) {
	if maxPlaintextLen < 1 {
		return nil, fmt.Errorf("invalid plaintext length. min: %d, got %d", 1, maxPlaintextLen)
	}

	encBuff, err := newEncryptionBuffer(maxPlaintextLen, sealer)
	if err != nil {
		return nil, err
	}

	return &EncryptingReader{
		reader:    r,
		buffer:    encBuff,
		remaining: nil,
	}, nil
}

// MaxCiphertextLen returns the maximum length of the ciphertext chunks this reader will create.
func (r *EncryptingReader) MaxCiphertextLen() int {
	return cap(r.buffer.buffer)
}

// Read reads data from the underlying reader and encrypts it as a chunk.
func (r *EncryptingReader) Read(p []byte) (int, error) {
	if len(r.remaining) > 0 {
		n := copy(p, r.remaining)
		r.remaining = r.remaining[n:]
		return n, nil
	}

	if r.buffer.containsFinalChunk() {
		return 0, io.EOF
	}

	readChunk, err := r.buffer.encryptChunkFrom(r.reader)
	if err != nil {
		return 0, err
	}

	if !readChunk {
		return 0, nil
	}

	n := copy(p, r.buffer.chunk)
	if n < len(r.buffer.chunk) {
		r.remaining = r.buffer.chunk[n:]
	}

	return n, nil
}

// DecryptingReader decrypts chunks of data and returns the plaintext.
//
// If integrity violations are encountered this reader will return [ErrIntegrityViolation].
//
// DecryptingReader expects data from the underlying reader to be encoded in
// the format specified in [Chunked OHTTP Responses].
//
// The nonce provided to this reader must match the nonce that was used to encrypt the original plaintext.
//
// For decryption a DecryptingReader needs to keep the full ciphertext of a chunk in memory.Internally
// DecryptingReader uses a dynamic buffer to hold this ciphertext, it starts at initialBufferLen and
// grows up to maxBufferLen. To minimize allocations the initialBufferLen should match the length of
// the chunks you're expected to read.
//
// To prevent DOS attacks, ciphertexts exceeding maxBufferLen will result in [ErrTooMuchData].
//
// DecryptingReader is not safe for concurrent use.
//
// [Chunked OHTTP Responses]: https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-response-encapsulation
type DecryptingReader struct {
	eof          bool
	reader       quicvarint.Reader
	opener       Opener
	chunkLen     int
	maxBufferLen int
	buffer       []byte
	remaining    []byte
}

var _ io.Reader = &DecryptingReader{}

// NewDecryptingReader creates a new decrypting reader.
func NewDecryptingReader(r io.Reader, opener Opener, initialPlaintextLen, maxPlaintextLen int) (*DecryptingReader, error) {
	if initialPlaintextLen < 1 || initialPlaintextLen > maxPlaintextLen {
		return nil, errors.New("invalid buffer lengths")
	}

	initialBufferLen := initialPlaintextLen + opener.Overhead()
	maxBufferLen := maxPlaintextLen + opener.Overhead() // buffer does not contain chunk length.

	quicReader := quicvarint.NewReader(r)

	return &DecryptingReader{
		reader:       quicReader,
		opener:       opener,
		chunkLen:     0,
		maxBufferLen: maxBufferLen,
		buffer:       make([]byte, initialBufferLen),
		remaining:    nil,
	}, nil
}

// Read reads from the underlying reader and decrypts chunks.
func (r *DecryptingReader) Read(p []byte) (int, error) {
	if len(r.remaining) > 0 {
		n := copyAndZero(p, r.remaining)
		r.remaining = r.remaining[n:]
		return n, nil
	}

	if r.eof {
		return 0, io.EOF
	}

	err := r.readAndDecryptChunk()
	if err != nil {
		return 0, err
	}

	n := copyAndZero(p, r.buffer)
	if n < len(r.buffer) {
		r.remaining = r.buffer[n:]
	}

	return n, nil
}

func (r *DecryptingReader) readAndDecryptChunk() error {
	chunkLength, err := quicvarint.Read(r.reader)
	if err != nil {
		return fmt.Errorf("failed to decode chunk length: %w", err)
	}
	if chunkLength > math.MaxInt {
		return fmt.Errorf("decoded quic chunk length greater than MaxInt, slice length limit reached: %d", chunkLength)
	}

	r.chunkLen = int(chunkLength)
	if r.chunkLen == 0 {
		return r.finalChunk()
	}

	return r.regularChunk()
}

func (r *DecryptingReader) regularChunk() error {
	if r.chunkLen > r.maxBufferLen {
		return ErrTooMuchData
	}

	// resize buffer if required
	r.growBuffer(r.chunkLen)

	r.buffer = r.buffer[:r.chunkLen]

	_, err := io.ReadFull(r.reader, r.buffer)
	if err != nil {
		return errors.Join(
			fmt.Errorf("failed to read chunk data: %w", err),
			ErrIntegrityViolation,
		)
	}

	r.buffer, err = r.opener.Open(r.buffer[:0], r.buffer, nil)
	if err != nil {
		return errors.Join(
			fmt.Errorf("failed to decrypt chunk: %w", err),
			ErrIntegrityViolation,
		)
	}

	// increase counter for the next chunk
	return nil
}

func (r *DecryptingReader) finalChunk() error {
	r.eof = true

	n, err := r.readFinalChunkData()
	if err != nil {
		return err
	}

	r.buffer = r.buffer[:n]

	r.buffer, err = r.opener.Open(r.buffer[:0], r.buffer, []byte("final"))
	if err != nil {
		err = errors.Join(
			fmt.Errorf("failed to decrypt chunk: %w", err),
			ErrIntegrityViolation,
		)
		return err
	}

	if len(r.buffer) == 0 {
		// nothing left to copy, can immediately return io.EOF to caller
		return io.EOF
	}

	return nil
}

func (r *DecryptingReader) readFinalChunkData() (int, error) {
	r.buffer = r.buffer[:0]

	sum := 0
	eof := false
	for {
		end := cap(r.buffer)
		if end > r.maxBufferLen {
			end = r.maxBufferLen
		}
		dst := r.buffer[sum:end]

		n, err := r.reader.Read(dst)
		sum += n
		if err != nil {
			if err == io.EOF {
				eof = true
				break
			}
			return 0, err
		}

		if len(r.buffer) == r.maxBufferLen {
			break
		}

		r.buffer = r.buffer[:sum]
		// assume we will do another copy of n items
		r.growBuffer(len(r.buffer) + n)
	}

	// filled the buffer up to max length but did not reach io.EOF.
	// this read checks for trailing data we can't process.
	if len(r.buffer) == r.maxBufferLen && !eof {
		tgt := make([]byte, 1)
		n, err := r.reader.Read(tgt)
		if n != 0 && err != io.EOF {
			return 0, ErrTooMuchData
		}
	}

	return sum, nil
}

// growBuffer grows the buffer to at least the provided capacity.
func (r *DecryptingReader) growBuffer(newCap int) {
	if cap(r.buffer) >= newCap {
		return
	}

	r.buffer = slices.Grow(r.buffer[:cap(r.buffer)], newCap-cap(r.buffer))
}

func copyAndZero(dst, src []byte) int {
	n := copy(dst, src)
	zero(src[:n])
	return n
}

func zero(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

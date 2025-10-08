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

package chunks_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"testing"

	"github.com/confidentsecurity/twoway/internal/chunks"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/stretchr/testify/require"
)

func TestEncryptingReader(t *testing.T) {
	const (
		key          = "00000000000000000000000000000000"
		nonce        = "000000000000"
		aeadOverhead = 16
	)

	// tests below only test the shape, actual decryption happens in TestDecryptingReader.
	tests := map[string]struct {
		r               io.Reader
		maxPlaintextLen int
		verifyOps       []verifyOp
	}{
		"ok, final chunk only, verify header": {
			r:               bytes.NewReader([]byte{}),
			maxPlaintextLen: 1, // min data chunk possible.
			verifyOps: []verifyOp{
				verifyReadChunkHeader(0),  // indicates final chunk
				verifyReadN(aeadOverhead), // aead overhead
				verifyEOF(),
				verifyEOF(), // check if eof is cached
			},
		},
		"ok, final chunk, one read": {
			r:               bytes.NewReader([]byte{}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadN(1 + aeadOverhead), // header + aead overhead
				verifyEOF(),
			},
		},
		"ok, single minimal data chunk, verify header": {
			r:               bytes.NewReader([]byte("a")),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(1 + aeadOverhead), // data + aead overhead
				verifyReadN(1 + aeadOverhead),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, single minimal data chunk, one read": {
			r:               bytes.NewReader([]byte("a")),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadN(2 + aeadOverhead), // header + data + aead overhead
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, multiple minimal data chunks, verify headers": {
			r:               bytes.NewReader([]byte("abc")),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(1 + aeadOverhead), // data + aead overhead
				verifyReadN(1 + aeadOverhead),
				verifyReadChunkHeader(1 + aeadOverhead), // data + aead overhead
				verifyReadN(1 + aeadOverhead),
				verifyReadChunkHeader(1 + aeadOverhead), // data + aead overhead
				verifyReadN(1 + aeadOverhead),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, multiple minimal data chunks, one read per chunk": {
			r:               bytes.NewReader([]byte("abc")),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadN(2 + aeadOverhead), // header + data + aead overhead
				verifyReadN(2 + aeadOverhead),
				verifyReadN(2 + aeadOverhead),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, multiple chunks of different sizes, verify headers": {
			r:               newHardcodedReads([]byte("a"), []byte("bc"), []byte("def")),
			maxPlaintextLen: 3,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(1 + aeadOverhead), // data + aead overhead
				verifyReadN(1 + aeadOverhead),
				verifyReadChunkHeader(2 + aeadOverhead), // data + aead overhead
				verifyReadN(2 + aeadOverhead),
				verifyReadChunkHeader(3 + aeadOverhead), // data + aead overhead
				verifyReadN(3 + aeadOverhead),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, multiple chunks of different sizes, one read per chunk": {
			r:               newHardcodedReads([]byte("a"), []byte("bc"), []byte("def")),
			maxPlaintextLen: 3,
			verifyOps: []verifyOp{
				verifyReadN(2 + aeadOverhead), // header + data + aead overhead
				verifyReadN(3 + aeadOverhead),
				verifyReadN(4 + aeadOverhead),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, single chunk with excess buffer size on read": {
			r:               bytes.NewReader([]byte("abc")),
			maxPlaintextLen: 3,
			verifyOps: []verifyOp{
				verifyReadNWithBufLen(4+aeadOverhead, 4+aeadOverhead+1),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, single chunk with max 1 byte header, verify header": {
			r:               bytes.NewReader(bytes.Repeat([]byte("a"), 63-aeadOverhead)),
			maxPlaintextLen: 63 - aeadOverhead,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(63), // data + aead overhead
				verifyReadN(63),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, single chunk with min 2 byte header, verify header": {
			r:               bytes.NewReader(bytes.Repeat([]byte("a"), 64-aeadOverhead)),
			maxPlaintextLen: 64 - aeadOverhead,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(64), // data + aead overhead
				verifyReadN(64),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		}, // update name of test
		"ok, single chunk with max 2 byte header, verify header": {
			r:               bytes.NewReader(bytes.Repeat([]byte("a"), 16383-aeadOverhead)),
			maxPlaintextLen: 16383 - aeadOverhead,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(16383), // data + aead overhead
				verifyReadN(16383),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, single chunk with min 4 byte header, verify header": {
			r:               bytes.NewReader(bytes.Repeat([]byte("a"), 16384-aeadOverhead)),
			maxPlaintextLen: 16384 - aeadOverhead,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(16384), // data + aead overhead
				verifyReadN(16384),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
		"ok, multiple chunks with different header lengths, verify headers": {
			r: newHardcodedReads(
				[]byte("a"), // 1 byte header length
				bytes.Repeat([]byte("a"), 65-aeadOverhead-2), // 2 byte header length
			),
			maxPlaintextLen: 65 - 2 - aeadOverhead,
			verifyOps: []verifyOp{
				verifyReadChunkHeader(1 + aeadOverhead), // data + aead overhead
				verifyReadN(1 + aeadOverhead),
				verifyReadChunkHeader(65 - 2), // data + aead overhead
				verifyReadN(65 - 2),
				// read the final chunk
				verifyReadN(1 + aeadOverhead),
				verifyEOF(),
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			block, err := aes.NewCipher([]byte(key))
			require.NoError(t, err)

			gcm, err := cipher.NewGCM(block)
			require.NoError(t, err)

			ctx, err := chunks.NewAEADContext(gcm, []byte(nonce))
			require.NoError(t, err)

			r, err := chunks.NewEncryptingReader(tc.r, ctx, tc.maxPlaintextLen)
			require.NoError(t, err)

			for _, op := range tc.verifyOps {
				op(t, r)
			}
		})
	}
}

func TestDecryptingReader(t *testing.T) {
	const (
		key          = "00000000000000000000000000000000"
		otherKey     = "10000000000000000000000000000000"
		nonce        = "000000000000"
		otherNonce   = "100000000000"
		aeadOverhead = 16
	)

	type readerFunc func(t *testing.T) io.Reader

	encReader := func(key, nonce string, ptR io.Reader, maxPlaintextLen int) readerFunc {
		return func(t *testing.T) io.Reader {
			t.Helper()

			block, err := aes.NewCipher([]byte(key))
			require.NoError(t, err)

			gcm, err := cipher.NewGCM(block)
			require.NoError(t, err)

			ctx, err := chunks.NewAEADContext(gcm, []byte(nonce))
			require.NoError(t, err)

			r, err := chunks.NewEncryptingReader(ptR, ctx, maxPlaintextLen)
			require.NoError(t, err)

			return r
		}
	}

	tamperReader := func(tamperFunc func([][]byte) [][]byte) readerFunc {
		return func(t *testing.T) io.Reader {
			t.Helper()

			const (
				plaintextChunkLen  = 1
				ciphertextChunkLen = plaintextChunkLen + aeadOverhead + 1
			)

			// read 3 same-sized chunks from the encrypted reader.
			r := encReader(key, nonce, bytes.NewReader([]byte("abc")), plaintextChunkLen)(t)

			raw, err := io.ReadAll(r)
			require.NoError(t, err)

			chunks := make([][]byte, 0)
			for i := 0; i < len(raw); i += ciphertextChunkLen {
				chunks = append(chunks, raw[i:i+ciphertextChunkLen])
			}

			// tamper with the chunks.
			chunks = tamperFunc(chunks)

			// format them for input
			input := make([]byte, 0)
			for _, chunk := range chunks {
				input = append(input, chunk...)
			}

			return bytes.NewReader(input)
		}
	}

	finalChunkWithDataReader := func(plaintext, trailing []byte) readerFunc {
		return func(t *testing.T) io.Reader {
			t.Helper()

			buf := &bytes.Buffer{}
			// manually construct a final chunk with data in it.
			intBytes := quicvarint.Append(nil, 0)

			_, err := buf.Write(intBytes)
			require.NoError(t, err)

			block, err := aes.NewCipher([]byte(key))
			require.NoError(t, err)

			gcm, err := cipher.NewGCM(block)
			require.NoError(t, err)

			data := gcm.Seal(nil, []byte(nonce), plaintext, []byte("final"))
			_, err = buf.Write(data)
			require.NoError(t, err)

			// trailing data will result in an error, but is required for certain test cases
			if len(trailing) > 0 {
				_, err := buf.Write(trailing)
				require.NoError(t, err)
			}

			return buf
		}
	}

	tests := map[string]struct {
		readerFunc      readerFunc
		maxPlaintextLen int
		verifyOps       []verifyOp
	}{
		"ok, final chunk only, returns eof": {
			readerFunc:      encReader(key, nonce, bytes.NewReader([]byte("")), 1),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyEOF(),
				verifyEOF(), // repeat to check if eof is cached.
			},
		},
		"ok, single minimal chunk": {
			readerFunc:      encReader(key, nonce, bytes.NewReader([]byte("a")), 1),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyEOF(),
			},
		},
		"ok, multiple minimal chunks": {
			readerFunc:      encReader(key, nonce, bytes.NewReader([]byte("abc")), 1),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyRead([]byte("b")),
				verifyRead([]byte("c")),
				verifyEOF(),
			},
		},
		"ok, multiple chunks of different sizes": {
			readerFunc:      encReader(key, nonce, newHardcodedReads([]byte("a"), []byte("bc"), []byte("def")), 3),
			maxPlaintextLen: 3,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyRead([]byte("bc")),
				verifyRead([]byte("def")),
				verifyEOF(),
			},
		},
		"ok, single chunk in multiple reads": {
			readerFunc:      encReader(key, nonce, bytes.NewReader([]byte("abc")), 3),
			maxPlaintextLen: 3,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyRead([]byte("b")),
				verifyRead([]byte("c")),
				verifyEOF(),
			},
		},
		"ok, single chunk with 2 byte header": {
			readerFunc:      encReader(key, nonce, bytes.NewReader(bytes.Repeat([]byte("a"), 65-aeadOverhead-2)), 65-aeadOverhead-2),
			maxPlaintextLen: 65 - aeadOverhead - 2,
			verifyOps: []verifyOp{
				verifyRead(bytes.Repeat([]byte("a"), 65-aeadOverhead-2)),
				verifyEOF(),
			},
		},
		"ok, data in final chunk": {
			readerFunc:      finalChunkWithDataReader([]byte("a"), nil),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyEOF(),
			},
		},
		"ok, read data in final chunk, data exceeds initial buffer": {
			readerFunc:      finalChunkWithDataReader([]byte("abc"), nil),
			maxPlaintextLen: 3,
			verifyOps: []verifyOp{
				verifyRead([]byte("abc")),
				verifyEOF(),
			},
		},
		"ok, read data in final chunk in multiple reads": {
			readerFunc:      finalChunkWithDataReader([]byte("abc"), nil),
			maxPlaintextLen: 3,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyRead([]byte("b")),
				verifyRead([]byte("c")),
				verifyEOF(),
			},
		},
		"fail, data in final chunk does not fit in maximum buffer": {
			readerFunc:      finalChunkWithDataReader([]byte("ab"), nil),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(2, chunks.ErrTooMuchData),
			},
		},
		"fail, chunk does not fit in maximum buffer": {
			readerFunc:      encReader(key, nonce, bytes.NewReader([]byte("ab")), 2),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(2, chunks.ErrTooMuchData),
			},
		},
		"fail, key mismatch": {
			readerFunc:      encReader(otherKey, nonce, bytes.NewReader([]byte("a")), 1),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, nonce mismatch": {
			readerFunc:      encReader(key, otherNonce, bytes.NewReader([]byte("a")), 1),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, eof mid data": {
			readerFunc: tamperReader(func(chunks [][]byte) [][]byte {
				// return only the first chunk, and cut it in half
				chunks[0] = chunks[0][:8]
				return [][]byte{chunks[0]}
			}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation, io.ErrUnexpectedEOF),
			},
		},
		"fail, ciphertext tampered with": {
			readerFunc: tamperReader(func(chunks [][]byte) [][]byte {
				chunks[0][1]++
				return chunks
			}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, data chunk auth tag tampered with": {
			readerFunc: tamperReader(func(chunks [][]byte) [][]byte {
				chunks[0][2]++
				return chunks
			}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, final chunk auth tag tampered with": {
			readerFunc: tamperReader(func(chunks [][]byte) [][]byte {
				chunks[3][1]++
				return chunks
			}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyRead([]byte("b")),
				verifyRead([]byte("c")),
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, chunk repeated": {
			readerFunc: tamperReader(func(chunks [][]byte) [][]byte {
				chunks[1] = chunks[0]
				return chunks
			}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyRead([]byte("a")),
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, chunk skipped": {
			readerFunc: tamperReader(func(chunks [][]byte) [][]byte {
				return chunks[1:]
			}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, chunks reordered": {
			readerFunc: tamperReader(func(chunks [][]byte) [][]byte {
				c := chunks[0]
				chunks[0] = chunks[1]
				chunks[1] = c
				return chunks
			}),
			maxPlaintextLen: 1,
			verifyOps: []verifyOp{
				verifyReadErrorIs(1, chunks.ErrIntegrityViolation),
			},
		},
		"fail, trailing data after final chunk data": {
			readerFunc:      finalChunkWithDataReader([]byte("a"), []byte("a")), // second a is not encrypted
			maxPlaintextLen: 2,                                                  // enough space in buffer for the trailing data
			verifyOps: []verifyOp{
				verifyReadErrorIs(2, chunks.ErrIntegrityViolation),
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			block, err := aes.NewCipher([]byte(key))
			require.NoError(t, err)

			gcm, err := cipher.NewGCM(block)
			require.NoError(t, err)

			ctx, err := chunks.NewAEADContext(gcm, []byte(nonce))
			require.NoError(t, err)

			r, err := chunks.NewDecryptingReader(tc.readerFunc(t), ctx, 1, tc.maxPlaintextLen)
			require.NoError(t, err)

			for _, op := range tc.verifyOps {
				op(t, r)
			}
		})
	}
}

// verifyOp is a helper function for verifiying streams of data from readers.
// these verification operations are designed to be executed in sequence.
type verifyOp func(t *testing.T, r io.Reader)

func verifyReadChunkHeader(wantLen int) verifyOp {
	return func(t *testing.T, r io.Reader) {
		t.Helper()

		quicReader := quicvarint.NewReader(r)
		gotLen, err := quicvarint.Read(quicReader)
		require.NoError(t, err)
		require.Equal(t, uint64(wantLen), gotLen)
	}
}

func verifyReadN(n int) verifyOp {
	return verifyReadNWithBufLen(n, n)
}

func verifyReadNWithBufLen(wantN, bufLen int) verifyOp {
	return func(t *testing.T, r io.Reader) {
		t.Helper()

		got := make([]byte, bufLen)
		n, err := r.Read(got)
		require.NoError(t, err)
		require.Equal(t, wantN, n)
	}
}

func verifyReadWithBufLen(want []byte, bufLen int) verifyOp {
	return func(t *testing.T, r io.Reader) {
		t.Helper()

		got := make([]byte, bufLen)
		n, err := r.Read(got)
		require.NoError(t, err)
		require.Equal(t, len(want), n)
		require.Equal(t, want, got[:n])
	}
}

func verifyReadErrorIs(bufLen int, wantErrs ...error) verifyOp {
	return func(t *testing.T, r io.Reader) {
		t.Helper()

		got := make([]byte, bufLen)
		n, err := r.Read(got)
		require.Error(t, err)

		for _, wantErr := range wantErrs {
			require.ErrorIs(t, err, wantErr)
		}

		require.Zero(t, n)
	}
}

func verifyRead(want []byte) verifyOp {
	return func(t *testing.T, r io.Reader) {
		t.Helper()

		verifyReadWithBufLen(want, len(want))(t, r)
	}
}

func verifyEOF() verifyOp {
	return func(t *testing.T, r io.Reader) {
		t.Helper()

		got := make([]byte, 1) // some space to make a mistake
		n, err := r.Read(got)
		require.ErrorIs(t, err, io.EOF)
		require.Equal(t, 0, n)
		require.Equal(t, got, []byte{0x00})
	}
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

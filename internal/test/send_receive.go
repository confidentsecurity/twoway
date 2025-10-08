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

package test

import "bytes"

// SendReceiveTest is test data for a send and receive test case.
type SendReceiveTest struct {
	Plaintext            []byte
	MaxPlaintextChunkLen int
	ChunkedLen           int
	UnchunkedLen         int
}

// SendReceiveTests returns test cases for send and receive tests.
func SendReceiveTests() map[string]SendReceiveTest {
	const finalChunkCiphertextLen = 16 + 1 // tag and length.
	return map[string]SendReceiveTest{
		"empty byte slice": {
			Plaintext:            []byte{},
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           finalChunkCiphertextLen,
			UnchunkedLen:         16,
		},
		"single byte": {
			Plaintext:            []byte("a"),
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           16 + 1 + 1 + finalChunkCiphertextLen,
			UnchunkedLen:         16 + 1,
		},
		"several bytes": {
			Plaintext:            []byte("abc"),
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           16 + 1 + 3 + finalChunkCiphertextLen,
			UnchunkedLen:         16 + 3,
		},
		"1 chunk": {
			Plaintext:            bytes.Repeat([]byte("a"), 1006), // 1024-16-2
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           1006 + 16 + 2 + finalChunkCiphertextLen,
			UnchunkedLen:         16 + 1006,
		},
		"1 chunk + partial": {
			Plaintext:            bytes.Repeat([]byte("a"), 1006+494), // 1024-16-2 + 512-16-2
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           (1006 + 16 + 2) + (494 + 16 + 2) + finalChunkCiphertextLen,
			UnchunkedLen:         16 + 1006 + 494,
		},
		"2 chunks": {
			Plaintext:            bytes.Repeat([]byte("a"), 1006*2),
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           (16+2+1006)*2 + finalChunkCiphertextLen,
			UnchunkedLen:         16 + 1006*2,
		},
		"3 chunks": {
			Plaintext:            bytes.Repeat([]byte("a"), 1006*3),
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           (16+2+1006)*3 + finalChunkCiphertextLen,
			UnchunkedLen:         16 + 1006*3,
		},
		"10 chunks": {
			Plaintext:            bytes.Repeat([]byte("a"), 1006*10),
			MaxPlaintextChunkLen: 1006,
			ChunkedLen:           (16+2+1006)*10 + finalChunkCiphertextLen,
			UnchunkedLen:         16 + 1006*10,
		},
	}
}

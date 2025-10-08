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

type opConfig struct {
	chunked               bool
	initialChunkBufferLen int
	// maxChunkPlaintextLen is the maximum number of plaintext bytes that are stored in a chunk.
	// Excludes chunking and sealing overhead.
	maxChunkPlaintextLen int
}

func defaultOpenerConfig() *opConfig {
	return &opConfig{
		chunked: false,
		// initialBufferLen is only used by openers.
		initialChunkBufferLen: 4096,
		// Default to the minimum an OHTTP implementation must support.
		//
		// https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-response-encapsulation
		//
		// Implementations MUST support receiving chunks that contain 2^14 (16384) octets of data
		// prior to encapsulation. Senders of chunks SHOULD limit their chunks to this size,
		// unless they are aware of support for larger sizes by the receiving party.
		maxChunkPlaintextLen: 16384,
	}
}

func defaultSealerConfig() *opConfig {
	return &opConfig{
		chunked:               false,
		initialChunkBufferLen: 0,
		maxChunkPlaintextLen:  4096,
	}
}

// Option is an option for a sealer or opener.
type Option func(*opConfig) error

// WithInitialChunkBufferLen provides a custom initial buffer length for chunked opening operations.
//
// The provided length is a plaintext length, the actual buffer will be slightly larger to fit AEAD overhead.
//
// This option is only supported when using openers.
func WithInitialChunkBufferLen(initialBufferLen int) Option {
	return func(oc *opConfig) error {
		oc.initialChunkBufferLen = initialBufferLen
		return nil
	}
}

// WithMaxChunkPlaintextLen specifies the maximum length of plaintexts chunks. The maximum
// length of these chunks will be slightly larger to fit a chunk header and AEAD overhead.
//
// Both sealers and openers accept this option.
//
// Sealers will limit the chunks they generate to the maximum length. Openers will
// limit their receiving buffers to the maximum length.
//
// The default values for sealers/openers are suitable for use with OHTTP. If you are using OHTTP
// keep in mind the Chunked OHTTP RFC:
//
// https://www.ietf.org/archive/id/draft-ietf-ohai-chunked-ohttp-03.html#name-response-encapsulation.
//
//	Implementations MUST support receiving chunks that contain 2^14 (16384) octets of data prior
//	to encapsulation. Senders of chunks SHOULD limit their chunks to this size, unless they are
//	aware of support for larger sizes by the receiving party.
func WithMaxChunkPlaintextLen(maxChunkContentLen int) Option {
	return func(oc *opConfig) error {
		oc.maxChunkPlaintextLen = maxChunkContentLen
		return nil
	}
}

// EnableChunking splits the message into chunks that can be incrementely delivered. Use
// [WithMaxChunkPlaintextLen] to change the length of the chunks.
func EnableChunking() Option {
	return func(oc *opConfig) error {
		oc.chunked = true
		return nil
	}
}

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

import "errors"

var (
	// ErrTooMuchData indicates data can't fit into a buffer.
	ErrTooMuchData = errors.New("too much data")
	// ErrIntegrityViolation indicates data can't be decrypted properly.
	ErrIntegrityViolation = errors.New("integrity is violated")
	// ErrNonceReuse indicates a counter can't be increased without re-using a chunk nonce.
	ErrNonceReuse = errors.New("cannot increase counter without re-using chunk nonce")
	// ErrClosed indicates something was closed.
	ErrClosed = errors.New("closed")
)

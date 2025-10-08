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
	"encoding/binary"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// RequestHeader is the OHTTP Header added to request messages.
type RequestHeader struct {
	KeyID  byte
	KemID  hpke.KEM
	KDFID  hpke.KDF
	AEADID hpke.AEAD
}

// BinaryRequestHeaderLen is the binary encoded length of an OHTTP Request Header.
const BinaryRequestHeaderLen = 1 + 2 + 2 + 2

// NewRequestHeaderForSuite creates a new request header for the given suite and key ID.
func NewRequestHeaderForSuite(suite HPKESuite, keyID byte) RequestHeader {
	kemID, kdfID, aeadID := suite.Params()
	return RequestHeader{
		KeyID:  keyID,
		KemID:  kemID,
		KDFID:  kdfID,
		AEADID: aeadID,
	}
}

// ParseRequestHeaderFrom parses the first 7 bytes of the ct as a Requestheader.
// ParseRequestHeaderFrom leaves ct untouched.
//
// Use this function if you need to determine the suite and key id before instantiating
// a request receiver.
func ParseRequestHeaderFrom(ct []byte) (RequestHeader, error) {
	h := RequestHeader{}
	err := h.UnmarshalBinary(ct)
	return h, err
}

// MarshalBinary marshals the RequestHeader in the OHTTP wire format.
func (h RequestHeader) MarshalBinary() ([]byte, error) {
	// hdr = concat(encode(1, key_id),
	//             encode(2, kem_id),
	//             encode(2, kdf_id),
	//             encode(2, aead_id))
	hdr := make([]byte, BinaryRequestHeaderLen)
	hdr[0] = h.KeyID
	binary.BigEndian.PutUint16(hdr[1:3], uint16(h.KemID))
	binary.BigEndian.PutUint16(hdr[3:5], uint16(h.KDFID))
	binary.BigEndian.PutUint16(hdr[5:7], uint16(h.AEADID))

	return hdr, nil
}

// UnmarshalBinary unmarshals the RequestHeader from the OHTTP wire format.
func (h *RequestHeader) UnmarshalBinary(b []byte) error {
	if len(b) < BinaryRequestHeaderLen {
		return fmt.Errorf("header of invalid length, got %d want %d", len(b), BinaryRequestHeaderLen)
	}

	kemID := hpke.KEM(binary.BigEndian.Uint16(b[1:3]))
	kdfID := hpke.KDF(binary.BigEndian.Uint16(b[3:5]))
	aeadID := hpke.AEAD(binary.BigEndian.Uint16(b[5:7]))

	if !kemID.IsValid() {
		return fmt.Errorf("invalid KEM: %v", kemID)
	}

	if !kdfID.IsValid() {
		return fmt.Errorf("invalid KDF: %v", kdfID)
	}

	if !aeadID.IsValid() {
		return fmt.Errorf("invalid AEAD: %v", aeadID)
	}

	h.KeyID = b[0]
	h.KemID = kemID
	h.KDFID = kdfID
	h.AEADID = aeadID

	return nil
}

func info(hdr, mediaType []byte) []byte {
	// info = concat(encode_str("message/bhttp request"),
	//              encode(1, 0),
	//              hdr)
	info := bytes.Clone(mediaType)
	info = append(info, 0x00)
	info = append(info, hdr...)

	return info
}

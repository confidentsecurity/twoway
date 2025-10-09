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

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
)

// HPKESuite is a HPKE suite. Defined as an interface to allow the use of non-circl
// HPKE implementations in this package.
type HPKESuite interface {
	NewSender(pubKey kem.PublicKey, info []byte) (HPKESender, error)
	NewReceiver(privKey kem.PrivateKey, info []byte) (HPKEReceiver, error)
	Params() (hpke.KEM, hpke.KDF, hpke.AEAD)
}

// HPKEReceiver is a HPKE receiver. Defined as an interface to allow the use of non-circl
// HPKE implementations in this package.
type HPKEReceiver interface {
	Setup(enc []byte) (HPKEOpener, error)
}

// HPKESender is a HPKE sender. Defined as an interface to allow the use of non-circl
// HPKE implementations in this package.
type HPKESender interface {
	Setup(rnd io.Reader) ([]byte, HPKESealer, error)
}

// HPKEExporter is a HPKE exporter. Defined as an interface to allow the use of non-circl
// HPKE implementations in this package.
type HPKEExporter interface {
	Export(exporterContext []byte, length uint) []byte
}

// HPKEOpener is a HPKE opener. Defined as an interface to allow the use of non-circl
// HPKE implementations in this package.
type HPKEOpener interface {
	HPKEExporter
	Open(ct, aad []byte) ([]byte, error)
}

// HPKESealer is a HPKE sealer. Defined as an interface to allow the use of non-circl
// HPKE implementations in this package.
type HPKESealer interface {
	HPKEExporter
	Seal(pt, aad []byte) ([]byte, error)
}

// AdaptCirclHPKESuite adapts a Cloudflare Circl HPKE suite to a HPKE Suite that can
// be used with this package.
func AdaptCirclHPKESuite(suite hpke.Suite) HPKESuite {
	return circlHPKESuite{suite}
}

type circlHPKESuite struct {
	suite hpke.Suite
}

var _ HPKESuite = &circlHPKESuite{}

func (s circlHPKESuite) NewSender(pubKey kem.PublicKey, info []byte) (HPKESender, error) {
	sender, err := s.suite.NewSender(pubKey, info)
	return circlHPKESender{sender}, err
}
func (s circlHPKESuite) NewReceiver(privKey kem.PrivateKey, info []byte) (HPKEReceiver, error) {
	receiver, err := s.suite.NewReceiver(privKey, info)
	return circlHPKEReceiver{receiver}, err
}

func (s circlHPKESuite) Params() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return s.suite.Params()
}

type circlHPKESender struct {
	sender *hpke.Sender
}

func (s circlHPKESender) Setup(rnd io.Reader) ([]byte, HPKESealer, error) {
	enc, sealer, err := s.sender.Setup(rnd)
	return enc, sealer, err
}

type circlHPKEReceiver struct {
	receiver *hpke.Receiver
}

func (r circlHPKEReceiver) Setup(encapKey []byte) (HPKEOpener, error) {
	opener, err := r.receiver.Setup(encapKey)
	return opener, err
}

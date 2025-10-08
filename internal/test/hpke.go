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

import (
	"testing"

	"github.com/cloudflare/circl/hpke"
	"github.com/stretchr/testify/require"
)

// SetupHPKESenderReceiver sets up a HPKE sender and receiver with a random keypair.
func SetupHPKESenderReceiver(t *testing.T) (*hpke.Sender, *hpke.Receiver) {
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	kdfID, _, _ := suite.Params()

	publicKey, privateKey, err := kdfID.Scheme().GenerateKeyPair()
	require.NoError(t, err)

	sender, err := suite.NewSender(publicKey, []byte("test-context"))
	require.NoError(t, err)

	receiver, err := suite.NewReceiver(privateKey, []byte("test-context"))
	require.NoError(t, err)

	return sender, receiver
}

// SetupHPKESendersReceivers sets up n HPKE senders and receivers with random keypairs.
func SetupHPKESendersReceivers(t *testing.T, n int) ([]*hpke.Sender, []*hpke.Receiver) {
	senders := []*hpke.Sender{}
	receivers := []*hpke.Receiver{}
	for range n {
		s, rcv := SetupHPKESenderReceiver(t)
		senders = append(senders, s)
		receivers = append(receivers, rcv)
	}

	return senders, receivers
}

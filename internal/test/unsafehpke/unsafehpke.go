package unsafehpke

import (
	"sync"

	"github.com/cloudflare/circl/kem"
)

type InjectableXKEMPrivateKey struct {
	mu    *sync.Mutex
	key   kem.PrivateKey
	valid bool
}

var InjectedXKEMPrivateKey = InjectableXKEMPrivateKey{
	mu:    &sync.Mutex{},
	key:   nil,
	valid: false,
}

func (k *InjectableXKEMPrivateKey) Setup(pk kem.PrivateKey) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.key = pk
	k.valid = true
}

func (k *InjectableXKEMPrivateKey) Consume() (kem.PrivateKey, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.valid {
		k.valid = false
		return k.key, true
	}

	return nil, false
}

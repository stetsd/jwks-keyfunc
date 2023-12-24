package jwks_keyfunc

import (
	"crypto/rsa"
	"math/big"
)

const (
	// ktyRSA (key type) parameter identifies the cryptographic algorithm
	// It located in JWT header
	ktyRSA = "RSA"
)

// RSA try to convert JWK to RSA public key
func (t *JWK) RSA() (*rsa.PublicKey, error) {
	if t.Exp == "" || t.Mod == "" {
		return nil, ErrReqComponents
	}

	exp, err := componentToBase64(t.Exp)
	if err != nil {
		return nil, err
	}
	mod, err := componentToBase64(t.Mod)
	if err != nil {
		return nil, err
	}

	result := &rsa.PublicKey{}

	result.N = big.NewInt(0).SetBytes(mod)
	result.E = int(big.NewInt(0).SetBytes(exp).Uint64())

	return result, nil
}

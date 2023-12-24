package jwks_keyfunc

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/golang-jwt/jwt/v5"
)

// JWKS - JSON web key set.
type JWKS struct {
	rwm  sync.RWMutex
	keys map[string]parsedJWK
}

type BaseJWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK - JSON web key, for more information see there https://openid.net/specs/draft-jones-json-web-key-03.html.
type JWK struct {
	// The alg member identifies the cryptographic algorithm family used with the key.
	Alg string `json:"alg"`
	// The exp member contains the exponent value for the RSA public key.
	// It is represented as the base64url encoding of the value's big endian representation.
	Exp string `json:"e"`
	// The kid (Key ID) member can be used to match a specific key. This can be used, for instance,
	// to choose among a set of keys within the JWK during key rollover.
	Kid string `json:"kid"`
	// The "kty" (key type) parameter identifies the cryptographic algorithm
	// family used with the key, such as "RSA" or "EC".
	Kty string `json:"kty"`
	// The mod member contains the modulus value for the RSA public key.
	Mod string `json:"n"`
	// The use member identifies the intended use of the key.
	// Values defined by this specification are sig (signature) and enc (encryption).
	// Other values MAY be used. The use value is case sensitive. This member is OPTIONAL.
	Use string `json:"use"`
}

type parsedJWK struct {
	pk  any
	alg string
	use string
}

func NewFromJSONString(jwksString string) (*JWKS, error) {
	var rawJWKS BaseJWKS

	err := json.Unmarshal([]byte(jwksString), &rawJWKS)
	if err != nil {
		return nil, err
	}

	result := &JWKS{
		keys: make(map[string]parsedJWK, len(rawJWKS.Keys)),
	}

	for _, key := range rawJWKS.Keys {
		var pk any

		switch key.Kty {
		case ktyRSA:
			pk, err = key.RSA()
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: %q", ErrJWKAlgNotSupported, key.Kty)
		}

		result.keys[key.Kid] = parsedJWK{
			alg: key.Alg,
			use: key.Use,
			pk:  pk,
		}

	}

	return nil, nil
}

func (j *JWKS) KeyFunc(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"]
	if !ok {
		return nil, ErrReqKid
	}

	kidRes, ok := kid.(string)
	if !ok {
		return nil, ErrKidConvert
	}

	alg, ok := token.Header["alg"]
	if !ok {
		return nil, ErrReqAlg
	}

	algRes, ok := alg.(string)
	if !ok {
		return nil, ErrAlgConvert
	}

	return j.getPublicKey(kidRes, algRes)
}

func (j *JWKS) getPublicKey(kid, alg string) (interface{}, error) {
	j.rwm.RLock()

	pk, ok := j.keys[kid]

	j.rwm.RUnlock()

	if !ok {
		return nil, ErrPKNotFound
	}

	if pk.alg != "" && pk.alg != alg {
		return nil, ErrAlgNotSupported
	}

	return pk.pk, nil
}

package jwks_keyfunc

import "errors"

var (
	ErrJWKAlgNotSupported = errors.New("jwk algorithm type not supported")
	ErrReqComponents      = errors.New("required component not found to create public key")
	ErrReqKid             = errors.New("kid component not found in provided token")
	ErrKidConvert         = errors.New("kid has wrong type")
	ErrReqAlg             = errors.New("alg component not found in provided token")
	ErrAlgConvert         = errors.New("alg has wrong type")
	ErrPKNotFound         = errors.New("jwk not found for token kid")
	ErrAlgNotSupported    = errors.New("alg from token not supported")
)

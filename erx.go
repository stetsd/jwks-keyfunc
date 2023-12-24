package jwks_keyfunc

import "errors"

var (
	ErrJWKAlgNotSupported = errors.New("jwk algorithm type not supported")
	ErrReqComponents      = errors.New("required component not found to create public key")
)

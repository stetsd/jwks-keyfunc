package jwks_keyfunc

import (
	"encoding/base64"
	"strings"
)

func componentToBase64(component string) ([]byte, error) {
	component = strings.TrimRight(component, "=")

	return base64.RawURLEncoding.DecodeString(component)
}

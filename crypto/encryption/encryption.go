package encryption

import "errors"

var ErrInvalidKeyType = errors.New("invalid key type provided")
var ErrCiphertextTooShort = errors.New("ciphertext too short")

type Encryption interface {
	Encrypt(plaintext []byte, key interface{}) (string, error)
	Decrypt(ciphertext string, key interface{}) ([]byte, error)
}

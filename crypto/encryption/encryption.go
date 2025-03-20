package encryption

import "errors"

// ErrInvalidKeyType is returned when the provided key does not match the expected type.
var ErrInvalidKeyType = errors.New("invalid key type provided")

// ErrCiphertextTooShort is returned when the ciphertext is too short to contain a valid nonce.
var ErrCiphertextTooShort = errors.New("ciphertext too short")

// Encryption defines a common interface for encryption implementations.
// It allows for different encryption schemes (e.g., symmetric or hybrid) to be used interchangeably.
type Encryption interface {
	// Encrypt takes a plaintext byte slice and a key (of any type) to produce an encrypted string.
	// The key must be of a type that the implementation expects.
	Encrypt(plaintext []byte, key interface{}) (string, error)

	// Decrypt takes an encrypted string and a key (of any type) to recover the original plaintext.
	// The key must be of a type that the implementation expects.
	Decrypt(ciphertext string, key interface{}) ([]byte, error)
}

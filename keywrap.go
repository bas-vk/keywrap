// Keywrap algorithms are a class of symmetric encryption algorithms designed to
// encapsulate (encrypt) cryptographic key material. The algorithms are not
// limited to key material and input data is therefore referred to as keydata.
package keywrap

// Identifies a particular key wrap algorithm which is implemented in another
// package
type WrapAlgorithm uint

const (
	RFC3394 WrapAlgorithm = iota // import github.com/basvk/keywrap/rfc3394
	maxAlgorithms
)

// holds builder functions for key wrap algorithm implementations
var wrapAlgorithms = make([]func(key []byte) (KeyWrapper, error), maxAlgorithms)

// register a builder function which can create a wrap algorithm implementation
// must be called from the init method in implementation packages
func RegisterWrapAlgorithm(a WrapAlgorithm, builder func(key []byte) (KeyWrapper, error)) {
	if a > maxAlgorithms {
		panic("register building function for unknown wrap algorithm")
	}
	wrapAlgorithms[a] = builder
}

// create a wrap algorithm implementation
func (a WrapAlgorithm) New(key []byte) (KeyWrapper, error) {
	return wrapAlgorithms[a](key)
}

// KeyWrapper is the interface implemented by an object that can wrap keydata.
type KeyWrapper interface {
	// Wraps the given keydata with the given key
	Wrap(keydata []byte) (ciphertext []byte, err error)

	// Unwraps the given ciphertext with the given key back to keydata
	Unwrap(ciphertext []byte) (keydata []byte, err error)
}

// The rfc3394 package is an implementation of the key wrapping algorithm as
// described in RFC 3393. It uses the AES block cipher as a primitive to convert
// a chuck of key data to cipher text and back. See for more information
// http://www.ietf.org/rfc/rfc3394.txt or
// http://csrc.nist.gov/groups/ST/toolkit/documents/kms/key-wrap.pdf
package rfc3394

import (
	"crypto/aes"
	"errors"
	"github.com/keywrap"
)

func init() {
	keywrap.RegisterWrapAlgorithm(keywrap.RFC3394, New)
}

// represents the partial evaluation of a wrap/unwrap operation
type rfc3394KeyWrap struct {
	n   int
	iv  []byte
	r   [][]byte
	key []byte
}

// New returns a new key wrapper which uses AES as the primitive building block.
func New(key []byte) (keywrap.KeyWrapper, error) {

	l := len(key)
	if l != 16 && l != 24 && l != 32 {
		return nil, errors.New("Invalid key size given, must be 128, 192 or 256 bits")
	}

	akw := rfc3394KeyWrap{}
	akw.key = make([]byte, l)
	copy(akw.key, key)
	return &akw, nil
}

// Wrap the given keydata with the given key. The keydata must be a multiple of
// 64 bits, the key must be 128, 192 or 256 bits.
func (w *rfc3394KeyWrap) Wrap(keydata []byte) (ciphertext []byte, err error) {
	w.initializeForWrap(keydata)

	if err = w.calculateIntermediateValuesForWrap(); err == nil {
		ciphertext = w.outputWrap()
	}

	return
}

// Unwrap the given ciphertext with the given key. It will perform an integrity
// check afterwards to determine if the keydata wasn't altered.
func (w *rfc3394KeyWrap) Unwrap(ciphertext []byte) (keydata []byte, err error) {
	w.initializeForUnwrap(ciphertext)

	if err = w.calculateIntermediateValuesForUnwrap(); err != nil {
		return
	}

	if !w.integrityCheck() {
		return nil, errors.New("Integrity check failed")
	}

	keydata = w.outputUnwrap()
	return
}

// check if the IV after unwrapping is the default one
func (w *rfc3394KeyWrap) integrityCheck() bool {
	for _, b := range w.iv {
		if b != 0xa6 {
			return false
		}
	}
	return true
}

/*
Set A = IV, an initial value (see 2.2.3)
For i = 1 to n
	R[i] = P[i]
*/
func (w *rfc3394KeyWrap) initializeForWrap(plaintext []byte) {
	w.n = len(plaintext) / 8
	if len(plaintext)%8 > 0 {
		w.n += 1
	}

	w.iv = make([]byte, 8)
	for i := 0; i < 8; i++ {
		w.iv[i] = 0xa6 // default IV = 0xa6a6a6a6a6a6a6a6
	}

	w.r = make([][]byte, w.n)
	for i := 0; i < w.n; i++ {
		w.r[i] = make([]byte, 8)
		copy(w.r[i], plaintext[8*i:8*(1+i)])
	}
}

func xor(a []byte, b uint64) {
	for x := uint(0); x < 8; x++ {
		b >>= (8 * x)
		a[7-x] = a[7-x] ^ byte(b&0xff)
	}
}

/*
For j = 0 to 5
	For i=1 to n
		B = AES(K, A | R[i])
		A = MSB(64, B) ^ t where t = (n*j)+i
		R[i] = LSB(64, B)
*/
func (w *rfc3394KeyWrap) calculateIntermediateValuesForWrap() error {
	aes, err := aes.NewCipher(w.key)
	if err != nil {
		return err
	}

	for j := 0; j <= 5; j++ {
		for i := 0; i < w.n; i++ {

			buf := make([]byte, len(w.iv)+len(w.r[i]))
			b := make([]byte, aes.BlockSize())
			copy(buf, w.iv)
			copy(buf[8:], w.r[i])
			aes.Encrypt(b, buf)

			copy(w.iv, b[:8])
			copy(w.r[i], b[8:])

			t := uint64(w.n*j) + uint64(i+1)
			xor(w.iv, t)
		}
	}

	return nil
}

/*
Set C[0] = A
For i = 1 to n
    C[i] = R[i]
*/
func (w *rfc3394KeyWrap) outputWrap() []byte {
	c := make([]byte, (1+w.n)*8)
	copy(c, w.iv)
	for i, o := range w.r {
		copy(c[8*(1+i):], o)
	}
	return c
}

/*
Set A[s] = C[0] where s = 6n
	For i = 1 to n
		R[s][i] = C[i]
*/
func (w *rfc3394KeyWrap) initializeForUnwrap(ciphertext []byte) {
	w.n = len(ciphertext)/8 - 1

	w.iv = make([]byte, 8)
	copy(w.iv, ciphertext[:8])

	w.r = make([][]byte, w.n)
	for i := 0; i < w.n; i++ {
		w.r[i] = make([]byte, 8)
		copy(w.r[i], ciphertext[8+8*i:8*(i+2)])
	}
}

/*
For t = s to 1
    A[t-1] = MSB(64, AES-1(K, ((A[t] ^ t) | R[t][n]))
    R[t-1][1] = LSB(64, AES-1(K, ((A[t]^t) | R[t][n]))
    For i = 2 to n
        R[t-1][i] = R[t][i-1]
*/
func (w *rfc3394KeyWrap) calculateIntermediateValuesForUnwrap() error {
	aes, err := aes.NewCipher(w.key)
	if err != nil {
		return err
	}

	for j := 5; j >= 0; j-- {
		for i := (w.n - 1); i >= 0; i-- {

			t := uint64(w.n*j) + uint64(i+1)
			xor(w.iv, t)

			buf := make([]byte, len(w.iv)+len(w.r[i]))
			b := make([]byte, aes.BlockSize())

			copy(buf, w.iv)
			copy(buf[8:], w.r[i])

			aes.Decrypt(b, buf)
			copy(w.iv, b[:8])
			copy(w.r[i], b[8:])
		}
	}

	return nil
}

/*
For i = 1 to n
	P[i] = R[0][i]
*/
func (w *rfc3394KeyWrap) outputUnwrap() []byte {
	p := make([]byte, 8*w.n)
	for i, o := range w.r {
		copy(p[8*i:], o)
	}
	return p
}

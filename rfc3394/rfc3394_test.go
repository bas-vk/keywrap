package rfc3394

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type TestCase struct {
	// plaintext in case of wrap, ciphertext in case of unwrap
	Input []byte
	// expected output of wrap/unwrap action
	Expected []byte
}

func buildTestCase(keyData, output []byte) (*TestCase, error) {

	tc := &TestCase{
		make([]byte, hex.DecodedLen(len(keyData))),
		make([]byte, hex.DecodedLen(len(output))),
	}

	if _, err := hex.Decode(tc.Input, keyData); err != nil {
		return nil, err
	}

	if _, err := hex.Decode(tc.Expected, output); err != nil {
		return nil, err
	}

	return tc, nil
}

var key128 []byte
var key192 []byte
var key256 []byte

func init() {
	key128 = make([]byte, hex.DecodedLen(len("000102030405060708090A0B0C0D0E0F")))
	key192 = make([]byte, hex.DecodedLen(len("000102030405060708090A0B0C0D0E0F1011121314151617")))
	key256 = make([]byte, hex.DecodedLen(len("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")))

	hex.Decode(key128, []byte("000102030405060708090A0B0C0D0E0F"))
	hex.Decode(key192, []byte("000102030405060708090A0B0C0D0E0F1011121314151617"))
	hex.Decode(key256, []byte("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"))
}

func TestKeyWrap_Vector128(t *testing.T) {

	tc, err := buildTestCase(
		[]byte("00112233445566778899AABBCCDDEEFF"),
		[]byte("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"))

	if err != nil {
		t.Errorf("Error during test case setup %s\n", err)
	}

	keyWrap, _ := New(key128)

	if ciphertext, err := keyWrap.Wrap(tc.Input); err == nil {
		if !bytes.Equal(tc.Expected, ciphertext) {
			expected := make([]byte, hex.EncodedLen(len(tc.Expected)))
			got := make([]byte, hex.EncodedLen(len(ciphertext)))

			hex.Encode(expected, tc.Expected)
			hex.Encode(got, ciphertext)

			t.Errorf("Wrap 128 failed, expected[%s] got[%s]", expected, got)
		}
	} else {
		t.Errorf(err.Error())
	}
}

func TestKeyUnWrap_Vector128(t *testing.T) {

	tc, err := buildTestCase(
		[]byte("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"),
		[]byte("00112233445566778899AABBCCDDEEFF"))

	if err != nil {
		t.Errorf("Error during test case setup %s\n", err)
	}

	keyWrap, _ := New(key128)

	if plaintext, err := keyWrap.Unwrap(tc.Input); err == nil {
		if !bytes.Equal(tc.Expected, plaintext) {
			expected := make([]byte, hex.EncodedLen(len(tc.Expected)))
			got := make([]byte, hex.EncodedLen(len(plaintext)))

			hex.Encode(expected, tc.Expected)
			hex.Encode(got, plaintext)

			t.Errorf("UnWrap 128 failed, expected[%s] got[%s]", expected, got)
		}
	} else {
		t.Errorf(err.Error())
	}
}

func TestKeyWrap_Vector192(t *testing.T) {

	tc, err := buildTestCase(
		[]byte("00112233445566778899AABBCCDDEEFF"),
		[]byte("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"))

	if err != nil {
		t.Errorf("Error during test case setup %s\n", err)
	}

	keyWrap, _ := New(key192)

	if ciphertext, err := keyWrap.Wrap(tc.Input); err == nil {
		if !bytes.Equal(tc.Expected, ciphertext) {
			expected := make([]byte, hex.EncodedLen(len(tc.Expected)))
			got := make([]byte, hex.EncodedLen(len(ciphertext)))

			hex.Encode(expected, tc.Expected)
			hex.Encode(got, ciphertext)

			t.Errorf("Wrap 192 failed, expected[%s] got[%s]", expected, got)
		}
	} else {
		t.Errorf(err.Error())
	}
}

func TestKeyUnWrap_Vector192(t *testing.T) {

	tc, err := buildTestCase(
		[]byte("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"),
		[]byte("00112233445566778899AABBCCDDEEFF"))

	if err != nil {
		t.Errorf("Error during test case setup %s\n", err)
	}

	keyWrap, _ := New(key192)

	if plaintext, err := keyWrap.Unwrap(tc.Input); err == nil {
		if !bytes.Equal(tc.Expected, plaintext) {
			expected := make([]byte, hex.EncodedLen(len(tc.Expected)))
			got := make([]byte, hex.EncodedLen(len(plaintext)))

			hex.Encode(expected, tc.Expected)
			hex.Encode(got, plaintext)

			t.Errorf("UnWrap 128 failed, expected[%s] got[%s]", expected, got)
		}
	} else {
		t.Errorf(err.Error())
	}
}

func TestKeyWrap_Vector256(t *testing.T) {

	tc, err := buildTestCase(
		[]byte("00112233445566778899AABBCCDDEEFF"),
		[]byte("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"))

	if err != nil {
		t.Errorf("Error during test case setup %s\n", err)
	}

	keyWrap, _ := New(key256)

	if ciphertext, err := keyWrap.Wrap(tc.Input); err == nil {
		if !bytes.Equal(tc.Expected, ciphertext) {
			expected := make([]byte, hex.EncodedLen(len(tc.Expected)))
			got := make([]byte, hex.EncodedLen(len(ciphertext)))

			hex.Encode(expected, tc.Expected)
			hex.Encode(got, ciphertext)

			t.Errorf("Wrap 256 failed, expected[%s] got[%s]", expected, got)
		}
	} else {
		t.Errorf(err.Error())
	}
}

func TestKeyUnWrap_Vector256(t *testing.T) {

	tc, err := buildTestCase(
		[]byte("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"),
		[]byte("00112233445566778899AABBCCDDEEFF"))

	if err != nil {
		t.Errorf("Error during test case setup %s\n", err)
	}

	keyWrap, _ := New(key256)

	if plaintext, err := keyWrap.Unwrap(tc.Input); err == nil {
		if !bytes.Equal(tc.Expected, plaintext) {
			expected := make([]byte, hex.EncodedLen(len(tc.Expected)))
			got := make([]byte, hex.EncodedLen(len(plaintext)))

			hex.Encode(expected, tc.Expected)
			hex.Encode(got, plaintext)

			t.Errorf("UnWrap 128 failed, expected[%s] got[%s]", expected, got)
		}
	} else {
		t.Errorf(err.Error())
	}
}

func TestKeyWrap_InvalidKeyLength(t *testing.T) {
	invalidKey := []byte("abcd")

	if _, err := New(invalidKey); err == nil {
		t.Errorf("Accepted an invalid key")
	}
}

func TestKeyUnWrap_IntegrityCheck(t *testing.T) {

	tc, err := buildTestCase(
		[]byte("aFA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"), // modified first 4 bits
		[]byte("00112233445566778899AABBCCDDEEFF"))

	if err != nil {
		t.Errorf("Error during test case setup %s\n", err)
	}

	keyWrap, _ := New(key128)

	if _, err := keyWrap.Unwrap(tc.Input); err == nil {
		t.Errorf("Integrity check should have failed")
	}
}

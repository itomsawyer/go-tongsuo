package sm4

// #include "../../shim.h"
// #include <gcm.h>
import "C"
import (
	"crypto/cipher"
	"errors"
	"unsafe"
)

const (
	BlockSize      = 16
	TagSize        = 16
	MinimumTagSize = 12 // NIST SP 800-38D recommends tags with 12 or more bytes.
	NonceSize      = 12
)

// SM4GCM is basic type of sm4, which implement all cipher.AEAD interface
type SM4GCM struct {
	key []byte
}

// NewGCM return a basic SM4GCM struct
func NewGCM(k []byte) cipher.AEAD {
	return &SM4GCM{
		key: k,
	}
}

// NonceSize required by cipher.AEAD interface
// sm4-gcm nonce size is 12
func (sg *SM4GCM) NonceSize() int {
	return NonceSize
}

// Overhead required by cipher.AEAD interface, always equal tag size
// sm4-gcm tag size is 12
func (sg *SM4GCM) Overhead() int {
	return TagSize
}

func (sg *SM4GCM) tagSize() int {
	return TagSize
}

// Seal required by cipher.AEAD interface
func (sg *SM4GCM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != sg.NonceSize() {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}

	if uint64(len(plaintext)) > ((1<<32)-2)*uint64(BlockSize) {
		panic("crypto/cipher: message too large for GCM")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+sg.tagSize())

	// sm4 key size should euqal block size, the value is 16
	if len(sg.key) != BlockSize {
		panic("crypto/cipher: invalid buffer overlap")
	}

	encLen := C.sm4_gcm_encrypt((*C.uchar)(unsafe.Pointer(&plaintext[0])), C.int(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])), C.int(len(additionalData)),
		(*C.uchar)(unsafe.Pointer(&sg.key[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])), C.int(len(nonce)),
		(*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&out[len(plaintext)])))

	if int(encLen) != len(plaintext) {
		panic("error happen in sm4_gcm_encrypt")
	}

	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

// Open required by cipher.AEAD interface
func (sg *SM4GCM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != sg.NonceSize() {
		panic("crypto/cipher: incorrect nonce length given to GCM")
	}
	// Sanity check to prevent the authentication from always succeeding if an implementation
	// leaves tagSize uninitialized, for example.
	if sg.tagSize() < MinimumTagSize {
		panic("crypto/cipher: incorrect GCM tag size")
	}

	if len(ciphertext) < sg.tagSize() {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(BlockSize)+uint64(sg.tagSize()) {
		return nil, errOpen
	}

	tag := ciphertext[len(ciphertext)-sg.tagSize():]
	ciphertext = ciphertext[:len(ciphertext)-sg.tagSize()]
	ret := make([]byte, len(ciphertext), len(ciphertext))

	decRes := C.sm4_gcm_decrypt((*C.uchar)(unsafe.Pointer(&ciphertext[0])), C.int(len(ciphertext)),
		(*C.uchar)(unsafe.Pointer(&additionalData[0])), C.int(len(additionalData)),
		(*C.uchar)(unsafe.Pointer(&tag[0])),
		(*C.uchar)(unsafe.Pointer(&sg.key[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])), C.int(len(nonce)),
		(*C.uchar)(unsafe.Pointer(&ret[0])))

	if int(decRes) < 0 || int(decRes) != len(ciphertext) {
		return nil, errOpen
	}

	return ret, nil
}

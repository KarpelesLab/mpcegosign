package rsa3

import (
	"crypto/sha256"
	"fmt"
	"math/big"
)

// PKCS#1 v1.5 DigestInfo prefix for SHA-256
var sha256DigestInfoPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20,
}

// PadPKCS1v15SHA256 creates a PKCS#1 v1.5 padded message for RSA-3072 (384 bytes).
// Format: 00 01 [FF padding] 00 [DigestInfo] [hash]
func PadPKCS1v15SHA256(hash [32]byte) []byte {
	blockLen := 384 // RSA-3072

	// T = DigestInfo prefix + hash
	tLen := len(sha256DigestInfoPrefix) + 32 // 19 + 32 = 51

	// padLen = blockLen - 3 - tLen = 384 - 3 - 51 = 330
	padLen := blockLen - 3 - tLen
	if padLen < 8 {
		panic("key too short for PKCS#1 v1.5 padding")
	}

	em := make([]byte, blockLen)
	em[0] = 0x00
	em[1] = 0x01
	for i := 2; i < 2+padLen; i++ {
		em[i] = 0xFF
	}
	em[2+padLen] = 0x00
	copy(em[3+padLen:], sha256DigestInfoPrefix)
	copy(em[3+padLen+len(sha256DigestInfoPrefix):], hash[:])

	return em
}

// Sign performs raw RSA signing: sig = padded_msg^d mod N.
// The padded message and result are big-endian big integers.
func Sign(paddedMsg []byte, d, n *big.Int) []byte {
	m := new(big.Int).SetBytes(paddedMsg)
	s := new(big.Int).Exp(m, d, n)
	// Pad to 384 bytes
	sBytes := s.Bytes()
	result := make([]byte, 384)
	copy(result[384-len(sBytes):], sBytes)
	return result
}

// Verify checks that sig^e mod N equals the padded message.
func Verify(sig []byte, e int, n *big.Int, paddedMsg []byte) bool {
	s := new(big.Int).SetBytes(sig)
	eBig := big.NewInt(int64(e))
	recovered := new(big.Int).Exp(s, eBig, n)
	expected := new(big.Int).SetBytes(paddedMsg)
	return recovered.Cmp(expected) == 0
}

// SignSigStruct signs a SIGSTRUCT hash and returns the signature in big-endian.
func SignSigStruct(sigstructHash [32]byte, d, n *big.Int) ([]byte, error) {
	padded := PadPKCS1v15SHA256(sigstructHash)
	sig := Sign(padded, d, n)

	// Verify
	if !Verify(sig, 3, n, padded) {
		return nil, fmt.Errorf("signature verification failed")
	}
	return sig, nil
}

// MRSIGNER computes SHA-256 of the modulus (in little-endian byte order).
func MRSIGNER(modulusLE []byte) [32]byte {
	return sha256.Sum256(modulusLE)
}

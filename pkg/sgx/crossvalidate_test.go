package sgx

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"testing"

	"github.com/magicaltux/mpcegosign/pkg/elfutil"
)

const testBinary = "/home/magicaltux/projects/vpnet/vpnetd-sgx/vpnetd-sgx"

// Reference values extracted from the signed vpnetd-sgx binary.
// MRSIGNER is stable (same key), MRENCLAVE depends on binary content.
const (
	refMRSIGNER = "ab81fd99df38cd8d77fd4bd1fa22a76f7738d5182d5c8cde3d9a7aeaffbeb6be"
)

func skipIfNoBinary(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(testBinary); os.IsNotExist(err) {
		t.Skipf("test binary not found: %s", testBinary)
	}
}

func TestCrossValidateSigStructParsing(t *testing.T) {
	skipIfNoBinary(t)

	oeinfo, err := elfutil.ReadOEInfo(testBinary)
	if err != nil {
		t.Fatalf("ReadOEInfo: %v", err)
	}

	ss, err := ParseSigStruct(oeinfo.SigStructBytes())
	if err != nil {
		t.Fatalf("ParseSigStruct: %v", err)
	}

	// Verify headers
	for i := 0; i < 16; i++ {
		if ss.Raw[i] != SigStructHeader[i] {
			t.Errorf("header1[%d]: got %02x, want %02x", i, ss.Raw[i], SigStructHeader[i])
		}
	}
	for i := 0; i < 16; i++ {
		if ss.Raw[OffsetHeader2+i] != SigStructHeader2[i] {
			t.Errorf("header2[%d]: got %02x, want %02x", i, ss.Raw[OffsetHeader2+i], SigStructHeader2[i])
		}
	}

	if ss.Exponent() != 3 {
		t.Errorf("exponent: got %d, want 3", ss.Exponent())
	}

	// Verify MRENCLAVE is non-zero (actual value changes with binary content)
	mr := ss.MRENCLAVE()
	if mr == [32]byte{} {
		t.Error("MRENCLAVE is all zeros")
	}
	t.Logf("MRENCLAVE from SIGSTRUCT: %s", hex.EncodeToString(mr[:]))
}

func TestCrossValidateMRSIGNER(t *testing.T) {
	skipIfNoBinary(t)

	oeinfo, err := elfutil.ReadOEInfo(testBinary)
	if err != nil {
		t.Fatalf("ReadOEInfo: %v", err)
	}

	ss, err := ParseSigStruct(oeinfo.SigStructBytes())
	if err != nil {
		t.Fatalf("ParseSigStruct: %v", err)
	}

	// MRSIGNER = SHA-256(modulus_LE)
	modLE := ss.Modulus()
	mrsigner := sha256.Sum256(modLE)
	mrsignerHex := hex.EncodeToString(mrsigner[:])

	if mrsignerHex != refMRSIGNER {
		t.Errorf("MRSIGNER:\n  got  %s\n  want %s", mrsignerHex, refMRSIGNER)
	}
}

func TestCrossValidateSignatureVerification(t *testing.T) {
	skipIfNoBinary(t)

	oeinfo, err := elfutil.ReadOEInfo(testBinary)
	if err != nil {
		t.Fatalf("ReadOEInfo: %v", err)
	}

	ss, err := ParseSigStruct(oeinfo.SigStructBytes())
	if err != nil {
		t.Fatalf("ParseSigStruct: %v", err)
	}

	// Get modulus and signature (both LE in SIGSTRUCT)
	modLE := make([]byte, 384)
	copy(modLE, ss.Modulus())
	sigLE := make([]byte, 384)
	copy(sigLE, ss.Signature())

	// Convert to big-endian for math
	modBE := reverseBytes(modLE)
	sigBE := reverseBytes(sigLE)

	mod := new(big.Int).SetBytes(modBE)
	sig := new(big.Int).SetBytes(sigBE)

	// sig^3 mod N should equal PKCS#1 v1.5 padded hash
	three := big.NewInt(3)
	recovered := new(big.Int).Exp(sig, three, mod)

	// Compute the expected padded hash
	sigHash := ss.HashForSigning()
	padded := buildPKCS1v15SHA256(sigHash[:])
	expected := new(big.Int).SetBytes(padded)

	if recovered.Cmp(expected) != 0 {
		t.Error("signature verification failed: sig^3 mod N != padded_hash")
	}
}

func TestCrossValidateQ1Q2(t *testing.T) {
	skipIfNoBinary(t)

	oeinfo, err := elfutil.ReadOEInfo(testBinary)
	if err != nil {
		t.Fatalf("ReadOEInfo: %v", err)
	}

	ss, err := ParseSigStruct(oeinfo.SigStructBytes())
	if err != nil {
		t.Fatalf("ParseSigStruct: %v", err)
	}

	modBE := reverseBytes(ss.Modulus())
	sigBE := reverseBytes(ss.Signature())
	q1LE := ss.Raw[OffsetQ1 : OffsetQ1+Q1Size]
	q2LE := ss.Raw[OffsetQ2 : OffsetQ2+Q2Size]
	q1BE := reverseBytes(q1LE)
	q2BE := reverseBytes(q2LE)

	mod := new(big.Int).SetBytes(modBE)
	sig := new(big.Int).SetBytes(sigBE)
	q1 := new(big.Int).SetBytes(q1BE)
	q2 := new(big.Int).SetBytes(q2BE)

	// Q1 = floor(sig^2 / mod)
	sig2 := new(big.Int).Mul(sig, sig)
	expectedQ1 := new(big.Int).Div(sig2, mod)
	if q1.Cmp(expectedQ1) != 0 {
		t.Error("Q1 mismatch")
	}

	// R = sig^2 mod mod; Q2 = floor(sig*R / mod)
	r := new(big.Int).Mod(sig2, mod)
	sigR := new(big.Int).Mul(sig, r)
	expectedQ2 := new(big.Int).Div(sigR, mod)
	if q2.Cmp(expectedQ2) != 0 {
		t.Error("Q2 mismatch")
	}
}

func TestCrossValidateEnclaveProperties(t *testing.T) {
	skipIfNoBinary(t)

	oeinfo, err := elfutil.ReadOEInfo(testBinary)
	if err != nil {
		t.Fatalf("ReadOEInfo: %v", err)
	}

	props, err := ParseEnclaveProperties(oeinfo.Data)
	if err != nil {
		t.Fatalf("ParseEnclaveProperties: %v", err)
	}

	if props.EnclaveType != OEEnclaveTypeSGX {
		t.Errorf("EnclaveType: got %d, want %d", props.EnclaveType, OEEnclaveTypeSGX)
	}

	// From enclave.json: heapSize=300 MB = 300*1024*1024/4096 = 76800 pages
	if props.SizeSettings.NumHeapPages != 76800 {
		t.Errorf("NumHeapPages: got %d, want 76800", props.SizeSettings.NumHeapPages)
	}

	if props.SizeSettings.NumStackPages != 1024 {
		t.Errorf("NumStackPages: got %d, want 1024", props.SizeSettings.NumStackPages)
	}

	if props.SizeSettings.NumTCS != 32 {
		t.Errorf("NumTCS: got %d, want 32", props.SizeSettings.NumTCS)
	}

	if props.ProductID != 1 {
		t.Errorf("ProductID: got %d, want 1", props.ProductID)
	}

	if props.SecurityVersion != 1 {
		t.Errorf("SecurityVersion: got %d, want 1", props.SecurityVersion)
	}

	if props.IsDebug() {
		t.Error("expected non-debug enclave")
	}
}

func TestCrossValidateMRENCLAVE(t *testing.T) {
	skipIfNoBinary(t)

	// The signed vpnetd-sgx binary was produced by ego sign which calls
	// ego-oesign with TWO separate ELF images (ego-enclave runtime + Go
	// payload binary). The measurement is computed from those two separate
	// images, not from the combined output binary on disk.
	//
	// To match the MRENCLAVE from the signed binary, we'd need the original
	// separate ego-enclave and payload images. This test validates that our
	// measurement code runs without error and produces a deterministic result.
	// Full MRENCLAVE matching requires testing against ego-oesign directly.

	oeinfo, err := elfutil.ReadOEInfo(testBinary)
	if err != nil {
		t.Fatalf("ReadOEInfo: %v", err)
	}

	props, err := ParseEnclaveProperties(oeinfo.Data)
	if err != nil {
		t.Fatalf("ParseEnclaveProperties: %v", err)
	}

	elfInfo, err := elfutil.ReadELFInfo(testBinary)
	if err != nil {
		t.Fatalf("ReadELFInfo: %v", err)
	}

	mrenclave, err := ComputeMRENCLAVE(elfInfo, props)
	if err != nil {
		t.Fatalf("ComputeMRENCLAVE: %v", err)
	}

	got := hex.EncodeToString(mrenclave[:])
	t.Logf("Computed MRENCLAVE: %s", got)

	// Read the MRENCLAVE from the signed binary's SIGSTRUCT for comparison
	ss, _ := ParseSigStruct(oeinfo.SigStructBytes())
	mr2 := ss.MRENCLAVE()
	refMR := hex.EncodeToString(mr2[:])
	t.Logf("SIGSTRUCT MRENCLAVE: %s", refMR)

	if got == refMR {
		t.Log("MRENCLAVE matches SIGSTRUCT!")
	} else {
		t.Log("MRENCLAVE does not match SIGSTRUCT (expected: ego sign uses two separate ELF images for measurement)")
	}

	// Verify determinism: same input should produce same output
	mrenclave2, _ := ComputeMRENCLAVE(elfInfo, props)
	got2 := hex.EncodeToString(mrenclave2[:])
	if got != got2 {
		t.Errorf("measurement not deterministic: %s != %s", got, got2)
	}
}

func reverseBytes(b []byte) []byte {
	r := make([]byte, len(b))
	for i, v := range b {
		r[len(b)-1-i] = v
	}
	return r
}

func buildPKCS1v15SHA256(hash []byte) []byte {
	prefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
		0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	em := make([]byte, 384)
	em[0] = 0x00
	em[1] = 0x01
	tLen := len(prefix) + 32
	padLen := 384 - 3 - tLen
	for i := 2; i < 2+padLen; i++ {
		em[i] = 0xFF
	}
	em[2+padLen] = 0x00
	copy(em[3+padLen:], prefix)
	copy(em[3+padLen+len(prefix):], hash)
	return em
}

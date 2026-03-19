package sgx

import (
	"testing"
)

func TestSigStructRoundTrip(t *testing.T) {
	ss := NewSigStruct()

	// Set values
	ss.SetDate(2024, 3, 15)
	ss.SetExponent(3)
	ss.SetISVProdID(42)
	ss.SetISVSVN(7)
	ss.SetMiscSelect(0)
	ss.SetMiscMask(0xFFFFFFFF)
	ss.SetAttributes(AttributeInit|AttributeMode64Bit, DefaultXFRM)
	ss.SetAttributesMask(^uint64(0), ^uint64(0))

	mrenclave := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	ss.SetMRENCLAVE(mrenclave)

	// Round-trip
	data := ss.Bytes()
	if len(data) != SigStructSize {
		t.Fatalf("expected %d bytes, got %d", SigStructSize, len(data))
	}

	ss2, err := ParseSigStruct(data)
	if err != nil {
		t.Fatalf("ParseSigStruct failed: %v", err)
	}

	if ss2.Exponent() != 3 {
		t.Errorf("exponent: got %d, want 3", ss2.Exponent())
	}

	mr := ss2.MRENCLAVE()
	if mr != mrenclave {
		t.Error("MRENCLAVE mismatch after round-trip")
	}

	// Verify headers
	for i := 0; i < 16; i++ {
		if data[i] != SigStructHeader[i] {
			t.Errorf("header1[%d]: got %02x, want %02x", i, data[i], SigStructHeader[i])
		}
	}
	for i := 0; i < 16; i++ {
		if data[OffsetHeader2+i] != SigStructHeader2[i] {
			t.Errorf("header2[%d]: got %02x, want %02x", i, data[OffsetHeader2+i], SigStructHeader2[i])
		}
	}
}

func TestSigStructHashForSigning(t *testing.T) {
	ss := NewSigStruct()
	ss.SetDate(2024, 1, 1)
	ss.SetExponent(3)
	ss.SetISVProdID(1)
	ss.SetISVSVN(1)

	hash1 := ss.HashForSigning()

	// Change something in signed region
	ss.SetISVProdID(2)
	hash2 := ss.HashForSigning()

	if hash1 == hash2 {
		t.Error("changing signed field should change hash")
	}

	// Change something outside signed region (signature)
	ss.SetISVProdID(2) // keep same
	sig := make([]byte, SignatureSize)
	sig[0] = 0xFF
	ss.SetSignature(sig)
	hash3 := ss.HashForSigning()

	if hash2 != hash3 {
		t.Error("changing non-signed field should not change hash")
	}
}

func TestSigStructSize(t *testing.T) {
	// Verify final offset + size = SigStructSize
	endQ2 := OffsetQ2 + Q2Size
	if endQ2 != SigStructSize {
		t.Errorf("Q2 end (%d) != SigStructSize (%d)", endQ2, SigStructSize)
	}
}

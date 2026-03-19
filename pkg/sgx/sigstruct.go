package sgx

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// SigStruct represents an SGX SIGSTRUCT (1808 bytes).
type SigStruct struct {
	Raw [SigStructSize]byte
}

// NewSigStruct creates a new SIGSTRUCT with default headers.
func NewSigStruct() *SigStruct {
	s := &SigStruct{}
	copy(s.Raw[OffsetHeader1:], SigStructHeader[:])
	copy(s.Raw[OffsetHeader2:], SigStructHeader2[:])
	return s
}

// ParseSigStruct parses a SIGSTRUCT from a byte slice.
func ParseSigStruct(data []byte) (*SigStruct, error) {
	if len(data) < SigStructSize {
		return nil, fmt.Errorf("sigstruct data too short: %d < %d", len(data), SigStructSize)
	}
	s := &SigStruct{}
	copy(s.Raw[:], data[:SigStructSize])
	return s, nil
}

// Bytes returns the raw SIGSTRUCT bytes.
func (s *SigStruct) Bytes() []byte {
	return s.Raw[:]
}

// SetDate sets the date in BCD format (YYYYMMDD).
func (s *SigStruct) SetDate(year, month, day int) {
	binary.LittleEndian.PutUint32(s.Raw[OffsetDate:], bcdDate(year, month, day))
}

func bcdDate(year, month, day int) uint32 {
	y := uint32(year)
	m := uint32(month)
	d := uint32(day)
	return (y/1000)<<28 | ((y/100)%10)<<24 | ((y/10)%10)<<20 | (y%10)<<16 |
		(m/10)<<12 | (m%10)<<8 | (d/10)<<4 | (d%10)
}

// SetModulus sets the modulus (384 bytes, little-endian).
func (s *SigStruct) SetModulus(mod []byte) {
	copy(s.Raw[OffsetModulus:OffsetModulus+ModulusSize], mod)
}

// Modulus returns the modulus bytes (little-endian).
func (s *SigStruct) Modulus() []byte {
	return s.Raw[OffsetModulus : OffsetModulus+ModulusSize]
}

// SetExponent sets the public exponent (little-endian uint32).
func (s *SigStruct) SetExponent(exp uint32) {
	binary.LittleEndian.PutUint32(s.Raw[OffsetExponent:], exp)
}

// Exponent returns the public exponent.
func (s *SigStruct) Exponent() uint32 {
	return binary.LittleEndian.Uint32(s.Raw[OffsetExponent:])
}

// SetSignature sets the RSA signature (384 bytes, little-endian).
func (s *SigStruct) SetSignature(sig []byte) {
	copy(s.Raw[OffsetSignature:OffsetSignature+SignatureSize], sig)
}

// Signature returns the signature bytes (little-endian).
func (s *SigStruct) Signature() []byte {
	return s.Raw[OffsetSignature : OffsetSignature+SignatureSize]
}

// SetMRENCLAVE sets the measurement hash.
func (s *SigStruct) SetMRENCLAVE(mrenclave [32]byte) {
	copy(s.Raw[OffsetMRENCLAVE:], mrenclave[:])
}

// MRENCLAVE returns the measurement hash.
func (s *SigStruct) MRENCLAVE() [32]byte {
	var h [32]byte
	copy(h[:], s.Raw[OffsetMRENCLAVE:OffsetMRENCLAVE+32])
	return h
}

// SetMiscSelect sets the MISCSELECT field.
func (s *SigStruct) SetMiscSelect(val uint32) {
	binary.LittleEndian.PutUint32(s.Raw[OffsetMiscSelect:], val)
}

// SetMiscMask sets the MISCSELECT mask.
func (s *SigStruct) SetMiscMask(val uint32) {
	binary.LittleEndian.PutUint32(s.Raw[OffsetMiscMask:], val)
}

// SetAttributes sets the ATTRIBUTES field (16 bytes: flags + xfrm).
func (s *SigStruct) SetAttributes(flags, xfrm uint64) {
	binary.LittleEndian.PutUint64(s.Raw[OffsetAttributes:], flags)
	binary.LittleEndian.PutUint64(s.Raw[OffsetAttributes+8:], xfrm)
}

// SetAttributesMask sets the ATTRIBUTES mask (16 bytes: flags_mask + xfrm_mask).
func (s *SigStruct) SetAttributesMask(flagsMask, xfrmMask uint64) {
	binary.LittleEndian.PutUint64(s.Raw[OffsetAttrMask:], flagsMask)
	binary.LittleEndian.PutUint64(s.Raw[OffsetAttrMask+8:], xfrmMask)
}

// SetISVProdID sets the ISV Product ID.
func (s *SigStruct) SetISVProdID(id uint16) {
	binary.LittleEndian.PutUint16(s.Raw[OffsetISVProdID:], id)
}

// SetISVSVN sets the ISV Security Version Number.
func (s *SigStruct) SetISVSVN(svn uint16) {
	binary.LittleEndian.PutUint16(s.Raw[OffsetISVSVN:], svn)
}

// SetQ1 sets the Q1 value (384 bytes, little-endian).
func (s *SigStruct) SetQ1(q1 []byte) {
	copy(s.Raw[OffsetQ1:OffsetQ1+Q1Size], q1)
}

// SetQ2 sets the Q2 value (384 bytes, little-endian).
func (s *SigStruct) SetQ2(q2 []byte) {
	copy(s.Raw[OffsetQ2:OffsetQ2+Q2Size], q2)
}

// SetISVFamilyID sets the ISV Family ID (16 bytes).
func (s *SigStruct) SetISVFamilyID(id [16]byte) {
	copy(s.Raw[OffsetISVFamilyID:], id[:])
}

// SetISVExtProdID sets the ISV Extended Product ID (16 bytes).
func (s *SigStruct) SetISVExtProdID(id [16]byte) {
	copy(s.Raw[OffsetISVExtProdID:], id[:])
}

// HashForSigning computes SHA-256 over the two signed regions.
func (s *SigStruct) HashForSigning() [32]byte {
	h := sha256.New()
	h.Write(s.Raw[SignedRegion1Start:SignedRegion1End])
	h.Write(s.Raw[SignedRegion2Start:SignedRegion2End])
	var digest [32]byte
	h.Sum(digest[:0])
	return digest
}

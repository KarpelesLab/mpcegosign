package sgx

import (
	"encoding/binary"
	"fmt"
)

// EnclaveProperties represents oe_sgx_enclave_properties_t found in .oeinfo.
type EnclaveProperties struct {
	// Header (32 bytes)
	Size         uint32
	EnclaveType  uint32
	SizeSettings EnclaveSizeSettings

	// Config (64 bytes at offset 32)
	ProductID       uint16
	SecurityVersion uint16
	Padding1        uint32
	Flags           uint64 // OE_SGX_FLAGS_*
	FamilyID        [16]byte
	ExtProductID    [16]byte
	Attributes      uint64 // not used directly; for completeness
	XFRM            uint64 // not used directly

	// ImageInfo (48 bytes at offset 96)
	OEInfoRVA   uint64
	OEInfoSize  uint64
	RelocRVA    uint64
	RelocSize   uint64
	HeapRVA     uint64
	EnclaveSize uint64
}

// EnclaveSizeSettings holds the size configuration.
type EnclaveSizeSettings struct {
	NumHeapPages  uint64
	NumStackPages uint64
	NumTCS        uint64
}

// ParseEnclaveProperties parses the properties from .oeinfo section data.
func ParseEnclaveProperties(data []byte) (*EnclaveProperties, error) {
	if len(data) < 144 {
		return nil, fmt.Errorf("oeinfo data too short: %d < 144", len(data))
	}

	p := &EnclaveProperties{}

	// Header (32 bytes)
	p.Size = binary.LittleEndian.Uint32(data[0:4])
	p.EnclaveType = binary.LittleEndian.Uint32(data[4:8])
	p.SizeSettings.NumHeapPages = binary.LittleEndian.Uint64(data[8:16])
	p.SizeSettings.NumStackPages = binary.LittleEndian.Uint64(data[16:24])
	p.SizeSettings.NumTCS = binary.LittleEndian.Uint64(data[24:32])

	// Config (64 bytes at offset 32)
	p.ProductID = binary.LittleEndian.Uint16(data[32:34])
	p.SecurityVersion = binary.LittleEndian.Uint16(data[34:36])
	p.Padding1 = binary.LittleEndian.Uint32(data[36:40])
	p.Flags = binary.LittleEndian.Uint64(data[40:48])
	copy(p.FamilyID[:], data[48:64])
	copy(p.ExtProductID[:], data[64:80])
	p.Attributes = binary.LittleEndian.Uint64(data[80:88])
	p.XFRM = binary.LittleEndian.Uint64(data[88:96])

	// ImageInfo (48 bytes at offset 96)
	p.OEInfoRVA = binary.LittleEndian.Uint64(data[96:104])
	p.OEInfoSize = binary.LittleEndian.Uint64(data[104:112])
	p.RelocRVA = binary.LittleEndian.Uint64(data[112:120])
	p.RelocSize = binary.LittleEndian.Uint64(data[120:128])
	p.HeapRVA = binary.LittleEndian.Uint64(data[128:136])
	p.EnclaveSize = binary.LittleEndian.Uint64(data[136:144])

	return p, nil
}

// IsDebug returns true if the debug flag is set.
func (p *EnclaveProperties) IsDebug() bool {
	return p.Flags&0x1 != 0
}

// SGXAttributes returns the attributes flags for SIGSTRUCT.
func (p *EnclaveProperties) SGXAttributes() uint64 {
	flags := uint64(AttributeInit | AttributeMode64Bit)
	if p.IsDebug() {
		flags |= AttributeDebug
	}
	return flags
}

// SGXAttributesMask returns the attributes mask for SIGSTRUCT.
func (p *EnclaveProperties) SGXAttributesMask() uint64 {
	// Mask all defined bits: INIT, DEBUG, MODE64BIT
	return ^uint64(0) // OE uses 0xFFFFFFFFFFFFFFFF
}

package sgx

// SGX SIGSTRUCT magic values
var SigStructHeader = [16]byte{
	0x06, 0x00, 0x00, 0x00, 0xE1, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var SigStructHeader2 = [16]byte{
	0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00,
	0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
}

// SIGSTRUCT field sizes
const (
	SigStructSize = 1808
	ModulusSize   = 384 // 3072 bits
	ExponentSize  = 4
	SignatureSize = 384
	Q1Size        = 384
	Q2Size        = 384
	MRENCLAVESize = 32
)

// SIGSTRUCT field offsets (Intel SDM Vol 3D, Table 38-19)
const (
	OffsetHeader1   = 0   // 16 bytes
	OffsetVendor    = 16  // 4 bytes
	OffsetDate      = 20  // 4 bytes
	OffsetHeader2   = 24  // 16 bytes
	OffsetSwDefined = 40  // 4 bytes
	OffsetReserved1 = 44  // 84 bytes
	OffsetModulus   = 128 // 384 bytes
	OffsetExponent  = 512 // 4 bytes
	OffsetSignature = 516 // 384 bytes

	// Signed body region (900-1027)
	OffsetMiscSelect = 900 // 4 bytes
	OffsetMiscMask   = 904 // 4 bytes
	OffsetReserved2  = 908 // 20 bytes
	OffsetAttributes = 928 // 16 bytes (flags + xfrm)
	OffsetAttrMask   = 944 // 16 bytes
	OffsetMRENCLAVE  = 960 // 32 bytes
	OffsetReserved3  = 992 // 32 bytes
	OffsetISVProdID  = 1024 // 2 bytes
	OffsetISVSVN     = 1026 // 2 bytes
	// End of signed body at 1028

	OffsetReserved4 = 1028 // 12 bytes
	OffsetQ1        = 1040 // 384 bytes
	OffsetQ2        = 1424 // 384 bytes
	// Total: 1808
)

// ISV Family ID and Extended Product ID live in the reserved fields (OE extensions)
const (
	OffsetISVFamilyID  = 908  // inside Reserved2 (OE extension)
	OffsetISVExtProdID = 992  // inside Reserved3 (OE extension)
)

// Signed regions of SIGSTRUCT
const (
	SignedRegion1Start = 0
	SignedRegion1End   = 128
	SignedRegion2Start = 900
	SignedRegion2End   = 1028
)

// SECINFO flags for page types
const (
	SecinfoR   = 0x1
	SecinfoW   = 0x2
	SecinfoX   = 0x4
	SecinfoTCS = 0x08
	SecinfoREG = 0x10
)

// SGX page size
const PageSize = 4096

// Attributes flags
const (
	AttributeInit     = 0x1
	AttributeDebug    = 0x2
	AttributeMode64Bit = 0x4
)

// Default XFRM (extended feature request mask)
const DefaultXFRM = uint64(0x3) // FPU + SSE

// OE enclave type
const OEEnclaveTypeSGX = 2

// OE properties end marker
var OEInfoEndMarker = [8]byte{0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec, 0xec}

// SSA frame size in pages
const SSAFrameSize = 1

package sgx

import (
	"encoding/binary"
	"sort"

	"github.com/magicaltux/mpcegosign/pkg/elfutil"
)

// EnclaveLayout holds all the computed layout information needed for measurement.
type EnclaveLayout struct {
	ImageSize       uint64 // total span of PT_LOAD segments, page-aligned
	RelocRVA        uint64 // where relocation data starts (= ImageSize)
	RelocSize       uint64 // size of relocation data, page-aligned
	PayloadDataRVA  uint64 // where payload data starts (= RelocRVA + RelocSize)
	PayloadDataSize uint64 // size of payload data, page-aligned
	HeapRVA         uint64 // where heap starts
	EnclaveSize     uint64 // total enclave size (power of 2)
	TLSPageCount    uint64 // number of TLS pages from PT_TLS
	EntryRVA        uint64 // entry point RVA from ELF header
}

// ComputeLayout computes the enclave memory layout from ELF info and properties.
func ComputeLayout(elfInfo *elfutil.ELFInfo, props *EnclaveProperties) *EnclaveLayout {
	layout := &EnclaveLayout{}

	layout.ImageSize = elfInfo.ImageSize
	layout.RelocRVA = elfInfo.ImageSize
	layout.RelocSize = roundUpToPage(elfInfo.RelocSize)
	layout.PayloadDataRVA = layout.RelocRVA + layout.RelocSize
	layout.PayloadDataSize = roundUpToPage(elfInfo.PayloadDataSize)
	layout.HeapRVA = layout.PayloadDataRVA + layout.PayloadDataSize
	layout.TLSPageCount = elfInfo.TLSPageCount
	layout.EntryRVA = elfInfo.EntryRVA

	// Calculate total loaded size
	heapSize := props.SizeSettings.NumHeapPages * PageSize
	stackSize := PageSize + (props.SizeSettings.NumStackPages * PageSize) + PageSize // guard + stack + guard
	tlsSize := layout.TLSPageCount * PageSize
	controlSize := (OESGXTCSControlPages + OESGXTCSThreadDataPages) * PageSize
	perTCS := stackSize + tlsSize + controlSize

	totalLoaded := layout.ImageSize + layout.RelocSize + layout.PayloadDataSize + heapSize +
		(props.SizeSettings.NumTCS * perTCS)

	layout.EnclaveSize = nextPow2(totalLoaded)

	return layout
}

// OE constants for thread control structure layout
const (
	OESGXTCSControlPages    uint64 = 4 // TCS(1) + SSA(2) + guard(1)
	OESGXTCSThreadDataPages uint64 = 1
)

// ComputeMRENCLAVE computes the MRENCLAVE measurement from ELF segments and
// enclave properties, following the OE page layout order.
func ComputeMRENCLAVE(elfInfo *elfutil.ELFInfo, props *EnclaveProperties) ([32]byte, error) {
	layout := ComputeLayout(elfInfo, props)
	m := NewMeasurement()

	// ECREATE
	m.ECREATE(SSAFrameSize, layout.EnclaveSize)

	// 1. ELF PT_LOAD segment pages → EADD + EEXTEND
	// Sort segments by virtual address
	sorted := make([]elfutil.SegmentInfo, len(elfInfo.Segments))
	copy(sorted, elfInfo.Segments)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].VAddr < sorted[j].VAddr
	})

	for _, seg := range sorted {
		flags := elfFlagsToSecinfo(seg.Flags) | SecinfoREG
		pageStart := roundDownToPage(seg.VAddr)
		segEnd := seg.VAddr + seg.MemSize

		for pageRVA := pageStart; pageRVA < segEnd; pageRVA += PageSize {
			// Get page data from the image
			pageData := getSegmentPageData(elfInfo, pageRVA)
			m.AddPage(pageRVA, flags, pageData, true)
		}
	}

	// 2. Relocation pages → EADD + EEXTEND (R, REG)
	if elfInfo.RelocSize > 0 {
		relocPages := layout.RelocSize / PageSize
		for p := uint64(0); p < relocPages; p++ {
			pageOffset := layout.RelocRVA + p*PageSize
			dataOffset := p * PageSize

			var pageData []byte
			if dataOffset < uint64(len(elfInfo.RelocData)) {
				end := dataOffset + PageSize
				if end > uint64(len(elfInfo.RelocData)) {
					end = uint64(len(elfInfo.RelocData))
				}
				pageData = elfInfo.RelocData[dataOffset:end]
			}
			m.AddPage(pageOffset, SecinfoR|SecinfoREG, pageData, true)
		}
	}

	// 3. Payload data pages → EADD + EEXTEND (R, REG) — EGo extension
	if elfInfo.PayloadDataSize > 0 && len(elfInfo.PayloadData) > 0 {
		payloadPages := layout.PayloadDataSize / PageSize
		for p := uint64(0); p < payloadPages; p++ {
			pageOffset := layout.PayloadDataRVA + p*PageSize
			dataOffset := p * PageSize

			pageData := make([]byte, PageSize)
			if dataOffset < uint64(len(elfInfo.PayloadData)) {
				end := dataOffset + PageSize
				if end > uint64(len(elfInfo.PayloadData)) {
					end = uint64(len(elfInfo.PayloadData))
				}
				copy(pageData, elfInfo.PayloadData[dataOffset:end])
			}
			m.AddPage(pageOffset, SecinfoR|SecinfoREG, pageData, true)
		}
	}

	// 4. Heap pages → EADD only, NO EEXTEND (R/W, REG, zeros)
	vaddr := layout.HeapRVA
	for p := uint64(0); p < props.SizeSettings.NumHeapPages; p++ {
		m.EADD(vaddr, SecinfoR|SecinfoW|SecinfoREG)
		vaddr += PageSize
	}

	// 4. Per-TCS thread data
	for t := uint64(0); t < props.SizeSettings.NumTCS; t++ {
		// Guard page (skip)
		vaddr += PageSize

		// Stack pages → EADD + EEXTEND (R/W, REG, fill 0xCCCCCCCC)
		for sp := uint64(0); sp < props.SizeSettings.NumStackPages; sp++ {
			m.AddPageWithPattern(vaddr, SecinfoR|SecinfoW|SecinfoREG, 0xCCCCCCCC)
			vaddr += PageSize
		}

		// Guard page (skip)
		vaddr += PageSize

		// TCS page → EADD + EEXTEND (TCS flag)
		tcsData := buildTCSPage(vaddr, layout.EntryRVA, layout.TLSPageCount)
		m.AddPage(vaddr, SecinfoTCS, tcsData, true)
		tcsVAddr := vaddr
		vaddr += PageSize

		// 2 SSA pages → EADD + EEXTEND (R/W, REG, zeros)
		m.AddPage(vaddr, SecinfoR|SecinfoW|SecinfoREG, make([]byte, PageSize), true)
		vaddr += PageSize
		m.AddPage(vaddr, SecinfoR|SecinfoW|SecinfoREG, make([]byte, PageSize), true)
		vaddr += PageSize

		// Guard page (skip)
		vaddr += PageSize

		// TLS pages → EADD + EEXTEND (R/W, REG, zeros)
		for tp := uint64(0); tp < layout.TLSPageCount; tp++ {
			m.AddPage(vaddr, SecinfoR|SecinfoW|SecinfoREG, make([]byte, PageSize), true)
			vaddr += PageSize
		}

		// Thread data page → EADD + EEXTEND (R/W, REG, zeros)
		_ = tcsVAddr // TCS addr could be used for thread data, but OE zeros this page
		m.AddPage(vaddr, SecinfoR|SecinfoW|SecinfoREG, make([]byte, PageSize), true)
		vaddr += PageSize
	}

	result := m.Sum()
	return result, nil
}

// getSegmentPageData retrieves page data at a given RVA from the ELF image.
func getSegmentPageData(elfInfo *elfutil.ELFInfo, pageRVA uint64) []byte {
	page := make([]byte, PageSize)
	// Find data from any segment that covers this page
	for _, seg := range elfInfo.Segments {
		segStart := seg.VAddr
		segFileEnd := seg.VAddr + seg.FileSize

		// Check overlap between [pageRVA, pageRVA+PageSize) and [segStart, segFileEnd)
		overlapStart := pageRVA
		if overlapStart < segStart {
			overlapStart = segStart
		}
		overlapEnd := pageRVA + PageSize
		if overlapEnd > segFileEnd {
			overlapEnd = segFileEnd
		}

		if overlapStart < overlapEnd {
			srcOff := overlapStart - seg.VAddr
			dstOff := overlapStart - pageRVA
			copy(page[dstOff:], seg.Data[srcOff:srcOff+(overlapEnd-overlapStart)])
		}
	}
	return page
}

// elfFlagsToSecinfo converts ELF segment flags to SGX SECINFO flags.
func elfFlagsToSecinfo(flags uint32) uint64 {
	var sf uint64
	if flags&elfutil.PF_R != 0 {
		sf |= SecinfoR
	}
	if flags&elfutil.PF_W != 0 {
		sf |= SecinfoW
	}
	if flags&elfutil.PF_X != 0 {
		sf |= SecinfoX
	}
	return sf
}

// buildTCSPage constructs the TCS (Thread Control Structure) page content.
// Fields are relative to enclave base (vaddr 0).
func buildTCSPage(tcsVAddr, entryRVA, tlsPageCount uint64) []byte {
	page := make([]byte, PageSize)

	// TCS structure layout (Intel SDM):
	// Offset 0: STATE (8 bytes) - 0
	// Offset 8: FLAGS (8 bytes) - 0
	// Offset 16: OSSA (8 bytes) - SSA offset from enclave base
	// Offset 24: CSSA (4 bytes) - 0
	// Offset 28: NSSA (4 bytes) - 2
	// Offset 32: OENTRY (8 bytes) - entry point offset
	// Offset 40: AEP (8 bytes) - 0
	// Offset 48: OFSBASGX (8 bytes) - FS base offset
	// Offset 56: OGSBASGX (8 bytes) - GS base offset
	// Offset 64: FSLIMIT (4 bytes) - 0xFFFFFFFF
	// Offset 68: GSLIMIT (4 bytes) - 0xFFFFFFFF

	// OSSA: SSA starts right after TCS page
	ssaOffset := tcsVAddr + PageSize
	binary.LittleEndian.PutUint64(page[16:24], ssaOffset)

	// NSSA: 2 SSA slots
	binary.LittleEndian.PutUint32(page[28:32], 2)

	// OENTRY: entry point
	binary.LittleEndian.PutUint64(page[32:40], entryRVA)

	// FSBASE: points to end of (TLS + control pages) segment
	// fsbase = tcsVAddr + (tlsPageCount + OE_SGX_TCS_CONTROL_PAGES) * PAGE_SIZE
	fsbase := tcsVAddr + (tlsPageCount+OESGXTCSControlPages)*PageSize
	binary.LittleEndian.PutUint64(page[48:56], fsbase)

	// GSBASE: same as FSBASE (for Windows debugger compat)
	binary.LittleEndian.PutUint64(page[56:64], fsbase)

	// FSLIMIT and GSLIMIT
	binary.LittleEndian.PutUint32(page[64:68], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(page[68:72], 0xFFFFFFFF)

	return page
}

func roundUpToPage(n uint64) uint64 {
	return (n + PageSize - 1) & ^uint64(PageSize-1)
}

func roundDownToPage(n uint64) uint64 {
	return n & ^uint64(PageSize-1)
}

func nextPow2(n uint64) uint64 {
	if n == 0 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	return n + 1
}

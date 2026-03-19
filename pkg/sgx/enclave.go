package sgx

import (
	"encoding/binary"
	"sort"

	"github.com/magicaltux/mpcegosign/pkg/elfutil"
)

// ComputeMRENCLAVE computes the MRENCLAVE measurement from ELF segments and
// enclave properties, following the OE page layout order.
func ComputeMRENCLAVE(segments []elfutil.LoadSegment, reloc *elfutil.Relocation, props *EnclaveProperties) ([32]byte, error) {
	m := NewMeasurement()

	// ECREATE
	m.ECREATE(SSAFrameSize, props.EnclaveSize)

	// Sort segments by virtual address
	sorted := make([]elfutil.LoadSegment, len(segments))
	copy(sorted, segments)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].VAddr < sorted[j].VAddr
	})

	// 1. ELF PT_LOAD segments → EADD + EEXTEND
	for _, seg := range sorted {
		flags := elfFlagsToSecinfo(seg.Flags)
		numPages := (seg.MemSize + PageSize - 1) / PageSize

		for p := uint64(0); p < numPages; p++ {
			pageOffset := seg.VAddr + p*PageSize
			dataOffset := p * PageSize

			var pageData []byte
			if dataOffset < seg.FileSize {
				end := dataOffset + PageSize
				if end > seg.FileSize {
					end = seg.FileSize
				}
				pageData = seg.Data[dataOffset:end]
			}

			m.AddPage(pageOffset, flags, pageData, true)
		}
	}

	// 2. Relocation pages → EADD + EEXTEND (R, REG)
	if reloc != nil && reloc.Size > 0 {
		numRelocPages := (reloc.Size + PageSize - 1) / PageSize
		for p := uint64(0); p < numRelocPages; p++ {
			pageOffset := reloc.RVA + p*PageSize
			dataOffset := p * PageSize

			var pageData []byte
			if dataOffset < uint64(len(reloc.Data)) {
				end := dataOffset + PageSize
				if end > uint64(len(reloc.Data)) {
					end = uint64(len(reloc.Data))
				}
				pageData = reloc.Data[dataOffset:end]
			}

			m.AddPage(pageOffset, SecinfoR|SecinfoREG, pageData, true)
		}
	}

	// 3. Heap pages → EADD only, NO EEXTEND (R/W, REG)
	heapStart := props.HeapRVA
	for p := uint64(0); p < props.SizeSettings.NumHeapPages; p++ {
		pageOffset := heapStart + p*PageSize
		m.EADD(pageOffset, SecinfoR|SecinfoW|SecinfoREG)
	}

	// Calculate where thread data starts (after heap)
	threadStart := heapStart + props.SizeSettings.NumHeapPages*PageSize

	// 4. Per-TCS thread data
	numTCS := props.SizeSettings.NumTCS
	numStackPages := props.SizeSettings.NumStackPages

	vaddr := threadStart
	for t := uint64(0); t < numTCS; t++ {
		// Guard page (skip, advance vaddr)
		vaddr += PageSize

		// Stack pages → EADD + EEXTEND (R/W, REG, fill 0xCCCCCCCC)
		for sp := uint64(0); sp < numStackPages; sp++ {
			m.AddPageWithPattern(vaddr, SecinfoR|SecinfoW|SecinfoREG, 0xCCCCCCCC)
			vaddr += PageSize
		}

		// Guard page (skip)
		vaddr += PageSize

		// TCS page → EADD + EEXTEND (TCS flag, structured TCS data)
		tcsData := buildTCSPage(vaddr, numStackPages)
		m.AddPage(vaddr, SecinfoTCS, tcsData, true)
		tcsPageAddr := vaddr
		vaddr += PageSize

		// 2 SSA pages → EADD + EEXTEND (R/W, REG, zeros)
		for ssa := 0; ssa < 2; ssa++ {
			m.AddPage(vaddr, SecinfoR|SecinfoW|SecinfoREG, make([]byte, PageSize), true)
			vaddr += PageSize
		}

		// Guard page (skip)
		vaddr += PageSize

		// TLS pages → EADD + EEXTEND (R/W, REG, zeros)
		// OE uses 1 TLS page
		m.AddPage(vaddr, SecinfoR|SecinfoW|SecinfoREG, make([]byte, PageSize), true)
		vaddr += PageSize

		// Thread data page → EADD + EEXTEND (R/W, REG, thread-specific data)
		tdData := buildThreadDataPage(tcsPageAddr, vaddr, numStackPages)
		m.AddPage(vaddr, SecinfoR|SecinfoW|SecinfoREG, tdData, true)
		vaddr += PageSize
	}

	return m.Sum(), nil
}

// elfFlagsToSecinfo converts ELF segment flags to SGX SECINFO flags.
func elfFlagsToSecinfo(flags elfutil.ProgFlag) uint64 {
	var sf uint64 = SecinfoREG
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

func buildTCSPage(tcsVAddr uint64, numStackPages uint64) []byte {
	page := make([]byte, PageSize)

	// TCS structure layout (Intel SDM):
	// Offset 0: STATE (8 bytes) - 0 = inactive
	// Offset 8: FLAGS (8 bytes) - 0
	// Offset 16: OSSA (8 bytes) - offset to SSA from enclave base
	// Offset 24: CSSA (4 bytes) - current SSA slot index
	// Offset 28: NSSA (4 bytes) - number of SSA slots
	// Offset 32: OENTRY (8 bytes) - entry point offset
	// Offset 40: AEP (8 bytes) - 0
	// Offset 48: OFSBASGX (8 bytes) - offset to FS base
	// Offset 56: OGSBASGX (8 bytes) - offset to GS base
	// Offset 64: FSLIMIT (4 bytes)
	// Offset 68: GSLIMIT (4 bytes)

	// OSSA: SSA starts right after TCS page
	ssaOffset := tcsVAddr + PageSize
	binary.LittleEndian.PutUint64(page[16:24], ssaOffset)

	// NSSA: 2 SSA slots
	binary.LittleEndian.PutUint32(page[28:32], 2)

	// OENTRY: will be set by the enclave loader, typically 0 in measurement
	// OFSBASGX/OGSBASGX: will be set per-thread

	return page
}

// buildThreadDataPage constructs the per-thread data page.
func buildThreadDataPage(tcsVAddr, tdVAddr uint64, numStackPages uint64) []byte {
	page := make([]byte, PageSize)

	// OE thread data structure:
	// Offset 0: self_addr (8 bytes)
	// Offset 8: last_sp (8 bytes) - top of stack
	// Offset 16: stack_base_addr (8 bytes)
	// Offset 24: stack_limit (8 bytes)
	// Offset 32: tls_addr (8 bytes)
	// Offset 40: tls_array (8 bytes)

	binary.LittleEndian.PutUint64(page[0:8], tdVAddr)

	// Stack top is at (tcs - guard - stack) region
	stackTop := tcsVAddr - PageSize // guard page before TCS
	stackBase := stackTop - numStackPages*PageSize
	binary.LittleEndian.PutUint64(page[8:16], stackTop)
	binary.LittleEndian.PutUint64(page[16:24], stackBase)
	binary.LittleEndian.PutUint64(page[24:32], stackBase)

	// TLS: one page before thread data
	tlsAddr := tdVAddr - PageSize
	binary.LittleEndian.PutUint64(page[32:40], tlsAddr)

	return page
}


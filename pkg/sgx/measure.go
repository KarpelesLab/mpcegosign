package sgx

import (
	"crypto/sha256"
	"encoding/binary"
	"hash"
)

// Measurement accumulates the running SHA-256 hash for MRENCLAVE.
type Measurement struct {
	h hash.Hash
}

// NewMeasurement creates a new MRENCLAVE measurement context.
func NewMeasurement() *Measurement {
	return &Measurement{h: sha256.New()}
}

// ECREATE adds the initial ECREATE measurement block.
// 64 bytes: "ECREATE\0" + ssaframesize(4) + enclavesize(8) + zeros(44)
func (m *Measurement) ECREATE(ssaFrameSize uint32, enclaveSize uint64) {
	var block [64]byte
	copy(block[0:8], "ECREATE\x00")
	binary.LittleEndian.PutUint32(block[8:12], ssaFrameSize)
	binary.LittleEndian.PutUint64(block[12:20], enclaveSize)
	// bytes 20-63 are zero
	m.h.Write(block[:])
}

// EADD adds an EADD measurement block for a page.
// 64 bytes: "EADD\0\0\0\0" + offset(8) + secinfo_flags(8) + zeros(40)
func (m *Measurement) EADD(offset uint64, secinfoFlags uint64) {
	var block [64]byte
	copy(block[0:8], "EADD\x00\x00\x00\x00")
	binary.LittleEndian.PutUint64(block[8:16], offset)
	binary.LittleEndian.PutUint64(block[16:24], secinfoFlags)
	// bytes 24-63 are zero
	m.h.Write(block[:])
}

// EEXTEND extends the measurement with 256 bytes of page data.
// For each 256-byte chunk:
//   64-byte header: "EEXTEND\0" + offset(8) + zeros(48)
//   Then the 256 bytes of data themselves
func (m *Measurement) EEXTEND(pageOffset uint64, chunkOffset int, data []byte) {
	offset := pageOffset + uint64(chunkOffset)

	var block [64]byte
	copy(block[0:8], "EEXTEND\x00")
	binary.LittleEndian.PutUint64(block[8:16], offset)
	// bytes 16-63 are zero
	m.h.Write(block[:])

	// Write the 256 bytes of data
	m.h.Write(data[:256])
}

// AddPage adds a page with EADD and optionally EEXTEND (for each 256-byte chunk).
func (m *Measurement) AddPage(offset uint64, secinfoFlags uint64, data []byte, extend bool) {
	m.EADD(offset, secinfoFlags)
	if extend && data != nil {
		pageData := make([]byte, PageSize)
		copy(pageData, data)
		for i := 0; i < PageSize; i += 256 {
			m.EEXTEND(offset, i, pageData[i:i+256])
		}
	}
}

// AddPageWithFill adds a page with EADD + EEXTEND using a fill pattern.
func (m *Measurement) AddPageWithFill(offset uint64, secinfoFlags uint64, fillByte byte) {
	m.EADD(offset, secinfoFlags)
	pageData := make([]byte, PageSize)
	for i := range pageData {
		pageData[i] = fillByte
	}
	for i := 0; i < PageSize; i += 256 {
		m.EEXTEND(offset, i, pageData[i:i+256])
	}
}

// AddPageWithPattern adds a page with EADD + EEXTEND using a uint32 fill pattern.
func (m *Measurement) AddPageWithPattern(offset uint64, secinfoFlags uint64, pattern uint32) {
	m.EADD(offset, secinfoFlags)
	pageData := make([]byte, PageSize)
	for i := 0; i < PageSize; i += 4 {
		binary.LittleEndian.PutUint32(pageData[i:], pattern)
	}
	for i := 0; i < PageSize; i += 256 {
		m.EEXTEND(offset, i, pageData[i:i+256])
	}
}

// Sum returns the final MRENCLAVE hash.
func (m *Measurement) Sum() [32]byte {
	var result [32]byte
	m.h.Sum(result[:0])
	return result
}

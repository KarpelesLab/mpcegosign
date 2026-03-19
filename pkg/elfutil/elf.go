package elfutil

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	OEInfoSectionName = ".oeinfo"
	OEInfoSize        = 2064 // minimum size including payload fields
	SigStructOffset   = 144
	SigStructSize     = 1808
	EndMarkerOffset   = 1952
	PayloadOffsetPos  = 2048
	PayloadSizePos    = 2056
)

// OEInfo holds the raw .oeinfo section data and its file offset.
type OEInfo struct {
	Data       []byte
	FileOffset uint64
}

// SegmentInfo holds information about a PT_LOAD segment.
type SegmentInfo struct {
	VAddr    uint64
	MemSize  uint64
	FileSize uint64
	Flags    uint32 // ELF p_flags
	Data     []byte // file-backed data
}

// ELFInfo holds all information extracted from the ELF needed for measurement.
type ELFInfo struct {
	Segments        []SegmentInfo
	ImageSize       uint64 // total image span (high - low), page-aligned
	RelocData       []byte // relocation section data
	RelocSize       uint64 // relocation data size
	TLSPageCount    uint64 // number of pages for TLS (from PT_TLS)
	EntryRVA        uint64 // entry point address
	PayloadData     []byte // EGo payload data (from .oeinfo offset)
	PayloadDataSize uint64 // EGo payload data size
}

// ReadOEInfo reads the .oeinfo section from an ELF binary.
func ReadOEInfo(path string) (*OEInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ELF: %w", err)
	}
	defer f.Close()

	sec := f.Section(OEInfoSectionName)
	if sec == nil {
		return nil, fmt.Errorf("section %s not found", OEInfoSectionName)
	}

	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", OEInfoSectionName, err)
	}

	return &OEInfo{
		Data:       data,
		FileOffset: sec.Offset,
	}, nil
}

// SigStructBytes returns the SIGSTRUCT portion of .oeinfo.
func (o *OEInfo) SigStructBytes() []byte {
	if len(o.Data) < SigStructOffset+SigStructSize {
		return nil
	}
	return o.Data[SigStructOffset : SigStructOffset+SigStructSize]
}

// SetSigStruct replaces the SIGSTRUCT in .oeinfo data.
func (o *OEInfo) SetSigStruct(sigstruct []byte) {
	copy(o.Data[SigStructOffset:SigStructOffset+SigStructSize], sigstruct[:SigStructSize])
}

// PayloadOffset returns the EGo payload offset (at .oeinfo+2048).
func (o *OEInfo) PayloadOffset() uint64 {
	if len(o.Data) < PayloadOffsetPos+8 {
		return 0
	}
	return binary.LittleEndian.Uint64(o.Data[PayloadOffsetPos:])
}

// PayloadSize returns the EGo payload size (at .oeinfo+2056).
func (o *OEInfo) PayloadSize() uint64 {
	if len(o.Data) < PayloadSizePos+8 {
		return 0
	}
	return binary.LittleEndian.Uint64(o.Data[PayloadSizePos:])
}

// WriteSigStructToFile writes the SIGSTRUCT back to the binary at the correct offset.
func WriteSigStructToFile(path string, oeinfo *OEInfo, sigstruct []byte) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	offset := int64(oeinfo.FileOffset) + SigStructOffset
	_, err = f.WriteAt(sigstruct[:SigStructSize], offset)
	return err
}

// ReadELFInfoForMeasurement reads ELF info and zeros the SIGSTRUCT in the
// in-memory image data (as oesign does before measuring).
func ReadELFInfoForMeasurement(path string) (*ELFInfo, error) {
	info, err := ReadELFInfo(path)
	if err != nil {
		return nil, err
	}

	// Zero the SIGSTRUCT within segment data covering .oeinfo
	// OE zeroes the sigstruct in-place before measuring
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sec := f.Section(OEInfoSectionName)
	if sec != nil {
		oeInfoVAddr := sec.Addr
		sigstructVAddr := oeInfoVAddr + SigStructOffset
		sigstructEnd := sigstructVAddr + SigStructSize

		for i := range info.Segments {
			seg := &info.Segments[i]
			segStart := seg.VAddr
			segFileEnd := seg.VAddr + seg.FileSize

			// Check overlap with sigstruct region
			overlapStart := sigstructVAddr
			if overlapStart < segStart {
				overlapStart = segStart
			}
			overlapEnd := sigstructEnd
			if overlapEnd > segFileEnd {
				overlapEnd = segFileEnd
			}

			if overlapStart < overlapEnd {
				zeroStart := overlapStart - seg.VAddr
				zeroEnd := overlapEnd - seg.VAddr
				for j := zeroStart; j < zeroEnd; j++ {
					seg.Data[j] = 0
				}
			}
		}
	}

	return info, nil
}

// ReadELFInfo reads all information needed for measurement from an ELF binary.
func ReadELFInfo(path string) (*ELFInfo, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ELF: %w", err)
	}
	defer f.Close()

	info := &ELFInfo{
		EntryRVA: f.Entry,
	}

	// Read PT_LOAD segments and compute image size
	var low, high uint64
	first := true
	for _, prog := range f.Progs {
		switch prog.Type {
		case elf.PT_LOAD:
			data := make([]byte, prog.Filesz)
			if prog.Filesz > 0 {
				if _, err := prog.ReadAt(data, 0); err != nil && err != io.EOF {
					return nil, fmt.Errorf("reading segment at vaddr %#x: %w", prog.Vaddr, err)
				}
			}
			info.Segments = append(info.Segments, SegmentInfo{
				VAddr:    prog.Vaddr,
				MemSize:  prog.Memsz,
				FileSize: prog.Filesz,
				Flags:    uint32(prog.Flags),
				Data:     data,
			})

			segEnd := prog.Vaddr + prog.Memsz
			if first || prog.Vaddr < low {
				low = prog.Vaddr
			}
			if first || segEnd > high {
				high = segEnd
			}
			first = false

		case elf.PT_TLS:
			// Compute TLS page count
			tlsSize := prog.Memsz
			if tlsSize > 0 {
				info.TLSPageCount = roundUpToPage64(tlsSize) / 4096
			}
		}
	}

	if !first {
		info.ImageSize = roundUpToPage64(high - low)
	}

	// Read relocation data
	info.RelocData, info.RelocSize, err = readRelocData(f)
	if err != nil {
		return nil, err
	}

	// Read EGo payload data from .oeinfo
	sec := f.Section(OEInfoSectionName)
	if sec != nil {
		oeData, err := sec.Data()
		if err == nil && len(oeData) >= PayloadSizePos+8 {
			payloadOffset := binary.LittleEndian.Uint64(oeData[PayloadOffsetPos:])
			payloadSize := binary.LittleEndian.Uint64(oeData[PayloadSizePos:])
			if payloadOffset > 0 && payloadSize > 0 {
				info.PayloadDataSize = payloadSize
				info.PayloadData, err = readPayloadData(path, payloadOffset, payloadSize)
				if err != nil {
					return nil, fmt.Errorf("reading payload data: %w", err)
				}
			}
		}
	}

	return info, nil
}

func readPayloadData(path string, offset, size uint64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data := make([]byte, size)
	_, err = f.ReadAt(data, int64(offset))
	if err != nil && err != io.EOF {
		return nil, err
	}
	return data, nil
}

func readRelocData(f *elf.File) ([]byte, uint64, error) {
	// Look for .dynamic section to find DT_REL/DT_RELA
	dynSec := f.Section(".dynamic")
	if dynSec == nil {
		return nil, 0, nil
	}

	dynData, err := dynSec.Data()
	if err != nil {
		return nil, 0, fmt.Errorf("reading .dynamic: %w", err)
	}

	var relaAddr, relaSize uint64

	for i := 0; i+16 <= len(dynData); i += 16 {
		tag := int64(binary.LittleEndian.Uint64(dynData[i:]))
		val := binary.LittleEndian.Uint64(dynData[i+8:])
		switch elf.DynTag(tag) {
		case elf.DT_RELA:
			relaAddr = val
		case elf.DT_RELASZ:
			relaSize = val
		}
	}

	if relaAddr == 0 || relaSize == 0 {
		return nil, 0, nil
	}

	// Read the relocation data
	data, err := readDataAtVAddr(f, relaAddr, relaSize)
	if err != nil {
		return nil, 0, fmt.Errorf("reading relocation data: %w", err)
	}

	return data, relaSize, nil
}

func readDataAtVAddr(f *elf.File, vaddr, size uint64) ([]byte, error) {
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if vaddr >= prog.Vaddr && vaddr+size <= prog.Vaddr+prog.Filesz {
			offset := vaddr - prog.Vaddr
			data := make([]byte, size)
			_, err := prog.ReadAt(data, int64(offset))
			if err != nil && err != io.EOF {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("virtual address %#x not found in any PT_LOAD segment", vaddr)
}

// MergeELFInfoForEGo creates a combined ELFInfo for EGo's dual-image layout.
// mainImage is the ego-enclave runtime, payloadImage is the user's Go binary.
// The layout follows OE's _add_pages: main segments, then payload segments
// (offset by main image size), then merged relocations.
func MergeELFInfoForEGo(mainImage, payloadImage *ELFInfo) *ELFInfo {
	merged := &ELFInfo{
		EntryRVA: mainImage.EntryRVA,
	}

	// Main image segments go first (at their own vaddrs)
	merged.Segments = append(merged.Segments, mainImage.Segments...)

	// Payload segments are offset by main image size
	for _, seg := range payloadImage.Segments {
		shifted := SegmentInfo{
			VAddr:    seg.VAddr + mainImage.ImageSize,
			MemSize:  seg.MemSize,
			FileSize: seg.FileSize,
			Flags:    seg.Flags,
			Data:     seg.Data,
		}
		merged.Segments = append(merged.Segments, shifted)
	}

	// Total image size = main + payload
	merged.ImageSize = mainImage.ImageSize + payloadImage.ImageSize

	// TLS: OE computes TLS from the main image only (the submodule's TLS
	// is typically zero for EGo payloads)
	merged.TLSPageCount = mainImage.TLSPageCount
	if payloadImage.TLSPageCount > merged.TLSPageCount {
		merged.TLSPageCount = payloadImage.TLSPageCount
	}

	// Relocations: OE merges relocation data from both images.
	// The main image's _link_elf_image resolves cross-module relocations and
	// stores the combined reloc data. For measurement purposes, we concatenate
	// and page-align.
	totalRelocSize := roundUpToPage64(mainImage.RelocSize + payloadImage.RelocSize)
	mergedReloc := make([]byte, totalRelocSize)
	copy(mergedReloc, mainImage.RelocData)
	copy(mergedReloc[mainImage.RelocSize:], payloadImage.RelocData)
	merged.RelocData = mergedReloc
	merged.RelocSize = mainImage.RelocSize + payloadImage.RelocSize

	// Payload data comes from the payload image's .oeinfo
	merged.PayloadData = payloadImage.PayloadData
	merged.PayloadDataSize = payloadImage.PayloadDataSize

	return merged
}

func roundUpToPage64(n uint64) uint64 {
	return (n + 4095) & ^uint64(4095)
}

// CopyFile creates a copy of a file.
func CopyFile(src, dst string) error {
	in, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, in, 0755)
}

// ProgFlag is an alias for elf.ProgFlag so other packages don't need to import debug/elf.
type ProgFlag = elf.ProgFlag

const (
	PF_X uint32 = 0x1
	PF_W uint32 = 0x2
	PF_R uint32 = 0x4
)

package elfutil

import (
	"bytes"
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

// LoadSegment represents a PT_LOAD segment from the ELF.
type LoadSegment struct {
	VAddr    uint64
	MemSize  uint64
	FileSize uint64
	Flags    elf.ProgFlag
	Data     []byte
}

// ReadLoadSegments reads all PT_LOAD segments from an ELF binary.
func ReadLoadSegments(path string) ([]LoadSegment, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ELF: %w", err)
	}
	defer f.Close()

	var segments []LoadSegment
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		data := make([]byte, prog.Filesz)
		if _, err := prog.ReadAt(data, 0); err != nil && err != io.EOF {
			return nil, fmt.Errorf("reading segment at vaddr %#x: %w", prog.Vaddr, err)
		}
		segments = append(segments, LoadSegment{
			VAddr:    prog.Vaddr,
			MemSize:  prog.Memsz,
			FileSize: prog.Filesz,
			Flags:    prog.Flags,
			Data:     data,
		})
	}
	return segments, nil
}

// Relocation represents .dynamic relocation info.
type Relocation struct {
	RVA  uint64
	Size uint64
	Data []byte
}

// ReadRelocations reads relocation data from the ELF binary.
// It looks at the .dynamic section for DT_REL/DT_RELA entries.
func ReadRelocations(path string) (*Relocation, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ELF: %w", err)
	}
	defer f.Close()

	dynSec := f.Section(".dynamic")
	if dynSec == nil {
		return nil, nil // no dynamic section
	}

	dynData, err := dynSec.Data()
	if err != nil {
		return nil, fmt.Errorf("reading .dynamic: %w", err)
	}

	var relAddr, relSize uint64
	var relaAddr, relaSize uint64

	// Parse dynamic entries (each is 16 bytes on 64-bit: tag + val)
	r := bytes.NewReader(dynData)
	for {
		var tag, val int64
		if err := binary.Read(r, binary.LittleEndian, &tag); err != nil {
			break
		}
		if err := binary.Read(r, binary.LittleEndian, &val); err != nil {
			break
		}
		switch elf.DynTag(tag) {
		case elf.DT_REL:
			relAddr = uint64(val)
		case elf.DT_RELSZ:
			relSize = uint64(val)
		case elf.DT_RELA:
			relaAddr = uint64(val)
		case elf.DT_RELASZ:
			relaSize = uint64(val)
		}
	}

	// Prefer RELA over REL
	addr, size := relaAddr, relaSize
	if addr == 0 {
		addr, size = relAddr, relSize
	}
	if addr == 0 || size == 0 {
		return nil, nil
	}

	// Read the relocation data from the file using the virtual address
	// We need to find which segment contains this address
	data, err := readDataAtVAddr(f, addr, size)
	if err != nil {
		return nil, fmt.Errorf("reading relocation data: %w", err)
	}

	return &Relocation{
		RVA:  addr,
		Size: size,
		Data: data,
	}, nil
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
	PF_X ProgFlag = elf.PF_X
	PF_W ProgFlag = elf.PF_W
	PF_R ProgFlag = elf.PF_R
)

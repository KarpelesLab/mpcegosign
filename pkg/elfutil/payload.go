package elfutil

import (
	"encoding/binary"
	"os"
)

// ReadPayloadInfo reads the EGo payload offset and size from .oeinfo.
func ReadPayloadInfo(oeinfo *OEInfo) (offset, size uint64) {
	return oeinfo.PayloadOffset(), oeinfo.PayloadSize()
}

// WritePayloadInfo writes payload offset and size into the binary's .oeinfo section.
func WritePayloadInfo(path string, oeinfo *OEInfo, payloadOffset, payloadSize uint64) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[0:8], payloadOffset)
	binary.LittleEndian.PutUint64(buf[8:16], payloadSize)

	fileOff := int64(oeinfo.FileOffset) + PayloadOffsetPos
	_, err = f.WriteAt(buf[:], fileOff)
	return err
}

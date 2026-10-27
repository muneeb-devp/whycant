package binfmt

import (
	"debug/elf"
	"encoding/binary"
)

// MinimalELF builds the smallest little-endian ELF file ParseELF accepts: a
// header, one program header (PT_INTERP when interp is set, else PT_LOAD)
// and the loader path. Tests use it instead of committing binaries.
func MinimalELF(class int, machine elf.Machine, interp string) []byte {
	return MinimalELFOrder(class, machine, interp, binary.LittleEndian)
}

// MinimalELFOrder is MinimalELF with a chosen byte order.
func MinimalELFOrder(class int, machine elf.Machine, interp string, bo binary.ByteOrder) []byte {
	ehsize, phentsize := 52, 32
	if class == 64 {
		ehsize, phentsize = 64, 56
	}
	interpOff := ehsize + phentsize
	b := make([]byte, interpOff+len(interp)+1)
	copy(b, elf.ELFMAG)
	b[elf.EI_CLASS] = byte(elf.ELFCLASS32)
	if class == 64 {
		b[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	}
	b[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	if bo == binary.BigEndian {
		b[elf.EI_DATA] = byte(elf.ELFDATA2MSB)
	}
	b[elf.EI_VERSION] = byte(elf.EV_CURRENT)
	bo.PutUint16(b[16:], uint16(elf.ET_EXEC))
	bo.PutUint16(b[18:], uint16(machine))

	ptype := elf.PT_LOAD
	if interp != "" {
		ptype = elf.PT_INTERP
		copy(b[interpOff:], interp)
	}
	ph := b[ehsize:]
	if class == 64 {
		bo.PutUint64(b[32:], uint64(ehsize))
		bo.PutUint16(b[54:], uint16(phentsize))
		bo.PutUint16(b[56:], 1)
		bo.PutUint32(ph, uint32(ptype))
		bo.PutUint64(ph[8:], uint64(interpOff))
		bo.PutUint64(ph[32:], uint64(len(interp)+1))
	} else {
		bo.PutUint32(b[28:], uint32(ehsize))
		bo.PutUint16(b[42:], uint16(phentsize))
		bo.PutUint16(b[44:], 1)
		bo.PutUint32(ph, uint32(ptype))
		bo.PutUint32(ph[4:], uint32(interpOff))
		bo.PutUint32(ph[16:], uint32(len(interp)+1)) //nolint:gosec // fixture strings are tiny
	}
	return b
}

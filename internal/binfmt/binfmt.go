// Package binfmt identifies what the kernel would do with a file passed to
// execve: run a script through its #! interpreter, or load an ELF binary
// (possibly through a dynamic loader).
package binfmt

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

// HeadSize is how much of a file is enough to identify it in almost all
// cases; ParseELF reports when more is needed.
const HeadSize = 4096

// Shebang is a parsed "#!" line.
type Shebang struct {
	Interpreter string
	Arg         string // the single optional argument, may be empty
	// CRLF is true when the line ends in a carriage return, which then
	// becomes part of the interpreter name or argument ("bad interpreter").
	CRLF bool
}

// ParseShebang parses a #! line the way the kernel's binfmt_script does:
// leading blanks are skipped, the interpreter ends at the first space or
// tab, the rest (with outer blanks trimmed) is one argument, and trailing
// spaces and tabs are dropped. A carriage return is not a blank.
func ParseShebang(head []byte) (Shebang, bool) {
	if !bytes.HasPrefix(head, []byte("#!")) {
		return Shebang{}, false
	}
	line := head[2:]
	if i := bytes.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = bytes.TrimRight(line, " \t")
	line = bytes.TrimLeft(line, " \t")
	sb := Shebang{CRLF: bytes.HasSuffix(line, []byte("\r"))}
	interp, arg, _ := bytes.Cut(line, []byte(" "))
	if i := bytes.IndexByte(interp, '\t'); i >= 0 {
		arg = append(append([]byte{}, interp[i+1:]...), arg...)
		interp = interp[:i]
	}
	sb.Interpreter = string(interp)
	sb.Arg = string(bytes.Trim(arg, " \t"))
	return sb, true
}

// ELF is what matters about an ELF binary for execution.
type ELF struct {
	Class   int // 32 or 64
	Machine elf.Machine
	// Interp is the PT_INTERP dynamic loader; empty for static binaries.
	Interp string
}

// ErrNotELF means the file does not start with the ELF magic.
var ErrNotELF = errors.New("not an ELF file")

// NeedMoreError means the head was too short; read Size bytes and retry.
type NeedMoreError struct{ Size int }

func (e *NeedMoreError) Error() string { return fmt.Sprintf("need %d bytes of the file", e.Size) }

// IsELF reports whether head starts with the ELF magic.
func IsELF(head []byte) bool { return bytes.HasPrefix(head, []byte(elf.ELFMAG)) }

// ParseELF reads the ELF header and program headers from the start of a
// file, without needing the section headers at its end.
func ParseELF(head []byte) (*ELF, error) {
	if !IsELF(head) {
		return nil, ErrNotELF
	}
	if len(head) < 52 {
		return nil, &NeedMoreError{Size: 64}
	}
	var bo binary.ByteOrder
	switch elf.Data(head[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		bo = binary.LittleEndian
	case elf.ELFDATA2MSB:
		bo = binary.BigEndian
	default:
		return nil, errors.New("elf: unknown byte order")
	}

	e := &ELF{Machine: elf.Machine(bo.Uint16(head[18:]))}
	var phoff uint64
	var phentsize, phnum int
	switch elf.Class(head[elf.EI_CLASS]) {
	case elf.ELFCLASS64:
		if len(head) < 64 {
			return nil, &NeedMoreError{Size: 64}
		}
		e.Class = 64
		phoff = bo.Uint64(head[32:])
		phentsize = int(bo.Uint16(head[54:]))
		phnum = int(bo.Uint16(head[56:]))
	case elf.ELFCLASS32:
		e.Class = 32
		phoff = uint64(bo.Uint32(head[28:]))
		phentsize = int(bo.Uint16(head[42:]))
		phnum = int(bo.Uint16(head[44:]))
	default:
		return nil, errors.New("elf: unknown class")
	}
	minEnt := 32
	if e.Class == 64 {
		minEnt = 56
	}
	if phnum == 0 {
		return e, nil
	}
	if phentsize < minEnt || phoff > 1<<20 {
		return nil, errors.New("elf: bad program headers")
	}

	for i := range phnum {
		off := int(phoff) + i*phentsize
		if off+phentsize > len(head) {
			return nil, &NeedMoreError{Size: int(phoff) + phnum*phentsize}
		}
		ph := head[off:]
		if elf.ProgType(bo.Uint32(ph)) != elf.PT_INTERP {
			continue
		}
		var start, size uint64
		if e.Class == 64 {
			start, size = bo.Uint64(ph[8:]), bo.Uint64(ph[32:])
		} else {
			start, size = uint64(bo.Uint32(ph[4:])), uint64(bo.Uint32(ph[16:]))
		}
		if size == 0 || size > 4096 || start > 1<<20 {
			return nil, errors.New("elf: bad PT_INTERP")
		}
		if int(start+size) > len(head) {
			return nil, &NeedMoreError{Size: int(start + size)}
		}
		e.Interp = string(bytes.TrimRight(head[start:start+size], "\x00"))
		break
	}
	return e, nil
}

// MachineName is a friendly architecture name, as uname -m prints it.
func MachineName(m elf.Machine, class int) string {
	switch m {
	case elf.EM_X86_64:
		return "x86_64"
	case elf.EM_386:
		return "i386"
	case elf.EM_AARCH64:
		return "aarch64"
	case elf.EM_ARM:
		return "arm"
	case elf.EM_RISCV:
		if class == 32 {
			return "riscv32"
		}
		return "riscv64"
	case elf.EM_PPC64:
		return "ppc64"
	case elf.EM_PPC:
		return "ppc"
	case elf.EM_S390:
		return "s390x"
	case elf.EM_MIPS:
		return "mips"
	case elf.EM_LOONGARCH:
		return "loongarch64"
	}
	return m.String()
}

// HostMachine maps a GOARCH to the ELF machine that runs natively, and the
// one that 64-bit kernels usually also run in compat mode (or 0).
func HostMachine(goarch string) (native, compat elf.Machine) {
	switch goarch {
	case "amd64":
		return elf.EM_X86_64, elf.EM_386
	case "386":
		return elf.EM_386, 0
	case "arm64":
		return elf.EM_AARCH64, elf.EM_ARM
	case "arm":
		return elf.EM_ARM, 0
	case "riscv64":
		return elf.EM_RISCV, 0
	case "ppc64", "ppc64le":
		return elf.EM_PPC64, 0
	case "s390x":
		return elf.EM_S390, 0
	case "loong64":
		return elf.EM_LOONGARCH, 0
	case "mips", "mipsle", "mips64", "mips64le":
		return elf.EM_MIPS, 0
	}
	return 0, 0
}

// QemuName is the binfmt_misc entry name qemu-user registers for a machine,
// e.g. "qemu-aarch64".
func QemuName(m elf.Machine, class int) string {
	name := MachineName(m, class)
	switch name {
	case "x86_64", "aarch64", "arm", "riscv64", "riscv32", "ppc64", "s390x", "mips", "loongarch64", "i386":
		return "qemu-" + name
	}
	return ""
}
